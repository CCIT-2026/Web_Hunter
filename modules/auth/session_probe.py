"""
modules/auth/session_probe.py

Identifica endpoint di registrazione e login, si autentica usando le
credenziali stock da settings["test_user"], e salva cookie/token in
auth_state.json per i runner successivi (sqlmap, ghauri, ecc.).

State machine (persistente in reports/<service>/auth_state.json):

  unregistered → registered → logged_in
                     ↑              |
                     └── re-register se login fallisce (service reset)

Flusso execute():
  1. Trova login_ep e register_ep tra gli endpoint mappati
  2. Tenta login → successo → salva stato, fine
  3. Login fallisce → tenta register → tenta login → successo → salva stato
  4. Tutto fallisce → salva stato fallito, i runner successivi girano senza auth
"""

import json as _json
import urllib.request
import urllib.error
from pathlib import Path

from modules.base_runner import BaseRunner, make_run_fn
from orchestrator.colors import step as _step_raw, ok as _ok_raw, warn as _warn_raw

def _step(msg: str): _step_raw(f"[session_probe] {msg}")
def _ok(msg: str):   _ok_raw(f"[session_probe] {msg}")
def _warn(msg: str): _warn_raw(f"[session_probe] {msg}")

# ---------------------------------------------------------------------------
# Credential field families
# ---------------------------------------------------------------------------

_FAMILIES: dict[str, list[str]] = {
    "username":   ["username", "user", "login", "nickname", "handle", "uname", "account"],
    "password":   ["password", "passwd", "pass", "pwd", "passphrase"],
    "email":      ["email", "mail", "e_mail", "e-mail"],
    "phone":      ["phone", "tel", "mobile", "cellphone", "phone_number", "phonenumber"],
    "first_name": ["first_name", "firstname", "fname", "given_name", "forename"],
    "last_name":  ["last_name", "lastname", "lname", "surname", "family_name"],
    "name":       ["name", "full_name", "fullname", "display_name"],
}

_LOGIN_KEYWORDS    = {"login", "signin", "sign_in", "auth", "token", "session", "authenticate"}
_REGISTER_KEYWORDS = {"register", "signup", "sign_up", "registration", "create", "enroll", "join"}

_INJECTION_MODULES = {"sqlmap", "ghauri", "nosqli", "sstimap", "commix"}


def _match_field(name: str, test_user: dict) -> str | None:
    low = name.lower().replace("-", "_")
    for family_key, aliases in _FAMILIES.items():
        if low in aliases or any(low == a or low.endswith("_" + a) or low.startswith(a + "_") for a in aliases):
            return test_user.get(family_key)
    return None


def _path_tokens(path: str) -> set[str]:
    return set(path.lower().replace("-", "_").replace("/", " ").split())


class SessionProbeRunner(BaseRunner):
    MODULE_NAME = "session_probe"

    def execute(self):
        test_user = self.settings.get("test_user")
        if not test_user:
            _warn("test_user non configurato in settings.json — salto")
            return "skipped", "skip: test_user non configurato in settings.json"

        target_base = (self.settings.get("target_url") or "http://localhost").rstrip("/")

        login_ep    = self._find_endpoint(_LOGIN_KEYWORDS)
        register_ep = self._find_endpoint(_REGISTER_KEYWORDS)

        if not login_ep:
            _warn("nessun endpoint di login trovato — salto")
            return "skipped", "skip: nessun endpoint di login trovato"

        _step(f"login → {login_ep['path']}")

        state = self._load_state()
        already_registered = state.get("registered", False)

        # Tenta login diretto
        ok, cookie, auth_header = self._do_login(target_base, login_ep, test_user)
        if ok:
            if already_registered:
                _ok("già registrato — login OK")
            else:
                _ok("login OK (credenziali accettate senza registrazione)")
            self._save_state(state, cookie, auth_header, registered=already_registered, logged_in=True)
            return "completed", None

        # Login fallito → registra (o ri-registra dopo reset servizio)
        if register_ep:
            if already_registered:
                _warn("login fallito (service reset?) — ri-registro...")
            else:
                _step(f"login fallito — registro nuovo utente → {register_ep['path']}")
            self._do_register(target_base, register_ep, test_user)
            ok, cookie, auth_header = self._do_login(target_base, login_ep, test_user)
            if ok:
                _ok("registrato e loggato con successo")
                self._save_state(state, cookie, auth_header, registered=True, logged_in=True)
                return "completed", None

        # Tutto fallito
        _warn("autenticazione fallita — i runner procedono senza sessione")
        self._save_state(state, None, None, registered=already_registered, logged_in=False)
        return "completed", "warn: autenticazione fallita — i runner procedono senza sessione"

    # ------------------------------------------------------------------
    # Endpoint detection
    # ------------------------------------------------------------------

    def _find_endpoint(self, keywords: set) -> dict | None:
        for ep in self.endpoints:
            if _path_tokens(ep["path"]) & keywords:
                return ep
        return None

    # ------------------------------------------------------------------
    # Payload builder
    # ------------------------------------------------------------------

    def _build_payload(self, ep: dict, test_user: dict) -> dict:
        payload = {}
        for p in ep.get("params", []):
            if p.get("location") != "body":
                continue
            val = _match_field(p["name"], test_user)
            if val is not None:
                payload[p["name"]] = val
        return payload

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _post_json(self, url: str, payload: dict) -> tuple[int, dict, str]:
        data = _json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, dict(resp.headers), resp.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read().decode(errors="replace")
        except Exception as e:
            return -1, {}, str(e)

    def _extract_auth(self, headers: dict, body: str) -> tuple[str | None, str | None]:
        cookie = None
        auth_header = None

        raw_cookie = headers.get("Set-Cookie") or headers.get("set-cookie", "")
        if raw_cookie:
            cookie = raw_cookie.split(";")[0].strip()

        try:
            data = _json.loads(body)
            if isinstance(data, dict):
                for key in ("token", "access_token", "jwt", "auth_token", "id_token", "accessToken"):
                    if key in data:
                        auth_header = f"Authorization: Bearer {data[key]}"
                        break
        except Exception:
            pass

        return cookie or None, auth_header or None

    def _is_success(self, status: int, body: str) -> bool:
        if status in (200, 201):
            return True
        # Alcuni server ritornano 4xx ma con token nel body
        try:
            data = _json.loads(body)
            if isinstance(data, dict):
                for key in ("token", "access_token", "jwt", "auth_token"):
                    if key in data:
                        return True
        except Exception:
            pass
        return False

    def _do_login(self, base: str, ep: dict, test_user: dict) -> tuple[bool, str | None, str | None]:
        payload = self._build_payload(ep, test_user)
        if not payload:
            return False, None, None
        status, headers, body = self._post_json(f"{base}{ep['path']}", payload)
        if self._is_success(status, body):
            cookie, auth_header = self._extract_auth(headers, body)
            return True, cookie, auth_header
        return False, None, None

    def _do_register(self, base: str, ep: dict, test_user: dict) -> bool:
        payload = self._build_payload(ep, test_user)
        if not payload:
            return False
        status, _, _ = self._post_json(f"{base}{ep['path']}", payload)
        return status in (200, 201)

    # ------------------------------------------------------------------
    # State persistence
    # ------------------------------------------------------------------

    def _load_state(self) -> dict:
        existing = self._load_json("auth_state.json")
        if existing:
            return existing
        return {"registered": False, "logged_in": False, "cookie": None, "auth_header": None}

    def _save_state(self, state: dict, cookie: str | None, auth_header: str | None,
                    registered: bool, logged_in: bool):
        state.update({
            "registered":  registered,
            "logged_in":   logged_in,
            "cookie":      cookie,
            "auth_header": auth_header,
        })
        out = self.report_dir / "json_reports" / "auth_state.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(_json.dumps(state, indent=2))


run = make_run_fn(SessionProbeRunner)
