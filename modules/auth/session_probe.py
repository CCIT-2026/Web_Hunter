"""
modules/auth/session_probe.py

Identifica endpoint di registrazione e login, si autentica usando le
credenziali stock da settings["test_user"], e salva cookie/token in
auth_state.json per i runner successivi (sqlmap, ghauri, ecc.).

HTTP layer:
  - Il corpo della richiesta rispetta l'encoding reale dell'endpoint
    (form-urlencoded o json), letto da endpoints_map.json — stesso
    pattern già usato da sqlmap_runner.py e ghauri_runner.py.
  - Le redirect (3xx) NON vengono seguite automaticamente da urllib:
    verrebbe perso il Set-Cookie della risposta originale (verificato:
    urllib converte un POST->302 in un GET automatico e la risposta
    finale non porta più l'header Set-Cookie del hop intermedio).
    Le seguiamo a mano, hop per hop, riattaccando ad ogni hop i cookie
    già raccolti, fino a un cap di hop.

Success detection (per app a redirect, es. Flask con flash()+redirect):
  - Non ci basiamo sulla sola presenza di un Set-Cookie: molte app
    (Flask in testa) impostano un cookie di sessione anche sul path di
    fallimento, perché flash() scrive comunque nella sessione. L'unico
    segnale non ambiguo è la destinazione finale della catena di
    redirect: se atterriamo di nuovo su login o su register, è un
    fallimento certo, non un'euristica.

State machine (persistente in reports/<service>/auth_state.json):

  unregistered → registered → logged_in
                     ↑              |
                     └── re-register se login fallisce (service reset)

Flusso execute():
  1. Trova login_ep e register_ep tra gli endpoint mappati
  2. Tenta login → successo → salva stato, fine
  3. Login fallisce → tenta register → tenta login → successo → salva stato
  4. Tutto fallisce → HARD STOP: stampa errore rosso e ritorna status
     "blocked". L'orchestratore (orchestrator/core.py) interrompe la
     pipeline per questo servizio invece di far girare i moduli di
     injection/dynamic senza sessione (che produrrebbero solo falsi
     negativi silenziosi).
"""

import json as _json
import urllib.request
import urllib.error
import urllib.parse

from modules.base_runner import BaseRunner, make_run_fn
from orchestrator.colors import step as _step_raw, ok as _ok_raw, warn as _warn_raw, err as _err_raw

def _step(msg: str): _step_raw(f"[session_probe] {msg}")
def _ok(msg: str):   _ok_raw(f"[session_probe] {msg}")
def _warn(msg: str): _warn_raw(f"[session_probe] {msg}")
def _err(msg: str):  _err_raw(f"[session_probe] {msg}")

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

_MAX_REDIRECT_HOPS = 5


def _match_field(name: str, test_user: dict) -> str | None:
    low = name.lower().replace("-", "_")
    for family_key, aliases in _FAMILIES.items():
        if low in aliases or any(low == a or low.endswith("_" + a) or low.startswith(a + "_") for a in aliases):
            return test_user.get(family_key)
    return None


def _path_tokens(path: str) -> set[str]:
    return set(path.lower().replace("-", "_").replace("/", " ").split())


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Blocca il redirect automatico: una 3xx arriva al chiamante come
    HTTPError con lo status/headers ORIGINALI (Set-Cookie incluso), invece
    di sparire dentro un GET automatico che urllib farebbe da solo."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


class SessionProbeRunner(BaseRunner):
    MODULE_NAME = "session_probe"

    def execute(self):
        test_user = self.settings.get("test_user")
        if not test_user:
            _warn("test_user non configurato in settings.json — salto")
            return "skipped", "skip: test_user non configurato in settings.json"

        target_base = (self.settings.get("target_url") or "http://localhost").rstrip("/")

        self._login_ep    = self._find_endpoint(_LOGIN_KEYWORDS)
        self._register_ep = self._find_endpoint(_REGISTER_KEYWORDS)

        if not self._login_ep:
            _warn("nessun endpoint di login trovato — salto")
            return "skipped", "skip: nessun endpoint di login trovato"

        _step(f"login → {self._login_ep['path']}")

        state = self._load_state()
        already_registered = state.get("registered", False)

        # Tenta login diretto
        ok, cookie, auth_header, reason = self._do_login(target_base, self._login_ep, test_user)
        if ok:
            if already_registered:
                _ok("già registrato — login OK")
            else:
                _ok("login OK (credenziali accettate senza registrazione)")
            self._save_state(state, cookie, auth_header, registered=already_registered, logged_in=True)
            return "completed", None

        # Login fallito → registra (o ri-registra dopo reset servizio)
        if self._register_ep:
            if already_registered:
                _warn(f"login fallito ({reason}) — service reset? ri-registro...")
            else:
                _step(f"login fallito ({reason}) — registro nuovo utente → {self._register_ep['path']}")
            self._do_register(target_base, self._register_ep, test_user)
            ok, cookie, auth_header, reason = self._do_login(target_base, self._login_ep, test_user)
            if ok:
                _ok("registrato e loggato con successo")
                self._save_state(state, cookie, auth_header, registered=True, logged_in=True)
                return "completed", None

        # Tutto fallito — hard stop: niente sessione valida, i moduli a valle
        # (injection, dalfox, ...) andrebbero avanti "alla cieca" contro
        # endpoint protetti e produrrebbero solo falsi negativi silenziosi.
        _err(f"AUTENTICAZIONE FALLITA ({reason}).")
        _err("I moduli dinamici auth-dipendenti (sqlmap, ghauri, dalfox, directory_traversal, ...) "
             "verranno saltati per evitare falsi negativi silenziosi contro endpoint protetti; "
             "i moduli statici (semgrep, secret scanning, ...) girano comunque.")
        _err(f"Per abilitare anche i moduli dinamici verifica le credenziali in settings.json → "
             f"test_user (username attuale: {test_user.get('username')!r}) e rilancia.")
        self._save_state(state, None, None, registered=already_registered, logged_in=False)
        return "blocked", f"auth hard-fail: {reason}"

    # ------------------------------------------------------------------
    # Endpoint detection
    # ------------------------------------------------------------------

    def _find_endpoint(self, keywords: set) -> dict | None:
        """Tra gli endpoint il cui path richiama login/register, preferisce
        quello POST con parametri body: molte app (Flask in testa) mappano
        sia una GET (rende il form, nessun parametro) sia una POST (riceve
        le credenziali) sullo stesso path — prendere la prima in ordine di
        file rischia di agganciare la GET e non avere mai nulla da inviare."""
        matches = [ep for ep in self.endpoints if _path_tokens(ep["path"]) & keywords]
        if not matches:
            return None
        posts = [ep for ep in matches if ep.get("method") in ("POST", "PUT", "PATCH") and ep.get("params")]
        return posts[0] if posts else matches[0]

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

    def _encode_body(self, ep: dict, payload: dict) -> tuple[bytes, str]:
        """Rispetta l'encoding reale dell'endpoint (letto da endpoints_map.json),
        stesso pattern di sqlmap_runner.py / ghauri_runner.py."""
        body_params = [p for p in ep.get("params", []) if p.get("location") == "body"]
        use_json = any(p.get("encoding") == "json" for p in body_params)
        if use_json:
            return _json.dumps(payload).encode(), "application/json"
        return urllib.parse.urlencode(payload).encode(), "application/x-www-form-urlencoded"

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _raw_request(self, url: str, data: bytes | None = None, method: str = "GET",
                      content_type: str | None = None, cookies: dict | None = None):
        """Singola chiamata HTTP, non segue mai i redirect.
        Ritorna (status, headers_message_obj, body)."""
        headers = {"Accept": "*/*"}
        if content_type:
            headers["Content-Type"] = content_type
        if cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            resp = _OPENER.open(req, timeout=10)
            return resp.status, resp.headers, resp.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read().decode(errors="replace")
        except Exception as e:
            return -1, {}, str(e)

    def _merge_cookies(self, headers, into: dict) -> None:
        """Accumula ogni Set-Cookie della risposta (possono essere più di uno) in `into`."""
        if not headers:
            return
        try:
            raw_cookies = headers.get_all("Set-Cookie") or []
        except AttributeError:
            single = headers.get("Set-Cookie") if hasattr(headers, "get") else None
            raw_cookies = [single] if single else []
        for raw in raw_cookies:
            name_value = raw.split(";")[0].strip()
            if "=" in name_value:
                name, _, value = name_value.partition("=")
                into[name] = value

    def _token_from_body(self, body: str) -> str | None:
        try:
            data = _json.loads(body)
        except Exception:
            return None
        if isinstance(data, dict):
            for key in ("token", "access_token", "jwt", "auth_token", "id_token", "accessToken"):
                if key in data:
                    return f"Authorization: Bearer {data[key]}"
        return None

    def _follow_redirects(self, base_url: str, location: str, cookies: dict) -> tuple[str, bool]:
        """Segue a mano la catena di redirect (riattaccando i cookie già
        raccolti ad ogni hop), fino a _MAX_REDIRECT_HOPS.
        Ritorna (path_di_destinazione_finale, e' un loop senza uscita)."""
        current = urllib.parse.urljoin(base_url, location)
        for _ in range(_MAX_REDIRECT_HOPS):
            status, headers, _body = self._raw_request(current, method="GET", cookies=cookies)
            self._merge_cookies(headers, cookies)
            if 300 <= status < 400:
                loc = headers.get("Location") if headers else None
                if not loc:
                    break
                current = urllib.parse.urljoin(current, loc)
                continue
            return urllib.parse.urlparse(current).path, False
        return urllib.parse.urlparse(current).path, True

    def _submit(self, base: str, ep: dict, test_user: dict) -> tuple[bool, str | None, str | None, str | None]:
        """POST delle credenziali su `ep`.
        Ritorna (success, cookie_header, auth_header, reason_se_fallito)."""
        payload = self._build_payload(ep, test_user)
        if not payload:
            return False, None, None, "nessun campo credenziali mappato sull'endpoint"

        data, content_type = self._encode_body(ep, payload)
        url = f"{base}{ep['path']}"
        status, headers, body = self._raw_request(url, data=data, method="POST", content_type=content_type)

        cookies: dict = {}
        self._merge_cookies(headers, cookies)

        if 200 <= status < 300:
            auth_header = self._token_from_body(body)
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items()) or None
            return True, cookie_str, auth_header, None

        if 300 <= status < 400:
            location = headers.get("Location") if headers else None
            if not location:
                return False, None, None, f"redirect {status} senza header Location"

            final_path, looped = self._follow_redirects(url, location, cookies)
            if looped:
                return False, None, None, f"redirect loop (>{_MAX_REDIRECT_HOPS} hop) senza destinazione stabile"

            login_path    = self._login_ep["path"] if self._login_ep else None
            register_path = self._register_ep["path"] if self._register_ep else None
            if final_path in (login_path, register_path):
                return False, None, None, f"redirect terminato su {final_path} (credenziali rifiutate)"

            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items()) or None
            return True, cookie_str, None, None

        if status == -1:
            return False, None, None, f"connessione fallita: {body}"
        return False, None, None, f"HTTP {status}"

    def _do_login(self, base: str, ep: dict, test_user: dict) -> tuple[bool, str | None, str | None, str | None]:
        return self._submit(base, ep, test_user)

    def _do_register(self, base: str, ep: dict, test_user: dict) -> bool:
        ok, *_rest = self._submit(base, ep, test_user)
        return ok

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
