"""
modules/injection/ghauri_runner.py

Complemento a sqlmap: stessa logica di selezione endpoint, tool diverso.
ghauri è più preciso su alcuni DBMS e richiede meno richieste.
Non gated su has_sql_queries (stesso motivo di sqlmap_runner).

Solo detection, non estrazione dati (--dbs/--dump-all esclusi — CTF whitebox).
Output: reports/<service>/ghauri.json

NOTE su output di ghauri: tutto l'output diagnostico ([INFO]/[WARNING]/[CRITICAL])
va su STDERR; STDOUT contiene solo il banner e i prompt interattivi.
Il parser deve quindi ispezionare stderr.
"""

import logging
import re

from modules.base_runner import BaseRunner, make_run_fn

logger = logging.getLogger(__name__)

# Emetti finding medium-confidence se ghauri vede almeno N segnali "appears to be
# injectable" per un parametro ma li scarta tutti come false positive.
_FALSE_POS_THRESHOLD = 3

_TARGET_URL = "http://localhost"

_PATH_PARAM_RE = [
    (re.compile(r"<(?:int|float):[^>]+>"), "1"),
    (re.compile(r"<path:[^>]+>"),          "test/path"),
    (re.compile(r"<[^>]+>"),               "test"),
]


def _sanitize_url_path(path: str) -> str:
    for pattern, replacement in _PATH_PARAM_RE:
        path = pattern.sub(replacement, path)
    return path


class GhauriRunner(BaseRunner):
    MODULE_NAME = "ghauri"

    def execute(self):
        if not self.tool_available("ghauri"):
            return "error", "ghauri not found in PATH"

        target_base = (self.settings.get("target_url") or _TARGET_URL).rstrip("/")
        sql_files = {loc["file"] for loc in self.stack.get("sql_query_locations", [])}
        candidates = [ep for ep in self.endpoints if ep.get("params") and ep["file"] in sql_files]
        if not candidates:
            candidates = [ep for ep in self.endpoints if ep.get("params")]
        if not candidates:
            return "skipped", "skip: no parameterized endpoints"

        for ep in candidates:
            url = f"{target_base}{_sanitize_url_path(ep['path'])}"
            self._test_endpoint(url, ep)

        return "completed", None

    def _load_auth_args(self) -> list[str]:
        state = self._load_json("auth_state.json") or {}
        if not state.get("logged_in"):
            return []
        args = []
        if state.get("cookie"):
            args += ["--cookie", state["cookie"]]
        if state.get("auth_header"):
            args += ["-H", state["auth_header"]]
        return args

    def _test_endpoint(self, url: str, ep: dict):
        import json as _json

        cmd = [
            "ghauri", "-u", url,
            "--batch", "--level=1",
            "--timeout", str(self.timeout),
            "--ignore-code=401,403",
        ] + self._load_auth_args()

        body_params  = [p for p in ep.get("params", []) if p["location"] == "body"]
        query_params = [p for p in ep.get("params", []) if p["location"] == "query"]

        if ep["method"] in ("POST", "PUT", "PATCH") and body_params:
            use_json = any(p.get("encoding") == "json" for p in body_params)
            if use_json:
                payload = _json.dumps({p["name"]: "GHAURITEST" for p in body_params})
                cmd += ["--data", payload, "-H", "Content-Type: application/json"]
            else:
                cmd += ["--data", "&".join(f"{p['name']}=GHAURITEST" for p in body_params)]
        elif query_params:
            qs = "&".join(f"{p['name']}=GHAURITEST" for p in query_params)
            url = f"{url}?{qs}"
            cmd[cmd.index("-u") + 1] = url

        rc, stdout, stderr = self.sh(cmd, timeout=self.timeout * 3)

        if rc == -1:
            return
        if rc == -2:
            logger.warning("ghauri: timeout su %s — endpoint saltato", ep["path"])
            return
        if rc not in (0, 1):
            logger.warning("ghauri: RC=%d inatteso su %s", rc, ep["path"])

        seen: set[str] = set()
        # Conta segnali "appears to be injectable" per param (possono essere false positive)
        signals: dict[str, int] = {}

        # Frasi che indicano linee negative/rumore — da saltare nel path high-confidence
        _NEGATIVE = (
            "appears to be",    # tentativo (gestito dal contatore signals)
            "does not seem",    # verdetto negativo per-param
            "not appear to be", # verdetto negativo finale
            "might not",        # euristica negativa
            "all tested",       # riassunto finale negativo
            "false positive",   # warning false positive
        )

        # ghauri scrive tutto l'output diagnostico su stderr
        for line in stderr.splitlines():
            low = line.lower()

            # Conta segnali injectable (inclusi quelli poi scartati come false positive)
            m_sig = re.search(
                r"parameter\s+'([^']+)'.*?appears\s+to\s+be.*?injectable", line, re.I
            )
            if m_sig:
                param = m_sig.group(1).strip()
                signals[param] = signals.get(param, 0) + 1
                continue  # non emettere subito: aspetta verdetto finale

            if "injectable" not in low and "vulnerable" not in low:
                continue
            if any(p in low for p in _NEGATIVE):
                continue

            # Deve esserci un parametro esplicito identificato
            m = re.search(r"parameter\s+'([^']+)'", line, re.I)
            if not m:
                continue
            param = m.group(1).strip()
            if param in seen:
                continue
            seen.add(param)
            self.add_finding(
                type_="sqli",
                file_=ep["file"],
                line=ep["line"],
                endpoint=ep["path"],
                method=ep["method"],
                confidence="high",
                detail=f"ghauri: param={param} — {line.strip()[:160]}",
                param=param,
            )

        # Finding medium-confidence: molti segnali injectable ma tutti scartati come false positive.
        # Pattern tipico: server con risposte variabili (es. 401/500) che ingannano il boolean oracle.
        for param, count in signals.items():
            if param not in seen and count >= _FALSE_POS_THRESHOLD:
                seen.add(param)
                self.add_finding(
                    type_="sqli",
                    file_=ep["file"],
                    line=ep["line"],
                    endpoint=ep["path"],
                    method=ep["method"],
                    confidence="medium",
                    detail=(
                        f"ghauri: param={param} — {count}x segnale injectable scartato come "
                        f"false positive (risposte server instabili — verificare con sqlmap)"
                    ),
                    param=param,
                )


run = make_run_fn(GhauriRunner)
