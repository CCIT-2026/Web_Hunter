"""
modules/injection/ghauri_runner.py

Complemento a sqlmap: stessa logica di selezione endpoint, tool diverso.
ghauri è più preciso su alcuni DBMS e richiede meno richieste.
Non gated su has_sql_queries (stesso motivo di sqlmap_runner).

Solo detection, non estrazione dati (--dbs/--dump-all esclusi — CTF whitebox).
Output: reports/<service>/ghauri.json
"""

import re

from modules.base_runner import BaseRunner, make_run_fn

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
        cmd = [
            "ghauri", "-u", url,
            "--batch", "--level=1",
            "--timeout", str(self.timeout),
            "--ignore-code=401,403",
        ] + self._load_auth_args()
        if ep["method"] == "POST" and ep.get("params"):
            data = "&".join(f"{p['name']}=TEST" for p in ep["params"] if p["location"] == "body")
            if data:
                cmd += ["--data", data]

        rc, stdout, stderr = self.sh(cmd, timeout=self.timeout * 3)
        if rc == -1:
            return

        # ghauri output: look for "Injectable" / "Parameter" in stdout
        for line in stdout.splitlines():
            if "injectable" in line.lower() or "vulnerable" in line.lower():
                self.add_finding(
                    type_="sqli",
                    file_=ep["file"],
                    line=ep["line"],
                    endpoint=ep["path"],
                    method=ep["method"],
                    confidence="high",
                    detail=f"ghauri: {line.strip()[:200]}",
                )


run = make_run_fn(GhauriRunner)
