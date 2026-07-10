"""
modules/injection/sqlmap_runner.py

Testa SQL injection su ogni endpoint con parametri trovati nel mapping.
NON fa discovery propria: legge endpoints_map.json.

Priorità: endpoint adiacenti a query SQL nel codice sorgente; fallback a tutti
gli endpoint parametrizzati. Non gated su has_sql_queries: lo stack_detector
può perdere pattern ORM non standard.

Usa --batch --level=2 --risk=1 (test locali, no ban risk).
Output: reports/<service>/sqlmap.json
"""

import json as _json
import re

from modules.base_runner import BaseRunner, make_run_fn

_TARGET_URL = "http://localhost"  # overridden by settings.target_url

# Flask/Werkzeug path param patterns → safe placeholder values
_PATH_PARAM_RE = [
    (re.compile(r"<(?:int|float):[^>]+>"), "1"),
    (re.compile(r"<path:[^>]+>"),          "test/path"),
    (re.compile(r"<[^>]+>"),               "test"),
]


def _sanitize_url_path(path: str) -> str:
    for pattern, replacement in _PATH_PARAM_RE:
        path = pattern.sub(replacement, path)
    return path


class SqlmapRunner(BaseRunner):
    MODULE_NAME = "sqlmap"

    def execute(self):
        if not self.tool_available("sqlmap"):
            return "error", "sqlmap not found in PATH"

        target_base = (self.settings.get("target_url") or _TARGET_URL).rstrip("/")

        # Only test endpoints that have parameters and sit near SQL locations
        sql_files = {loc["file"] for loc in self.stack.get("sql_query_locations", [])}
        candidates = [
            ep for ep in self.endpoints
            if ep.get("params") and ep["file"] in sql_files
        ]
        if not candidates:
            # Fallback: test all parameterized endpoints
            candidates = [ep for ep in self.endpoints if ep.get("params")]
        if not candidates:
            return "skipped", "skip: no parameterized endpoints found near SQL sinks"

        for ep in candidates:
            url = f"{target_base}{_sanitize_url_path(ep['path'])}"
            self._test_endpoint(url, ep)

        return "completed", None

    def _load_auth_args(self) -> list[str]:
        """Legge auth_state.json e ritorna gli argomenti sqlmap per cookie/header."""
        state = self._load_json("auth_state.json") or {}
        if not state.get("logged_in"):
            return []
        args = []
        if state.get("cookie"):
            args += ["--cookie", state["cookie"]]
        if state.get("auth_header"):
            # "Authorization: Bearer eyJ..." → -H "Authorization: Bearer eyJ..."
            args += ["-H", state["auth_header"]]
        return args

    def _test_endpoint(self, url: str, ep: dict):
        cmd = [
            "sqlmap", "-u", url,
            "--batch", "--level=2", "--risk=1",
            "--timeout", str(self.timeout),
            "--ignore-code=401,403",
        ] + self._load_auth_args()

        body_params = [p for p in ep.get("params", []) if p["location"] == "body"]
        query_params = [p for p in ep.get("params", []) if p["location"] == "query"]

        if ep["method"] in ("POST", "PUT", "PATCH") and body_params:
            use_json = any(p.get("encoding") == "json" for p in body_params)
            if use_json:
                payload = _json.dumps({p["name"]: "SQLITEST" for p in body_params})
                cmd += ["--data", payload, "-H", "Content-Type: application/json"]
            else:
                cmd += ["--data", "&".join(f"{p['name']}=SQLITEST" for p in body_params)]
        elif query_params:
            qs = "&".join(f"{p['name']}=SQLITEST" for p in query_params)
            url = f"{url}?{qs}"
            cmd[cmd.index("-u") + 1] = url

        rc, stdout, stderr = self.sh(cmd, timeout=self.timeout * 4)

        if rc == -1:
            return

        seen_params: set[str] = set()

        def _emit(param: str, technique: str):
            if param in seen_params:
                return
            seen_params.add(param)
            self.add_finding(
                type_="sqli",
                file_=ep["file"],
                line=ep["line"],
                endpoint=ep["path"],
                method=ep["method"],
                confidence="high",
                detail=f"sqlmap: param={param} technique={technique or 'unknown'}",
                param=param,
            )

        # Two parsing strategies for sqlmap output:
        #
        # 1. Inline [INFO] lines:
        #    "[INFO] POST parameter 'username' appears to be '...' injectable"
        #
        # 2. Summary block (printed after all tests):
        #    "Parameter: username (POST)"
        #    "    Type: boolean-based blind"
        #
        # Strategy 1 fires first; strategy 2 deduplicates via seen_params.

        summary_param: str | None = None
        for line in stdout.splitlines():
            # Strategy 1: inline "[INFO] ... parameter 'x' appears to be '...' injectable"
            m = re.search(
                r"parameter\s+'([^']+)'.*?appears\s+to\s+be\s+'([^']+)'\s+injectable",
                line, re.I,
            )
            if m:
                _emit(m.group(1).strip(), m.group(2).strip())
                continue

            # Strategy 2a: summary "Parameter: x (METHOD)"
            m = re.search(r"^Parameter:\s+(.+?)\s*\(", line)
            if m:
                summary_param = m.group(1).strip()
                continue

            # Strategy 2b: summary "    Type: ..."
            if summary_param:
                m = re.search(r"^\s+Type:\s+(.+)", line)
                if m:
                    _emit(summary_param, m.group(1).strip())
                    summary_param = None


run = make_run_fn(SqlmapRunner)
