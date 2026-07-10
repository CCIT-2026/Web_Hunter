"""
modules/injection/sqlmap_runner.py  — gated su has_sql_queries

Testa SQL injection su ogni endpoint con parametri trovati nel mapping.
NON fa discovery propria: legge endpoints_map.json.

Usa --batch --level=2 --risk=1 (test locali, no ban risk).
Output: reports/<service>/sqlmap.json
"""

import json as _json
import re

from modules.base_runner import BaseRunner, make_run_fn

_TARGET_URL = "http://localhost"  # overridden by settings.target_url


class SqlmapRunner(BaseRunner):
    MODULE_NAME = "sqlmap"

    def execute(self):
        if not self.stack.get("has_sql_queries"):
            return "skipped", "skip: has_sql_queries=False"
        if not self.tool_available("sqlmap"):
            return "error", "sqlmap not found in PATH"

        target_base = self.settings.get("target_url", _TARGET_URL).rstrip("/")

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
            url = f"{target_base}{ep['path']}"
            self._test_endpoint(url, ep)

        return "completed", None

    def _test_endpoint(self, url: str, ep: dict):
        cmd = [
            "sqlmap", "-u", url,
            "--batch", "--level=2", "--risk=1",
            "--timeout", str(self.timeout),
        ]

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

        # sqlmap writes results as text; parse its stdout for confirmed findings
        # Patterns: "Parameter: X (POST)" / "Type: " / "is vulnerable"
        current_param = None
        current_type = None
        for line in stdout.splitlines():
            low = line.lower()
            if "parameter:" in low:
                # "Parameter: username (POST)" or "Parameter: username (GET)"
                m = re.search(r"parameter:\s*['\"]?([^'\"(]+)['\"]?\s*\(", line, re.I)
                if m:
                    current_param = m.group(1).strip()
            if "type:" in low and current_param:
                m = re.search(r"type:\s*(.+)", line, re.I)
                if m:
                    current_type = m.group(1).strip()
            if ("is vulnerable" in low or "appears to be" in low) and current_param:
                self.add_finding(
                    type_="sqli",
                    file_=ep["file"],
                    line=ep["line"],
                    endpoint=ep["path"],
                    method=ep["method"],
                    confidence="high",
                    detail=f"sqlmap: param={current_param} technique={current_type or 'unknown'}",
                    param=current_param,
                )
                current_param = None
                current_type = None


run = make_run_fn(SqlmapRunner)
