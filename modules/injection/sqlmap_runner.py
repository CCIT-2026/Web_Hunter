"""
modules/injection/sqlmap_runner.py  — gated su has_sql_queries

Testa SQL injection su ogni endpoint con parametri trovati nel mapping.
NON fa discovery propria: legge endpoints_map.json.

Usa --batch --level=2 --risk=1 (test locali, no ban risk).
Output: reports/<service>/sqlmap.json
"""

import json
import tempfile
from pathlib import Path

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
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            cmd = [
                "sqlmap", "-u", url,
                "--batch", "--level=2", "--risk=1",
                "--output-dir", str(out_dir),
                "--format=JSON",
                "--timeout", str(self.timeout),
            ]
            # Add POST data if method is POST
            if ep["method"] == "POST" and ep.get("params"):
                data = "&".join(f"{p['name']}=TEST" for p in ep["params"] if p["location"] == "body")
                if data:
                    cmd += ["--data", data]

            rc, stdout, stderr = self.sh(cmd, timeout=self.timeout * 4)
            if rc == -1:
                return

            # Parse sqlmap JSON output from output dir
            for json_file in out_dir.rglob("*.json"):
                try:
                    data = json.loads(json_file.read_text())
                except Exception:
                    continue
                vulns = data.get("data", [])
                for v in vulns:
                    place = v.get("place", "")
                    param = v.get("parameter", "")
                    payloads = v.get("data", {})
                    for ptype, pdata in payloads.items():
                        self.add_finding(
                            type_="sqli",
                            file_=ep["file"],
                            line=ep["line"],
                            endpoint=ep["path"],
                            method=ep["method"],
                            confidence="high",
                            detail=f"SQLi confirmed: place={place} param={param} technique={ptype}",
                            param=param,
                        )


run = make_run_fn(SqlmapRunner)
