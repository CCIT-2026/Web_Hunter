"""
modules/injection/ghauri_runner.py  — gated su has_sql_queries

Complemento a sqlmap: stesso gating, stessa logica di selezione endpoint,
diverso tool. ghauri è più preciso su alcuni DBMS e richiede meno richieste.

Differenza vs sqlmap_runner: usa --dbs --dump-all a discrezione dell'analista
(qui solo detection, non estrazione dati — CTF whitebox, non pentest).

Output: reports/<service>/ghauri.json
"""

from modules.base_runner import BaseRunner, make_run_fn

_TARGET_URL = "http://localhost"


class GhauriRunner(BaseRunner):
    MODULE_NAME = "ghauri"

    def execute(self):
        if not self.stack.get("has_sql_queries"):
            return "skipped", "skip: has_sql_queries=False"
        if not self.tool_available("ghauri"):
            return "error", "ghauri not found in PATH"

        target_base = self.settings.get("target_url", _TARGET_URL).rstrip("/")
        sql_files = {loc["file"] for loc in self.stack.get("sql_query_locations", [])}
        candidates = [ep for ep in self.endpoints if ep.get("params") and ep["file"] in sql_files]
        if not candidates:
            candidates = [ep for ep in self.endpoints if ep.get("params")]
        if not candidates:
            return "skipped", "skip: no parameterized endpoints"

        for ep in candidates:
            url = f"{target_base}{ep['path']}"
            self._test_endpoint(url, ep)

        return "completed", None

    def _test_endpoint(self, url: str, ep: dict):
        cmd = [
            "ghauri", "-u", url,
            "--batch", "--level=1",
            "--timeout", str(self.timeout),
        ]
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
