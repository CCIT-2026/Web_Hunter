"""
modules/injection/sstimap_runner.py  — attivo se c'è almeno un endpoint con params
(nessun flag booleano dedicato nello stack: il gating fine è qui)

SSTImap cerca Server-Side Template Injection sui parametri degli endpoint.
Si limita agli endpoint con almeno un parametro non-path (body o query).

Output: reports/<service>/sstimap.json
"""

from modules.base_runner import BaseRunner, make_run_fn

_TARGET_URL = "http://localhost"
_INJECTABLE_LOCS = ("body", "query")


class SstimapRunner(BaseRunner):
    MODULE_NAME = "sstimap"

    def execute(self):
        if not self.tool_available("sstimap") and not self.tool_available("SSTImap"):
            return "error", "sstimap not found in PATH"

        target_base = self.settings.get("target_url", _TARGET_URL).rstrip("/")
        tool = "sstimap" if self.tool_available("sstimap") else "SSTImap"

        candidates = [
            ep for ep in self.endpoints
            if any(p["location"] in _INJECTABLE_LOCS for p in ep.get("params", []))
        ]
        if not candidates:
            return "skipped", "skip: no endpoints with body/query params"

        for ep in candidates:
            url = f"{target_base}{ep['path']}"
            for param in ep.get("params", []):
                if param["location"] not in _INJECTABLE_LOCS:
                    continue
                self._test_param(tool, url, ep, param)

        return "completed", None

    def _test_param(self, tool: str, url: str, ep: dict, param: dict):
        cmd = [tool, "-u", url, "-p", param["name"], "--crawl", "0"]
        if ep["method"] == "POST":
            cmd += ["--data", f"{param['name']}=TEST"]

        rc, stdout, _ = self.sh(cmd, timeout=self.timeout * 2)
        if rc == -1:
            return

        for line in stdout.splitlines():
            if any(kw in line.lower() for kw in ["vulnerable", "template injection", "engine"]):
                self.add_finding(
                    type_="ssti",
                    file_=ep["file"],
                    line=ep["line"],
                    endpoint=ep["path"],
                    method=ep["method"],
                    confidence="high",
                    detail=f"sstimap param={param['name']!r}: {line.strip()[:200]}",
                    param=param["name"],
                )


run = make_run_fn(SstimapRunner)
