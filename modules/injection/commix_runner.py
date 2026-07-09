"""
modules/injection/commix_runner.py  — attivo se c'è almeno un endpoint con params

commix testa OS command injection sui parametri degli endpoint.
Differenza vs sstimap: usa --output-dir per raccogliere i log strutturati.

Output: reports/<service>/commix.json
"""

import tempfile
from pathlib import Path

from modules.base_runner import BaseRunner, make_run_fn

_TARGET_URL = "http://localhost"
_INJECTABLE_LOCS = ("body", "query")


class CommixRunner(BaseRunner):
    MODULE_NAME = "commix"

    def execute(self):
        if not self.tool_available("commix"):
            return "error", "commix not found in PATH"

        target_base = self.settings.get("target_url", _TARGET_URL).rstrip("/")
        candidates = [
            ep for ep in self.endpoints
            if any(p["location"] in _INJECTABLE_LOCS for p in ep.get("params", []))
        ]
        if not candidates:
            return "skipped", "skip: no endpoints with body/query params"

        for ep in candidates:
            url = f"{target_base}{ep['path']}"
            self._test_endpoint(url, ep)

        return "completed", None

    def _test_endpoint(self, url: str, ep: dict):
        with tempfile.TemporaryDirectory() as tmpdir:
            cmd = [
                "commix", "--url", url,
                "--batch",
                "--output-dir", tmpdir,
                "--timeout", str(self.timeout),
            ]
            if ep["method"] == "POST" and ep.get("params"):
                data = "&".join(
                    f"{p['name']}=TEST"
                    for p in ep["params"]
                    if p["location"] in _INJECTABLE_LOCS
                )
                if data:
                    cmd += ["--data", data]

            rc, stdout, _ = self.sh(cmd, timeout=self.timeout * 3)
            if rc == -1:
                return

            for line in stdout.splitlines():
                if any(kw in line.lower() for kw in ["vulnerable", "command injection", "shell"]):
                    self.add_finding(
                        type_="command_injection",
                        file_=ep["file"],
                        line=ep["line"],
                        endpoint=ep["path"],
                        method=ep["method"],
                        confidence="high",
                        detail=f"commix: {line.strip()[:200]}",
                    )


run = make_run_fn(CommixRunner)
