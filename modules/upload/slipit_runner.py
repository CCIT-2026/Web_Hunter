"""
modules/upload/slipit_runner.py  — gated: has_file_upload

Testa bypass del controllo estensione file con slipit.
Ogni upload endpoint viene testato con file polimorfici che bypassano
le whitelist/blacklist di estensione.

Output: reports/<service>/slipit.json
"""

from modules.base_runner import BaseRunner, make_run_fn

_TARGET_URL = "http://localhost"
_DEFAULT_PAYLOADS = ["image.php.jpg", "shell.php%00.jpg", "file.phtml", "test.php5"]


class SlipitRunner(BaseRunner):
    MODULE_NAME = "slipit"

    def execute(self):
        if not self.stack.get("has_file_upload"):
            return "skipped", "skip: has_file_upload=False"

        tool_ok = self.tool_available("slipit")
        target_base = self.settings.get("target_url", _TARGET_URL).rstrip("/")

        upload_eps = [
            ep for ep in self.endpoints
            if any(p.get("type") == "file" for p in ep.get("params", []))
            or ep["file"] in {loc["file"] for loc in self.stack.get("file_upload_locations", [])}
        ]
        if not upload_eps:
            return "skipped", "skip: no upload endpoints identified in endpoints_map"

        for ep in upload_eps:
            url = f"{target_base}{ep['path']}"
            param = next((p["name"] for p in ep.get("params", []) if p.get("type") == "file"), "file")

            if tool_ok:
                self._test_with_slipit(url, ep, param)
            else:
                self._test_manual(url, ep, param)

        return "completed", None

    def _test_with_slipit(self, url: str, ep: dict, param: str):
        import tempfile, os
        with tempfile.TemporaryDirectory() as tmpdir:
            rc, stdout, _ = self.sh(
                ["slipit", "-u", url, "-p", param, "-d", tmpdir],
                timeout=self.timeout * 3,
            )
            for line in stdout.splitlines():
                if any(kw in line.lower() for kw in ["bypass", "success", "uploaded", "200"]):
                    self.add_finding(
                        type_="file_upload",
                        file_=ep["file"],
                        line=ep["line"],
                        endpoint=ep["path"],
                        method=ep["method"],
                        confidence="high",
                        detail=f"slipit: {line.strip()[:200]}",
                    )

    def _test_manual(self, url: str, ep: dict, param: str):
        import tempfile, os
        for fname in _DEFAULT_PAYLOADS:
            with tempfile.NamedTemporaryFile(suffix=fname.split(".")[-1], delete=False) as tmp:
                tmp.write(b"<?php phpinfo(); ?>")
                tmp_path = tmp.name
            try:
                rc, stdout, _ = self.sh(
                    ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                     "-F", f"{param}=@{tmp_path};filename={fname}",
                     url, "--max-time", str(self.timeout)],
                )
                if rc == 0 and stdout.strip() in ("200", "201", "302"):
                    self.add_finding(
                        type_="file_upload",
                        file_=ep["file"],
                        line=ep["line"],
                        endpoint=ep["path"],
                        method=ep["method"],
                        confidence="low",
                        detail=f"HTTP {stdout.strip()} uploading {fname!r} — manual verify required",
                        payload=fname,
                        requires_manual_review=True,
                    )
            finally:
                os.unlink(tmp_path)


run = make_run_fn(SlipitRunner)
