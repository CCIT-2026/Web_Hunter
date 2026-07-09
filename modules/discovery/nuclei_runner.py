"""
modules/discovery/nuclei_runner.py  — ungated discovery

Lancia nuclei contro il servizio locale. Richiede che il servizio sia
raggiungibile su un URL locale (settings.target_url oppure autodetect dal
port usato nel container del servizio).

Se target_url non è configurato, tenta di ricavarlo da un file
.target_url nella report_dir (scritto da start.py quando avvia il container
del servizio bersaglio). Se non trovato, skippa con motivazione esplicita.

Template usati: 'http/vulnerabilities' + 'http/exposures' (no DoS/bruteforce).

Output: reports/<service>/nuclei.json
"""

import json
from pathlib import Path

from modules.base_runner import BaseRunner, make_run_fn

_SAFE_TAGS = ["exposure", "misconfig", "cve", "sqli", "xss", "ssti", "ssrf", "traversal"]


class NucleiRunner(BaseRunner):
    MODULE_NAME = "nuclei"

    def execute(self):
        if not self.tool_available("nuclei"):
            return "error", "nuclei not found in PATH"

        target = self._resolve_target()
        if not target:
            return "skipped", "skip: target_url not configured and .target_url not found in report_dir"

        with __import__("tempfile").NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            out_path = tmp.name

        rc, stdout, stderr = self.sh(
            [
                "nuclei",
                "-target", target,
                "-tags", ",".join(_SAFE_TAGS),
                "-jsonl",
                "-output", out_path,
                "-timeout", str(self.timeout),
                "-silent",
                "-no-interactsh",
            ],
            timeout=self.timeout * 6,
        )
        if rc == -1:
            return "error", stderr

        for line in Path(out_path).read_text().splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            template_id = obj.get("template-id", "unknown")
            severity = obj.get("info", {}).get("severity", "info")
            conf_map = {"critical": "high", "high": "high", "medium": "medium",
                        "low": "low", "info": "low"}
            matched_at = obj.get("matched-at", "")
            name = obj.get("info", {}).get("name", template_id)

            self.add_finding(
                type_="nuclei",
                file_=None,
                line=None,
                endpoint=matched_at,
                method=None,
                confidence=conf_map.get(severity, "low"),
                detail=f"[{template_id}] {name} — {matched_at}",
                requires_manual_review=True,
            )

        return "completed", None

    def _resolve_target(self) -> str | None:
        url = self.settings.get("target_url", "").strip()
        if url:
            return url
        dot_target = self.report_dir / ".target_url"
        if dot_target.exists():
            return dot_target.read_text().strip()
        return None


run = make_run_fn(NucleiRunner)
