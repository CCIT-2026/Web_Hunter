"""
modules/discovery/gitleaks_runner.py  — gated su db_present_in_domain

Cerca segreti nella cronologia git (se .git esiste) o nel filesystem.
Nota: il sorgente è montato senza .git (sezione 7 del progetto), quindi
gitleaks gira in modalità detect --no-git sul filesystem.

Output: reports/<service>/gitleaks.json
"""

import json
import tempfile
from pathlib import Path

from modules.base_runner import BaseRunner, make_run_fn


class GitleaksRunner(BaseRunner):
    MODULE_NAME = "gitleaks"

    def execute(self):
        if not self.stack.get("db_present_in_domain"):
            return "skipped", "skip: db_present_in_domain=False"
        if not self.tool_available("gitleaks"):
            return "error", "gitleaks not found in PATH"

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            report_path = tmp.name

        rc, stdout, stderr = self.sh(
            [
                "gitleaks", "detect",
                "--source", str(self.service_root),
                "--no-git",
                "--report-format", "json",
                "--report-path", report_path,
                "--exit-code", "0",  # non fallire se trovati segreti
            ],
            timeout=self.timeout * 2,
        )
        if rc == -1:
            return "error", stderr

        try:
            findings_raw = json.loads(Path(report_path).read_text())
        except Exception:
            return "completed", None  # nessun output = nessun segreto

        if not isinstance(findings_raw, list):
            return "completed", None

        for item in findings_raw:
            rel_file = item.get("File", "")
            line_no = item.get("StartLine")
            rule = item.get("RuleID", "unknown")
            secret = item.get("Secret", "")[:40]
            match = item.get("Match", "")[:80]

            self.add_finding(
                type_="secret",
                file_=rel_file or None,
                line=line_no,
                endpoint=None,
                method=None,
                confidence="high",
                detail=f"gitleaks:{rule} secret={secret!r} match={match!r}",
                requires_manual_review=True,
            )

        return "completed", None


run = make_run_fn(GitleaksRunner)
