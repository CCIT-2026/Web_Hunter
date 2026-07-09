"""
modules/discovery/trufflehog_runner.py  — gated su db_present_in_domain

Cerca segreti nel filesystem con trufflehog (modalità filesystem, no git).

Output: reports/<service>/trufflehog.json
"""

import json

from modules.base_runner import BaseRunner, make_run_fn


class TrufflehogRunner(BaseRunner):
    MODULE_NAME = "trufflehog"

    def execute(self):
        if not self.stack.get("db_present_in_domain"):
            return "skipped", "skip: db_present_in_domain=False"
        if not self.tool_available("trufflehog"):
            return "error", "trufflehog not found in PATH"

        rc, stdout, stderr = self.sh(
            ["trufflehog", "filesystem", "--json", "--no-update", str(self.service_root)],
            timeout=self.timeout * 3,
        )
        if rc == -1:
            return "error", stderr

        for line in stdout.splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue

            detector = obj.get("DetectorName", "unknown")
            raw = obj.get("Raw", "")[:80]
            source = obj.get("SourceMetadata", {})
            data = source.get("Data", {}).get("Filesystem", {})
            rel_file = data.get("file", "")
            line_no = data.get("line")

            self.add_finding(
                type_="secret",
                file_=rel_file or None,
                line=line_no,
                endpoint=None,
                method=None,
                confidence="high",
                detail=f"trufflehog:{detector} raw={raw!r}",
                requires_manual_review=True,
            )

        return "completed", None


run = make_run_fn(TrufflehogRunner)
