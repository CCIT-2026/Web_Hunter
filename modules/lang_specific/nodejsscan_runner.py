"""
modules/lang_specific/nodejsscan_runner.py  — gated: language==javascript

Esegue nodejsscan (njsscan) sull'intero sorgente Node.js.
Output SARIF/JSON → findings standard.

Output: reports/<service>/nodejsscan.json
"""

import json
import tempfile
from pathlib import Path
from modules.base_runner import BaseRunner, make_run_fn

_SEVERITY_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


class NodejsscanRunner(BaseRunner):
    MODULE_NAME = "nodejsscan"

    def execute(self):
        if self.stack.get("language") != "javascript":
            return "skipped", "skip: language != javascript"

        tool = next((t for t in ("njsscan", "nodejsscan") if self.tool_available(t)), None)
        if not tool:
            return "error", "njsscan/nodejsscan not found in PATH"

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path = tmp.name

        rc, stdout, stderr = self.sh(
            [tool, "--json", "-o", out_path, str(self.service_root)],
            timeout=self.timeout * 3,
        )
        if rc == -1:
            return "error", stderr

        try:
            data = json.loads(Path(out_path).read_text())
        except Exception:
            return "completed", None  # empty output = no findings

        # njsscan JSON: {"nodejs": {"rule_id": {"files": [...], "metadata": {...}}}}
        for lang_key, rules in data.items():
            if not isinstance(rules, dict):
                continue
            for rule_id, rule_data in rules.items():
                meta = rule_data.get("metadata", {})
                severity = _SEVERITY_MAP.get(meta.get("severity", "INFO").upper(), "low")
                desc = meta.get("description", rule_id)

                for finfo in rule_data.get("files", []):
                    rel = finfo.get("file_path", "")
                    line_no = finfo.get("match_lines", [None])[0]
                    ep = next((e for e in self.endpoints if e["file"] == rel), None)

                    self.add_finding(
                        type_=rule_id.lower().replace("-", "_"),
                        file_=rel or None,
                        line=line_no,
                        endpoint=ep["path"] if ep else None,
                        method=ep["method"] if ep else None,
                        confidence=severity,
                        detail=f"[{rule_id}] {desc}",
                        requires_manual_review=True,
                    )

        return "completed", None


run = make_run_fn(NodejsscanRunner)
