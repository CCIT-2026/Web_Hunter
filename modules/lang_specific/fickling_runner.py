"""
modules/lang_specific/fickling_runner.py  — gated: language==python AND has_eval_on_input

Usa fickling per analizzare file pickle nel sorgente o ricevuti via endpoint.
Se trovati eval/exec/pickle.loads su input utente (già rilevati dallo stack_detector),
genera payload di prova e riporta file:riga per verifica manuale.

Output: reports/<service>/fickling.json
"""

import json
from pathlib import Path
from modules.base_runner import BaseRunner, make_run_fn

_PICKLE_EXTS = {".pkl", ".pickle", ".pt", ".pth", ".joblib", ".npy"}


class FicklingRunner(BaseRunner):
    MODULE_NAME = "fickling"

    def execute(self):
        if not (self.stack.get("language") == "python" and self.stack.get("has_eval_on_input")):
            return "skipped", "skip: requires language=python AND has_eval_on_input=True"
        if not self.tool_available("fickling"):
            return "error", "fickling not found in PATH"

        # 1. Analizza ogni file pickle trovato nel sorgente
        for fpath in self.service_root.rglob("*"):
            if fpath.suffix.lower() in _PICKLE_EXTS and ".git" not in fpath.parts:
                self._analyze_pickle(fpath)

        # 2. Per ogni sink eval/pickle già trovato dallo stack_detector, segnala per verifica
        for loc in self.stack.get("eval_locations", []):
            sink = loc.get("sink", "unknown")
            self.add_finding(
                type_="deserialization",
                file_=loc["file"],
                line=loc["line"],
                endpoint=loc.get("endpoint"),
                method=None,
                confidence="high" if "pickle" in sink else "medium",
                detail=f"Python sink={sink!r} on user input — verify fickling payload reachability",
                requires_manual_review=True,
            )

        return "completed", None

    def _analyze_pickle(self, fpath: Path):
        rel = str(fpath.relative_to(self.service_root))
        rc, stdout, stderr = self.sh(
            ["fickling", "--json", str(fpath)], timeout=self.timeout,
        )
        if rc == -1 or not stdout.strip():
            return
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return

        for node in data if isinstance(data, list) else [data]:
            if node.get("is_likely_safe") is False or node.get("severity", "").lower() in ("high", "critical"):
                self.add_finding(
                    type_="deserialization",
                    file_=rel,
                    line=None,
                    endpoint=None,
                    method=None,
                    confidence="high",
                    detail=f"fickling: malicious pickle detected — {node.get('description', 'unsafe opcode')}",
                    requires_manual_review=True,
                )


run = make_run_fn(FicklingRunner)
