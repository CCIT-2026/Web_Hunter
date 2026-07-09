"""
modules/lang_specific/phpggc_runner.py  — gated: has_php

Elenca le gadget chain disponibili per il framework PHP rilevato e
le cross-referenzia con i punti di deserializzazione trovati nel mapping.
Non invia payload: genera output per analisi manuale (richiederebbe un
endpoint vivo e un contesto specifico).

Output: reports/<service>/phpggc.json
"""

import re
from modules.base_runner import BaseRunner, make_run_fn

_UNSERIALIZE = re.compile(r"\bunserialize\s*\(", re.I)


class PhpggcRunner(BaseRunner):
    MODULE_NAME = "phpggc"

    def execute(self):
        if not self.stack.get("has_php"):
            return "skipped", "skip: has_php=False"
        if not self.tool_available("phpggc"):
            return "error", "phpggc not found in PATH"

        fw = self.stack.get("framework", "")
        rc, stdout, _ = self.sh(["phpggc", "--list"], timeout=10)
        if rc == -1:
            return "error", stdout or "phpggc --list failed"

        # Filter chains relevant to detected framework
        relevant = []
        for line in stdout.splitlines():
            if not line.strip() or line.startswith("Gadget"):
                continue
            if fw and fw.lower() in line.lower():
                relevant.append(line.strip())
            elif any(kw in line.lower() for kw in ["laravel", "symfony", "wordpress", "yii", "slim", "zend"]):
                relevant.append(line.strip())

        # Find unserialize() call sites in source
        for fpath in self.service_root.rglob("*.php"):
            if ".git" in fpath.parts:
                continue
            try:
                src = fpath.read_text(errors="replace")
            except Exception:
                continue
            rel = str(fpath.relative_to(self.service_root))
            for i, line in enumerate(src.splitlines()):
                if _UNSERIALIZE.search(line):
                    for chain in relevant[:5]:
                        self.add_finding(
                            type_="deserialization",
                            file_=rel,
                            line=i + 1,
                            endpoint=None,
                            method=None,
                            confidence="medium",
                            detail=f"unserialize() sink — potential chain: {chain}",
                            requires_manual_review=True,
                        )
                    if not relevant:
                        self.add_finding(
                            type_="deserialization",
                            file_=rel,
                            line=i + 1,
                            endpoint=None,
                            method=None,
                            confidence="low",
                            detail="unserialize() sink found — no matching phpggc chain for framework",
                            requires_manual_review=True,
                        )
                    break  # one finding per file

        return "completed", None


run = make_run_fn(PhpggcRunner)
