"""
modules/discovery/ripgrep_runner.py  — sempre attivo (ALWAYS_RUN)

Cerca pattern di vulnerabilità con ripgrep (rg) leggendo wordlist da:
  <settings.wordlists_path>/ripgrep/*.txt

Ogni .txt nella cartella è trattato come lista di pattern (uno per riga).
Il nome del file determina il tipo di finding (es. sqli_patterns.txt → sqli).
Se la cartella non esiste, usa pattern interni minimali di fallback.

Output: reports/<service>/ripgrep.json
"""

import os
import re
from pathlib import Path

from modules.base_runner import BaseRunner, make_run_fn

# Pattern interni minimali se mancano wordlist esterne
_BUILTIN_PATTERNS: dict[str, list[str]] = {
    "sqli": [
        r'cursor\.execute\s*\(.*%s',
        r'\"SELECT.*\+.*request\.',
        r"format\s*\(.*SELECT",
    ],
    "hardcoded_secret": [
        r'(?:password|secret|api_key|token)\s*=\s*["\'][^"\']{6,}["\']',
        r'(?:SECRET_KEY|API_KEY|DB_PASSWORD)\s*=\s*["\'][^"\']+["\']',
    ],
    "command_injection": [
        r'os\.system\s*\(',
        r'subprocess\.call\s*\(.*shell\s*=\s*True',
        r'exec\s*\(\s*["\']',
    ],
    "path_traversal": [
        r'open\s*\(\s*(?:request|req)\.',
        r'send_file\s*\(',
    ],
}

_SKIP_DIRS = [".git", "node_modules", "__pycache__", ".venv", "vendor"]


class RipgrepRunner(BaseRunner):
    MODULE_NAME = "ripgrep"

    def execute(self):
        if not self.tool_available("rg"):
            return "error", "ripgrep (rg) not found in PATH"

        patterns = self._load_patterns()
        for type_, pats in patterns.items():
            for pat in pats:
                self._run_pattern(pat, type_)

        return "completed", None

    def _load_patterns(self) -> dict[str, list[str]]:
        wl_path = Path(self.settings.get("wordlists_path", "/home/wordlists")) / "ripgrep"
        if not wl_path.is_dir():
            return _BUILTIN_PATTERNS

        patterns: dict[str, list[str]] = {}
        for txt in wl_path.glob("*.txt"):
            type_ = txt.stem.replace("-", "_").lower()
            lines = [l.strip() for l in txt.read_text().splitlines() if l.strip() and not l.startswith("#")]
            if lines:
                patterns[type_] = lines
        return patterns or _BUILTIN_PATTERNS

    def _run_pattern(self, pattern: str, type_: str):
        skip_args = []
        for d in _SKIP_DIRS:
            skip_args += ["--glob", f"!{d}/**"]

        rc, stdout, _ = self.sh(
            ["rg", "--json", "-i", "-e", pattern, str(self.service_root)] + skip_args,
            timeout=30,
        )
        if rc not in (0, 1):
            return  # 1 = no matches, -1 = not found (handled above)

        for line in stdout.splitlines():
            try:
                obj = __import__("json").loads(line)
            except Exception:
                continue
            if obj.get("type") != "match":
                continue
            data = obj["data"]
            rel = str(Path(data["path"]["text"]).relative_to(self.service_root) if Path(data["path"]["text"]).is_absolute() else data["path"]["text"])
            line_no = data["line_number"]
            text = data["lines"]["text"].strip()

            ep = next((e for e in self.endpoints if e["file"] == rel), None)
            self.add_finding(
                type_=type_,
                file_=rel,
                line=line_no,
                endpoint=ep["path"] if ep else None,
                method=ep["method"] if ep else None,
                confidence="low",
                detail=f"pattern={pattern!r}: {text[:120]}",
                requires_manual_review=True,
            )


run = make_run_fn(RipgrepRunner)
