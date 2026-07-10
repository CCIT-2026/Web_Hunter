"""
modules/lang_specific/symfony_runner.py  — gated: has_symfony_twig

Controlla debolezze comuni Symfony/Twig:
  - Twig SSTI (render con variabile da input utente)
  - APP_SECRET debole o hardcoded
  - Debug mode attivo in produzione
  - _fragment route abilitata

Statico (analisi sorgente), nessuna richiesta HTTP — produce findings
con file:riga per verifica manuale.

Output: reports/<service>/symfony.json
"""

import re
from modules.base_runner import BaseRunner, make_run_fn

_TWIG_VAR     = re.compile(r"""render\s*\(\s*(?:.*?\+.*?|\$\w+)\s*[,\)]""", re.I)
_APP_SECRET   = re.compile(r"""APP_SECRET\s*=\s*['"]?(\w{1,32})['"]?""")
_DEBUG_TRUE   = re.compile(r"""APP_DEBUG\s*=\s*true|debug:\s*true""", re.I)
_FRAGMENT     = re.compile(r"""_fragment|esi\.enabled:\s*true""", re.I)
_ENV_FILES    = {".env", ".env.local", ".env.prod", "config/packages/framework.yaml"}


class SymfonyRunner(BaseRunner):
    MODULE_NAME = "symfony"

    def execute(self):
        if not self.stack.get("has_symfony_twig"):
            return "skipped", "skip: has_symfony_twig=False"

        for fpath in self.service_root.rglob("*"):
            if ".git" in fpath.parts or fpath.is_dir():
                continue
            rel = str(fpath.relative_to(self.service_root))
            ext = fpath.suffix.lower()
            try:
                src = fpath.read_text(errors="replace")
            except Exception:
                continue

            lines = src.splitlines()

            if ext in {".php", ".twig"}:
                for i, line in enumerate(lines):
                    if _TWIG_VAR.search(line):
                        self.add_finding(
                            type_="ssti",
                            file_=rel, line=i + 1,
                            endpoint=None, method=None,
                            confidence="medium",
                            detail="Twig render() with dynamic template path — potential SSTI if path from input",
                            requires_manual_review=True,
                        )

            if rel in _ENV_FILES or ext in {".yaml", ".yml"} or fpath.name.startswith(".env"):
                for i, line in enumerate(lines):
                    m = _APP_SECRET.search(line)
                    if m and len(m.group(1)) < 32:
                        self.add_finding(
                            type_="secret",
                            file_=rel, line=i + 1,
                            endpoint=None, method=None,
                            confidence="high",
                            detail=f"APP_SECRET too short ({len(m.group(1))} chars) — vulnerable to cookie forgery",
                        )
                    if _DEBUG_TRUE.search(line):
                        self.add_finding(
                            type_="misconfig",
                            file_=rel, line=i + 1,
                            endpoint=None, method=None,
                            confidence="medium",
                            detail="APP_DEBUG=true detected — may expose stack traces in production",
                            requires_manual_review=True,
                        )
                    if _FRAGMENT.search(line):
                        self.add_finding(
                            type_="misconfig",
                            file_=rel, line=i + 1,
                            endpoint=None, method=None,
                            confidence="low",
                            detail="ESI/_fragment enabled — verify _fragment route is not publicly accessible",
                            requires_manual_review=True,
                        )

        return "completed", None


run = make_run_fn(SymfonyRunner)
