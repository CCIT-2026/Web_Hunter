"""
modules/discovery/semgrep_runner.py  — sempre attivo (ALWAYS_RUN)

Lancia semgrep --config=auto (o regola custom se wordlists_path contiene
semgrep/*.yml) e importa i risultati nel formato comune.

Output: reports/<service>/semgrep.json
"""

import json
import logging
import re
from pathlib import Path

from modules.base_runner import BaseRunner, make_run_fn

logger = logging.getLogger(__name__)

_CONF_MAP = {"high": "high", "error": "high", "warning": "medium", "info": "low"}


def _true_line(path: "Path", semgrep_line: int | None) -> int | None:
    """Mappa il numero di riga di semgrep alla riga reale nel file.

    Senza login al cloud Semgrep, start.line conta solo le righe non-vuote
    (le righe vuote vengono saltate dal parser interno). Questa funzione
    conta le righe non-vuote nel file reale e restituisce la posizione
    1-based corrispondente nell'intero file (righe vuote incluse).
    """
    if semgrep_line is None:
        return None
    try:
        file_lines = path.read_text(errors="replace").splitlines()
    except Exception as e:
        logger.warning("_true_line: impossibile leggere %s: %s", path, e)
        return semgrep_line

    nonblank = 0
    for i, line in enumerate(file_lines):
        if line.strip():
            nonblank += 1
            if nonblank == semgrep_line:
                true_line = i + 1
                if true_line != semgrep_line:
                    logger.debug("_true_line: %s %d → %d", path.name, semgrep_line, true_line)
                return true_line

    logger.warning("_true_line: %s semgrep_line=%d supera il totale non-blank=%d", path.name, semgrep_line, nonblank)
    return semgrep_line

# Tipi di finding semgrep → tipo interno (best-effort, poi l'analista verifica)
_RULE_TO_TYPE = re.compile(
    r"(sql|nosql|xss|ssti|xxe|ssrf|traversal|ldap|command|injection|jwt|secret|hardcoded|eval|pickle)",
    re.I,
)


class SemgrepRunner(BaseRunner):
    MODULE_NAME = "semgrep"

    def execute(self):
        if not self.tool_available("semgrep"):
            return "error", "semgrep not found in PATH"

        rc, stdout, stderr = self.sh(
            ["semgrep", "--config=auto", "--json", "--timeout", str(self.timeout), str(self.service_root)],
            cwd=str(self.service_root),
            timeout=self.timeout * 4,  # semgrep può essere lento su codebase grandi
        )

        if rc == -1:
            return "error", stderr
        if rc not in (0, 1):  # semgrep returns 1 on findings
            return "error", f"semgrep exited {rc}: {stderr[:300]}"

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return "error", f"cannot parse semgrep JSON: {stdout[:200]}"

        # dump raw per debug — inspect reports/<service>/semgrep_raw.json
        raw_out = self.report_dir / "semgrep_raw.json"
        raw_out.write_text(json.dumps(data.get("results", [])[:5], indent=2))

        for result in data.get("results", []):
            check_id = result.get("check_id", "")
            severity = _CONF_MAP.get(result.get("extra", {}).get("severity", "").lower(), "low")
            rel_path = result.get("path", "")
            start   = result.get("start", {})
            extra   = result.get("extra", {})
            line_no = _true_line(self.service_root / rel_path, start.get("line"))
            message = extra.get("message", check_id)

            # Match check_id against known type keywords
            m = _RULE_TO_TYPE.search(check_id)
            type_ = m.group(1).lower() if m else "semgrep"

            # Find endpoint associated with this file (best-effort)
            ep = next((e for e in self.endpoints if e["file"] == rel_path), None)
            endpoint = ep["path"] if ep else None
            method = ep["method"] if ep else None

            self.add_finding(
                type_=type_,
                file_=rel_path,
                line=line_no,
                endpoint=endpoint,
                method=method,
                confidence=severity,
                detail=f"[{check_id}] {message}",
                requires_manual_review=True,
            )

        return "completed", None


run = make_run_fn(SemgrepRunner)
