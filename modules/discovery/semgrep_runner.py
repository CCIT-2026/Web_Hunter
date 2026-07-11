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

# Pure infrastructure/container findings — not directly exploitable web vulns in CTF.
# Downgraded to low so they don't pollute the HIGH section of quick_report.
_INFRA_PATTERN = re.compile(
    r"dockerfile|docker.compose|missing.user|container\.security|missing-user", re.I
)


def _line_from_offset(path: "Path", offset: int) -> int | None:
    """Ricava il numero di riga (1-based) da un byte offset nel file.

    start.offset di semgrep è un conteggio di byte dall'inizio del file: è
    deterministico e non dipende da righe vuote né da login al cloud. Basta
    contare i newline prima dell'offset per avere la riga esatta.
    """
    try:
        text = path.read_text(errors="replace")
    except Exception as e:
        logger.warning("_line_from_offset: impossibile leggere %s: %s", path, e)
        return None
    if offset > len(text):
        logger.warning("_line_from_offset: offset %d fuori dal file %s (%d chars)", offset, path.name, len(text))
        return None
    return text[:offset].count("\n") + 1

# Maps a keyword extracted from the semgrep check_id to a canonical vuln type.
_RULE_TO_TYPE = re.compile(
    r"(sql|nosql|xss|ssti|xxe|ssrf|traversal|ldap|command|inject|jwt|secret|hardcoded|eval|pickle|"
    r"prototype|redirect|deseri|rce|misconfig|debug)",
    re.I,
)

_KEYWORD_TO_TYPE: dict[str, str] = {
    "sql":        "sqli",
    "nosql":      "nosql",
    "xss":        "xss",
    "ssti":       "ssti",
    "xxe":        "xxe",
    "ssrf":       "ssrf",
    "traversal":  "path_traversal",
    "ldap":       "ldap",
    "command":    "cmdi",
    "inject":     "cmdi",
    "jwt":        "jwt",
    "secret":     "secret",
    "hardcoded":  "secret",
    "eval":       "cmdi",
    "pickle":     "cmdi",
    "prototype":  "other",
    "redirect":   "open_redirect",
    "deseri":     "other",
    "rce":        "cmdi",
    "misconfig":  "misconfig",
    "debug":      "misconfig",
}


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

        raw_out = self.report_dir / "json_reports" / "semgrep_raw.json"
        raw_out.write_text(json.dumps(data.get("results", [])[:5], indent=2))

        for result in data.get("results", []):
            check_id = result.get("check_id", "")
            severity = _CONF_MAP.get(result.get("extra", {}).get("severity", "").lower(), "low")
            rel_path = result.get("path", "")
            start   = result.get("start", {})
            extra   = result.get("extra", {})
            offset = start.get("offset")
            line_no = _line_from_offset(self.service_root / rel_path, offset) if offset is not None else start.get("line")
            message = extra.get("message", check_id)

            # Derive canonical type from check_id keywords; fallback to "other"
            m = _RULE_TO_TYPE.search(check_id)
            type_ = _KEYWORD_TO_TYPE.get(m.group(1).lower(), "other") if m else "other"

            # Downgrade pure infra/container findings — not directly web-exploitable in CTF
            if _INFRA_PATTERN.search(check_id) or _INFRA_PATTERN.search(rel_path):
                severity = "low"

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
