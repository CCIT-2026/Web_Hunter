"""
modules/reporting/stats_tracker.py

Legge tutti i report JSON dei moduli in json_reports/ e produce stats.json
con il conteggio dei findings HIGH per tipo canonico.

Chiamato da orchestrator/core.py dopo la pipeline, prima di quick_report.
"""

import json
import logging
from collections import defaultdict
from pathlib import Path

logger = logging.getLogger(__name__)

# File di contratto — non sono report di moduli
_CONTRACT_FILES = {
    "detected_stack.json",
    "endpoints_map.json",
    "auth_state.json",
    "stack_detector.json",
    "mapping.json",
    "session_probe.json",
    "semgrep_raw.json",  # raw list output, not a module-report dict
}

# Normalizzazione raw type → chiave canonica
_CANONICAL: dict[str, str] = {
    "sqli":                            "sqli",
    "sql-injection":                   "sqli",
    "sql-injection-db-cursor-execute": "sqli",
    "formatted-sql-query":             "sqli",
    "sqlalchemy-execute-raw-query":    "sqli",
    "tainted-sql-string":              "sqli",
    "nan-injection":                   "sqli",
    "ssti":                            "ssti",
    "cmdi":                            "cmdi",
    "xxe":                             "xxe",
    "path-traversal":                  "path_traversal",
    "path_traversal":                  "path_traversal",
    "ssrf":                            "ssrf",
    "open-redirect":                   "open_redirect",
    "weak-jwt":                        "jwt",
    "hardcoded-secret":                "secret",
    "missing-user":                    "misconfig",
    "debug-enabled":                   "misconfig",
    "avoid_app_run_with_bad_host":     "misconfig",
    "send-file":                       "file_exposure",
}


def _canonical(raw_type: str) -> str:
    if not raw_type:
        return "other"
    key = raw_type.lower()
    if key in _CANONICAL:
        return _CANONICAL[key]
    last = key.rsplit(".", 1)[-1]
    return _CANONICAL.get(last, last)


def _is_env_secret(f: dict) -> bool:
    """
    True se il finding è un secret trovato in un file .env.
    I secret in .env sono configurazione attesa (ogni team ha le sue credenziali),
    non una vulnerabilità primaria da evidenziare nel quick report.
    """
    if _canonical(f.get("type", "")) != "secret":
        return False
    file_path = f.get("file", "") or ""
    name = Path(file_path).name
    return name == ".env" or name.endswith(".env")


def generate(report_dir: str) -> dict[str, int]:
    """
    Aggrega findings HIGH da tutti i moduli, esclude unlikely_path e secret in .env.
    Scrive stats.json nella report_dir. Ritorna il dict ordinato per count desc.
    """
    report_dir = Path(report_dir)
    json_dir = report_dir / "json_reports"
    counts: dict[str, int] = defaultdict(int)

    for jf in sorted(json_dir.glob("*.json")):
        if jf.name in _CONTRACT_FILES:
            continue
        try:
            data = json.loads(jf.read_text())
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        if data.get("status") in ("skipped", "error"):
            continue
        for f in data.get("findings", []):
            if f.get("confidence", "").upper() != "HIGH":
                continue
            if f.get("unlikely_path"):
                continue
            if _is_env_secret(f):
                continue
            counts[_canonical(f.get("type", ""))] += 1

    ordered = dict(sorted(counts.items(), key=lambda x: (-x[1], x[0])))
    (report_dir / "json_reports" / "stats.json").write_text(json.dumps(ordered, indent=2))
    logger.info("stats.json scritto (%d tipi)", len(ordered))
    return ordered
