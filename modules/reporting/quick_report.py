"""
modules/reporting/quick_report.py

Genera quick_report.md: quadro rapido, solo HIGH, niente rumore.

Struttura:
  - Logo ASCII
  - Stack table (stessa del report esteso)
  - Barchart vulnerabilità HIGH con conteggi
  - Per ogni tipo con findings: lista compatta file:riga + endpoint + detail

Esclusi: unlikely_path, confidence != HIGH, secret trovati in file .env
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


def _load_logo() -> str:
    here = Path(__file__).resolve().parent
    candidates = [
        Path("/assets/.logo/ascii_art.txt"),                          # container
        here.parent.parent / "assets" / ".logo" / "ascii_art.txt",   # /app/modules/../
        here.parent.parent.parent / "assets" / ".logo" / "ascii_art.txt",  # un livello sopra
    ]
    for path in candidates:
        if path.exists():
            return path.read_text().rstrip()
    return ""


_LOGO = _load_logo()

# (flag_key, display_label, locations_key_in_detected_stack)
_STACK_FLAGS = [
    ("has_php",                       "PHP",                  None),
    ("has_symfony_twig",              "Symfony/Twig",         None),
    ("has_grpc",                      "gRPC",                 None),
    ("has_file_upload",               "File upload",          "file_upload_locations"),
    ("has_sql_queries",               "Query SQL",            "sql_query_locations"),
    ("has_nosql",                     "NoSQL",                "nosql_locations"),
    ("uses_jwt",                      "JWT",                  "jwt_verification_locations"),
    ("has_eval_on_input",             "eval/pickle su input", "eval_locations"),
    ("has_outbound_request_on_input", "SSRF",                 "ssrf_locations"),
    ("has_graphql_endpoint",          "GraphQL",              "graphql_locations"),
    ("has_xpath_parser",              "XPath",                "xpath_locations"),
    ("has_file_path_from_input",      "Path Traversal",       "path_traversal_locations"),
    ("has_ldap_query",                "LDAP",                 "ldap_locations"),
]

_LABEL: dict[str, str] = {
    "sqli":           "SQL Injection",
    "ssti":           "SSTI",
    "cmdi":           "Command Injection",
    "xxe":            "XXE",
    "path_traversal": "Path Traversal",
    "ssrf":           "SSRF",
    "open_redirect":  "Open Redirect",
    "jwt":            "JWT debole",
    "secret":         "Secret hardcoded",
    "misconfig":      "Misconfiguration",
    "file_exposure":  "File Exposure",
    "other":          "Altro",
}

_CONTRACT_FILES = {
    "detected_stack.json", "endpoints_map.json", "auth_state.json",
    "stack_detector.json", "mapping.json", "session_probe.json",
    "semgrep_raw.json",  # raw list output, not a module-report dict
}

_BAR_CHAR = "█"
_BAR_MAX  = 24


def generate(service_name: str, report_dir: str) -> Path:
    report_dir = Path(report_dir)
    json_dir   = report_dir / "json_reports"
    out        = report_dir / "quick_report.md"

    stack            = _load_json(json_dir / "detected_stack.json") or {}
    findings_by_type = _collect_high_findings(json_dir)
    # Derive counts from the same source as the detail section — always in sync.
    high_stats = {k: len(v) for k, v in findings_by_type.items() if v}

    lines: list[str] = []

    # ── Logo ────────────────────────────────────────────────────────────────
    if _LOGO:
        lines += [f"```\n{_LOGO}\n```", ""]

    # ── Header ──────────────────────────────────────────────────────────────
    lang = stack.get("language", "unknown")
    fw   = stack.get("framework") or "unknown"
    lines += [
        f"# {service_name} — Quick Report",
        "",
        f"**Language:** {lang}  **Framework:** {fw}  "
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
    ]

    # ── Stack table ──────────────────────────────────────────────────────────
    lines += ["## Stack", ""]
    lines += ["| Caratteristica | | Evidenza (file:riga) |", "|---|---|---|"]
    for flag, label, locs_key in _STACK_FLAGS:
        val = stack.get(flag, False)
        if not val:
            lines.append(f"| {label} | ❌ | |")
            continue
        locs = stack.get(locs_key, [])[:3] if locs_key else []
        if locs:
            parts = []
            for loc in locs:
                ref = f"`{loc['file']}:{loc['line']}`"
                if loc.get("looks_weak") and loc.get("weak_reason"):
                    ref += f" *(weak: {loc['weak_reason']})*"
                parts.append(ref)
            lines.append(f"| {label} | ✅ | {', '.join(parts)} |")
        else:
            lines.append(f"| {label} | ✅ | |")
    lines.append("")

    # ── Barchart HIGH findings ────────────────────────────────────────────────
    if not high_stats:
        lines += ["## Vulnerabilità HIGH", "", "> Nessun finding HIGH rilevato.", ""]
    else:
        lines += ["## Vulnerabilità HIGH", ""]
        max_count = max(high_stats.values())
        lines += ["| Tipo | N | Incidenza |", "|---|---|---|"]
        for vtype, count in high_stats.items():
            label   = _LABEL.get(vtype, vtype.replace("_", " ").title())
            bar_len = round((count / max_count) * _BAR_MAX)
            bar     = _BAR_CHAR * bar_len
            lines.append(f"| **{label}** | {count} | `{bar}` |")
        lines.append("")

    # ── Dettaglio per tipo ───────────────────────────────────────────────────
    if findings_by_type:
        lines += ["## Dettaglio", ""]
        for vtype, flist in findings_by_type.items():
            if not flist:
                continue
            label = _LABEL.get(vtype, vtype.replace("_", " ").title())
            lines += [f"### {label}", ""]
            for f in flist:
                loc     = f"`{f['file']}:{f['line']}`" if f.get("file") else "?"
                method  = f" {f['method']}" if f.get("method") else ""
                ep      = f" — `{f['endpoint']}{method}`" if f.get("endpoint") else ""
                detail  = f.get("detail", "")
                src     = f.get("source_module", "")
                src_tag = f"  {src}" if src else ""
                entry   = f"- {loc}{ep}{src_tag}"
                if detail:
                    entry += f"\n  > {detail}"
                lines.append(entry)
            lines.append("")

    content = "\n".join(lines)
    out.write_text(content)
    logger.info("quick_report.md → %s (%d chars)", out, len(content))
    return out


def _collect_high_findings(json_dir: Path) -> dict[str, list[dict]]:
    """
    Raccoglie findings HIGH non-unlikely da tutti i moduli, raggruppa per tipo.
    Esclude secret trovati in file .env (stessa logica di stats_tracker).
    """
    from modules.reporting.stats_tracker import _canonical, _is_env_secret

    result: dict[str, list[dict]] = {}

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
        module_name = data.get("module", jf.stem)
        for f in data.get("findings", []):
            if f.get("confidence", "").upper() != "HIGH":
                continue
            if f.get("unlikely_path"):
                continue
            if _is_env_secret(f):
                continue
            key   = _canonical(f.get("type", ""))
            entry = {**f, "source_module": module_name}
            result.setdefault(key, []).append(entry)

    return dict(sorted(result.items(), key=lambda x: (-len(x[1]), x[0])))


def _load_json(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None
