"""
modules/reporting/markdown_report.py

Aggrega tutti i report JSON di un servizio in reports/<service>/report.md.
Segue l'ordine delle fasi della pipeline (non l'ordine di scrittura dei file).
Regole:
  - Moduli skippati per stack → non compaiono nel report (no rumore tipo "PHP: N/A")
  - Sezione "Path improbabili" per findings con unlikely_path=True
  - Sezione "Findings non verificabili automaticamente" raggruppata per priorità → tipo
  - La tabella stack iniziale è generata dai booleani di detected_stack.json
"""

import json
import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# /assets/.logo/ascii_art.txt è il path fisso nel container (copiato dal Dockerfile).
# Il fallback risale da __file__ per supportare esecuzioni fuori container (dev locale).
def _load_logo() -> str:
    candidates = [Path("/assets/.logo/ascii_art.txt")]
    here = Path(__file__).resolve().parent
    for p in [here, here.parent, here.parent.parent]:
        candidates.append(p / "assets" / ".logo" / "ascii_art.txt")
    for path in candidates:
        if path.exists():
            return path.read_text().rstrip()
    return ""

_LOGO = _load_logo()

# mapping è escluso dal loop: viene renderizzato direttamente da endpoints_map.json
_SECTION_ORDER = [
    ("stack_detector",   None),
    ("semgrep",          "Discovery — Static Analysis"),
    ("ripgrep",          "Discovery — Pattern Matching"),
    ("jsluice",          "Discovery — JS Extraction"),
    ("trufflehog",       "Discovery — Secret Scanning (trufflehog)"),
    ("gitleaks",         "Discovery — Secret Scanning (gitleaks)"),
    ("nuclei",           "Discovery — Dynamic (nuclei)"),
    ("sqlmap",           "Injection — SQL (sqlmap)"),
    ("ghauri",           "Injection — SQL (ghauri)"),
    ("sstimap",          "Injection — SSTI"),
    ("commix",           "Injection — Command Injection"),
    ("nosqli",           "Injection — NoSQL"),
    ("jwt_tool",         "Auth — JWT"),
    ("phpggc",           "Lang-specific — PHP Deserialization"),
    ("symfony",          "Lang-specific — Symfony/Twig"),
    ("fickling",         "Lang-specific — Python Deserialization"),
    ("nodejsscan",       "Lang-specific — Node.js"),
    ("grpcurl",          "gRPC"),
    ("slipit",           "Upload — Extension Bypass"),
    ("exiftool",         "Upload — EXIF Injection"),
    ("polyglot",         "Upload — Polyglot Files"),
    ("xxeexploiter",     "XXE"),
    ("ssrf_generic",     "Payload Library — SSRF"),
    ("graphql_generic",  "Payload Library — GraphQL"),
    ("xpath_generic",    "Payload Library — XPath"),
    ("directory_traversal", "Payload Library — Directory Traversal"),
    ("ldap_generic",     "Payload Library — LDAP"),
]

_STACK_FLAGS = [
    ("has_php",                       "PHP"),
    ("has_symfony_twig",              "Symfony/Twig"),
    ("has_grpc",                      "gRPC"),
    ("has_file_upload",               "File upload"),
    ("has_sql_queries",               "Query SQL"),
    ("has_nosql",                     "NoSQL"),
    ("uses_jwt",                      "JWT"),
    ("has_eval_on_input",             "eval/pickle su input"),
    ("has_outbound_request_on_input", "SSRF"),
    ("has_graphql_endpoint",          "GraphQL"),
    ("has_xpath_parser",              "XPath"),
    ("has_file_path_from_input",      "Path Traversal"),
    ("has_ldap_query",                "LDAP"),
]

_PRIORITY_ORDER = ["HIGH", "MEDIUM", "LOW"]

# Mappa l'ultimo segmento significativo del rule ID a un'etichetta leggibile.
# Il fallback è il valore raw del campo `type`, titolato.
_TYPE_LABELS: dict[str, str] = {
    "sqli":                              "SQL Injection",
    "sql-injection-db-cursor-execute":   "SQL Injection",
    "formatted-sql-query":               "SQL Injection",
    "sqlalchemy-execute-raw-query":      "SQL Injection",
    "tainted-sql-string":                "SQL Injection",
    "nan-injection":                     "NaN Injection",
    "missing-user":                      "Container — Missing USER",
    "debug-enabled":                     "Config — Debug abilitato",
    "avoid_app_run_with_bad_host":       "Config — Host 0.0.0.0",
    "ssti":                              "SSTI",
    "cmdi":                              "Command Injection",
    "xxe":                               "XXE",
    "path-traversal":                    "Path Traversal",
    "ssrf":                              "SSRF",
    "open-redirect":                     "Open Redirect",
    "weak-jwt":                          "JWT debole",
    "hardcoded-secret":                  "Secret hardcoded",
    "send-file":                         "File Exposure (send_file)",
}


def _type_label(raw_type: str) -> str:
    """Ritorna un'etichetta leggibile per il campo `type` di un finding."""
    if not raw_type:
        return "Generico"
    # prova match esatto
    if raw_type in _TYPE_LABELS:
        return _TYPE_LABELS[raw_type]
    # prova sull'ultimo segmento del rule ID (es. "...sql-injection-db-cursor-execute")
    last = raw_type.rsplit(".", 1)[-1]
    if last in _TYPE_LABELS:
        return _TYPE_LABELS[last]
    # fallback: titola e deunderscorea
    return last.replace("-", " ").replace("_", " ").title()


def generate(service_name: str, report_dir: str) -> Path:
    report_dir = Path(report_dir)
    out = report_dir / "report.md"

    stack = _load_json(report_dir / "detected_stack.json") or {}
    endpoints = _load_json(report_dir / "endpoints_map.json") or []

    lines: list[str] = []

    # ── Header ──────────────────────────────────────────────────────────────
    lang = stack.get("language", "unknown")
    fw = stack.get("framework") or "unknown"
    if _LOGO:
        lines += [f"```\n{_LOGO}\n```", ""]
    lines += [
        f"# {service_name}",
        "",
        f"**Language:** {lang}  **Framework:** {fw}  "
        f"**Path:** {report_dir}  **Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        "",
    ]

    # ── Stack summary table ──────────────────────────────────────────────────
    lines += ["| Caratteristica | Rilevato |", "|---|---|"]
    for flag, label in _STACK_FLAGS:
        val = stack.get(flag, False)
        lines.append(f"| {label} | {'**Sì**' if val else 'No'} |")
    lines.append("")

    # ── Mapping (da endpoints_map.json, non dal modulo mapping.json) ─────────
    if endpoints:
        lines += ["## Mapping", ""]
        lines += ["| Path | Metodo | File:Riga | Auth |", "|---|---|---|---|"]
        for ep in endpoints:
            auth_str = ep["auth"]["type"] if ep.get("auth") else "—"
            lines.append(
                f"| `{ep['path']}` | {ep['method']} | `{ep['file']}:{ep['line']}` | {auth_str} |"
            )
        lines.append("")

    # ── Per-module sections (ordered) ────────────────────────────────────────
    all_manual: list[dict] = []
    all_unlikely: list[dict] = []

    for module_name, section_title in _SECTION_ORDER:
        if section_title is None:
            continue
        report = _load_json(report_dir / f"{module_name}.json")
        if report is None:
            continue
        status = report.get("status", "unknown")
        if status == "skipped":
            continue

        findings = report.get("findings", [])
        main_findings = [f for f in findings if not f.get("unlikely_path") and not f.get("requires_manual_review")]
        unlikely     = [f for f in findings if f.get("unlikely_path")]
        manual       = [f for f in findings if f.get("requires_manual_review") and not f.get("unlikely_path")]
        all_unlikely.extend(unlikely)
        all_manual.extend(manual)

        lines += [f"## {section_title}", ""]
        if status == "error":
            lines += [f"> **Errore:** {report.get('skip_reason', 'unknown error')}", ""]
            continue

        _render_findings_grouped(main_findings + manual, lines, show_source=False)

    # ── Unlikely paths ───────────────────────────────────────────────────────
    if all_unlikely:
        lines += ["## Path improbabili", ""]
        lines += ["> Riferimenti JS/TS che non corrispondono ad alcun endpoint nel mapping.", ""]
        _render_findings_grouped(all_unlikely, lines, show_source=False)

    # ── Manual review — riepilogo cross-modulo per priorità → tipo ───────────
    if all_manual:
        lines += ["## Findings non verificabili automaticamente", ""]
        lines += ["> Riepilogo cross-modulo — gli stessi findings sono visibili nelle rispettive sezioni sopra.", ""]
        _render_findings_grouped(all_manual, lines, show_source=True)

    content = "\n".join(lines)
    out.write_text(content)
    logger.info("markdown_report → %s (%d chars)", out, len(content))
    return out


def _render_findings_grouped(findings: list[dict], lines: list[str], *, show_source: bool) -> None:
    """Renderizza findings raggruppati per priorità → tipo.

    Usato sia nelle sezioni per-modulo (show_source=False, il modulo è ovvio dal titolo)
    sia nel riepilogo cross-modulo finale (show_source=True).
    """
    if not findings:
        lines += ["Nessun finding.", ""]
        return

    groups: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for f in findings:
        priority = f.get("confidence", "unknown").upper()
        groups[priority][_type_label(f.get("type", ""))].append(f)

    ordered = [p for p in _PRIORITY_ORDER if p in groups]
    ordered += [p for p in groups if p not in _PRIORITY_ORDER]

    for priority in ordered:
        lines += [f"### {priority}", ""]
        for label in sorted(groups[priority]):
            lines += [f"#### {label}", ""]
            for f in groups[priority][label]:
                lines.append(_format_finding(f, show_source=show_source))
            lines.append("")


def _format_finding(f: dict, *, show_source: bool) -> str:
    """Riga singola di finding: file:riga, endpoint opzionale, source opzionale, detail."""
    loc    = f"`{f['file']}:{f['line']}`" if f.get("file") else "?"
    method = f" {f['method']}" if f.get("method") else ""
    ep     = f" — `{f['endpoint']}{method}`" if f.get("endpoint") else ""
    source = f" *(via {f['source_module']})*" if show_source and f.get("source_module") else ""
    detail = f.get("detail", "")
    header = f"- {loc}{ep}{source}"
    return header + f"\n  > {detail}" if detail else header


def _load_json(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None
