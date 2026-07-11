"""
orchestrator/run_pipeline.py — __main__ entry point per il container.

Invocato dall'entrypoint come:
    python3 -m orchestrator.run_pipeline --service-root ... --service-name ...

Legge RECON_SETTINGS da env se presente (JSON serializzato da start.py),
altrimenti carica settings.json dalla root dell'app.
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

# In container: /app è la working dir e contiene il package
sys.path.insert(0, str(Path(__file__).parent.parent))

from orchestrator.core import run_pipeline
from orchestrator import colors as _col


def _setup_logging(verbose: bool, debug: bool):
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    logging.basicConfig(
        level=level,
        format=f"{_col.DIM}%(asctime)s{_col.R}  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )


def main():
    parser = argparse.ArgumentParser(description="CTF Recon Suite — pipeline runner")
    parser.add_argument("--service-root", required=True)
    parser.add_argument("--service-name", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--module", default=None)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    _setup_logging(args.verbose, args.debug)

    # Settings: env var from start.py OR settings.json on disk
    settings_json = os.environ.get("RECON_SETTINGS", "")
    if settings_json:
        settings = json.loads(settings_json)
    else:
        cfg_path = Path(__file__).parent.parent / "settings.json"
        settings = json.loads(cfg_path.read_text()) if cfg_path.exists() else {}

    _col.header(f"Analisi  {args.service_name}")
    _col.step(f"report dir  →  {args.report_dir}")

    results = run_pipeline(
        service_root=args.service_root,
        service_name=args.service_name,
        report_dir=args.report_dir,
        settings=settings,
        single_module=args.module,
        verbose=args.verbose,
    )

    if results.get("_aborted"):
        _col.header("Riepilogo")
        _col.err("Analisi interrotta: autenticazione fallita in modo irrecuperabile.")
        _col.err("Nessun modulo di injection/dynamic è stato eseguito (avrebbe prodotto solo falsi negativi).")
        _col.err("Correggi le credenziali in settings.json → test_user e rilancia.")
        sys.exit(1)

    skipped = [k for k, v in results.items() if v == "skipped"]
    errors   = [k for k, v in results.items() if isinstance(v, Exception)]
    done     = [k for k, v in results.items() if isinstance(v, dict)]

    _col.header("Riepilogo")
    total_findings = sum(
        len(v.get("findings", [])) for v in results.values() if isinstance(v, dict)
    )
    _col.ok(f"Completati: {len(done)}   Saltati: {len(skipped)}   Errori: {len(errors)}")
    _col.ok(f"Finding totali: {total_findings}")
    if errors:
        _col.warn(f"Moduli in errore: {', '.join(errors)}")
    _col.ok(f"Report esteso  →  {args.report_dir}/extended_report.md")
    _col.ok(f"Quick report   →  {args.report_dir}/quick_report.md")
    _col.ok(f"Stats          →  {args.report_dir}/stats.json")


if __name__ == "__main__":
    main()
