"""
orchestrator/core.py

Loop principale della pipeline. Riceve il path del servizio, i settings,
e coordina l'esecuzione dei moduli seguendo trigger_rules.TRIGGERS.

Flusso:
  1. Esegui mapping (endpoint_parser) + stack_detector — sempre, in sequenza,
     perché tutti gli altri moduli dipendono dai loro output.
  2. Carica detected_stack.json + endpoints_map.json.
  3. Determina modules_to_run() tramite trigger_rules.
  4. Carica dinamicamente i runner corrispondenti e li acccoda su JobQueue.
  5. Blocca su join(), poi genera il report Markdown finale.
  6. Logga esplicitamente i moduli skippati (audit trail).

Design:
  - I runner sono importati dinamicamente da modules.<area>.<nome>_runner
    tramite il registry MODULE_REGISTRY (dichiarativo, non auto-discovery).
  - Il core non sa nulla del contenuto dei runner: li chiama tutti con la
    stessa firma run(service_root, service_name, report_dir, settings) -> dict.
  - L'oggetto settings è passato a ogni runner (rate limit, timeout, paths).
"""

import importlib
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

from orchestrator.trigger_rules import ALWAYS_RUN, UNGATED_DISCOVERY, modules_to_run, skipped_modules
from orchestrator.job_queue import JobQueue, DEFAULT_MUTEX_GROUPS

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module registry
# Mappa nome-modulo → dotted import path del runner.
# I moduli in ALWAYS_RUN/UNGATED_DISCOVERY vengono avviati esplicitamente;
# quelli in TRIGGERS sono avviati se modules_to_run() li include.
# ---------------------------------------------------------------------------

MODULE_REGISTRY: dict[str, str] = {
    # --- core (sempre, sequenziali al bootstrap) ---
    "mapping":        "modules.mapping.endpoint_parser",
    "stack_detector": "orchestrator.stack_detector",

    # --- always run ---
    "semgrep":  "modules.discovery.semgrep_runner",
    "ripgrep":  "modules.discovery.ripgrep_runner",

    # --- ungated discovery ---
    "jsluice":      "modules.discovery.jsluice_runner",
    "nuclei":       "modules.discovery.nuclei_runner",
    "xxeexploiter": "modules.xxe.xxeexploiter_runner",

    # --- gated: injection ---
    "sqlmap":   "modules.injection.sqlmap_runner",
    "ghauri":   "modules.injection.ghauri_runner",
    "sstimap":  "modules.injection.sstimap_runner",
    "commix":   "modules.injection.commix_runner",
    "nosqli":   "modules.injection.nosqli_runner",

    # --- gated: auth ---
    "jwt_tool": "modules.auth.jwt_tool_runner",

    # --- gated: discovery ---
    "trufflehog": "modules.discovery.trufflehog_runner",
    "gitleaks":   "modules.discovery.gitleaks_runner",

    # --- gated: lang-specific ---
    "phpggc":     "modules.lang_specific.phpggc_runner",
    "symfony":    "modules.lang_specific.symfony_runner",
    "fickling":   "modules.lang_specific.fickling_runner",
    "nodejsscan": "modules.lang_specific.nodejsscan_runner",

    # --- gated: grpc ---
    "grpcurl": "modules.grpc.grpcurl_runner",

    # --- gated: upload ---
    "slipit":   "modules.upload.slipit_runner",
    "exiftool": "modules.upload.exiftool_runner",
    "polyglot": "modules.upload.polyglot_runner",

    # --- gated: generic category (payload library) ---
    "ssrf_generic":        "modules.injection.generic_category_runner",
    "graphql_generic":     "modules.injection.generic_category_runner",
    "xpath_generic":       "modules.injection.generic_category_runner",
    "directory_traversal": "modules.injection.generic_category_runner",
    "ldap_generic":        "modules.injection.generic_category_runner",
}

# generic_category_runner gestisce più categorie: gli passiamo la categoria via kwargs.
GENERIC_CATEGORY_KWARGS: dict[str, dict] = {
    "ssrf_generic":        {"category": "ssrf"},
    "graphql_generic":     {"category": "graphql"},
    "xpath_generic":       {"category": "xpath"},
    "directory_traversal": {"category": "directory_traversal"},
    "ldap_generic":        {"category": "ldap"},
}


# ---------------------------------------------------------------------------
# Loader dinamico
# ---------------------------------------------------------------------------

def _load_runner(module_name: str):
    """Importa dinamicamente il modulo runner e restituisce la sua funzione run()."""
    dotted = MODULE_REGISTRY.get(module_name)
    if not dotted:
        raise ImportError(f"No registry entry for module '{module_name}'")
    mod = importlib.import_module(dotted)
    if not hasattr(mod, "run"):
        raise AttributeError(f"Module {dotted} has no run() function")
    return mod.run


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class Orchestrator:
    def __init__(
        self,
        service_root: str,
        service_name: str,
        report_dir: str,
        settings: dict,
        single_module: str | None = None,
        verbose: bool = False,
    ):
        self.service_root = str(Path(service_root).resolve())
        self.service_name = service_name
        self.report_dir = str(Path(report_dir).resolve())
        self.settings = settings
        self.single_module = single_module
        self.verbose = verbose
        Path(self.report_dir).mkdir(parents=True, exist_ok=True)

    # -----------------------------------------------------------------------

    def run(self) -> dict[str, Any]:
        """Entry point. Ritorna dict {modulo: report_dict | Exception | 'skipped'}."""
        t0 = time.monotonic()

        # Phase 1 — bootstrap (sequenziale, non entra in JobQueue)
        logger.info("=== Phase 1: bootstrap (mapping + stack_detector) ===")
        self._run_bootstrap()

        # Load contracts
        stack = self._load_json("detected_stack.json")
        endpoints = self._load_json("endpoints_map.json")

        if self.single_module:
            return self._run_single(self.single_module, stack, endpoints)

        # Phase 2 — run all triggered modules in parallel
        logger.info("=== Phase 2: parallel pipeline ===")
        to_run   = [m for m in modules_to_run(stack) if m not in ("mapping", "stack_detector")]
        skipped  = skipped_modules(stack)

        self._log_skip_plan(to_run, skipped)

        queue = JobQueue(self.settings, mutex_groups=DEFAULT_MUTEX_GROUPS)
        for module_name in to_run:
            self._enqueue(queue, module_name, stack, endpoints)
        queue.join()

        # Phase 3 — markdown report
        logger.info("=== Phase 3: markdown report ===")
        self._generate_markdown_report()

        results = queue.results
        results.update({name: "skipped" for name in skipped})
        elapsed = time.monotonic() - t0
        logger.info("=== Pipeline complete in %.1fs ===", elapsed)
        return results

    # -----------------------------------------------------------------------
    # Bootstrap: mapping (endpoint_parser) then stack_detector, in sequence
    # -----------------------------------------------------------------------

    def _run_bootstrap(self):
        for mod_name in ("mapping", "stack_detector"):
            try:
                fn = _load_runner(mod_name)
                fn(self.service_root, self.service_name, self.report_dir, self.settings)
            except Exception as exc:
                logger.exception("Bootstrap module '%s' failed", mod_name)
                self._write_stub_report(mod_name, "error", str(exc))

    # -----------------------------------------------------------------------
    # Single-module mode
    # -----------------------------------------------------------------------

    def _run_single(self, module_name: str, stack: dict, endpoints: list) -> dict[str, Any]:
        logger.info("=== Single module mode: %s ===", module_name)
        try:
            fn = _load_runner(module_name)
        except (ImportError, AttributeError) as exc:
            logger.error("Cannot load runner for '%s': %s", module_name, exc)
            self._write_stub_report(module_name, "error", str(exc))
            return {module_name: exc}

        extra = GENERIC_CATEGORY_KWARGS.get(module_name, {})
        try:
            result = fn(
                self.service_root, self.service_name, self.report_dir,
                self.settings,
                stack=stack, endpoints=endpoints, **extra,
            )
        except Exception as exc:
            logger.exception("Module %s raised", module_name)
            result = exc

        self._generate_markdown_report()
        return {module_name: result}

    # -----------------------------------------------------------------------
    # Enqueue helpers
    # -----------------------------------------------------------------------

    def _enqueue(self, queue: JobQueue, module_name: str, stack: dict, endpoints: list):
        try:
            fn = _load_runner(module_name)
        except (ImportError, AttributeError) as exc:
            logger.warning("Skipping '%s' (runner not found): %s", module_name, exc)
            self._write_stub_report(module_name, "error", f"runner not found: {exc}")
            return

        extra = GENERIC_CATEGORY_KWARGS.get(module_name, {})

        def _job():
            return fn(
                self.service_root, self.service_name, self.report_dir,
                self.settings,
                stack=stack, endpoints=endpoints, **extra,
            )

        queue.submit(module_name, _job)

    # -----------------------------------------------------------------------
    # Utilities
    # -----------------------------------------------------------------------

    def _load_json(self, filename: str) -> Any:
        p = Path(self.report_dir) / filename
        if not p.exists():
            logger.warning("%s not found — returning empty structure", filename)
            return [] if "map" in filename else {}
        return json.loads(p.read_text())

    def _write_stub_report(self, module_name: str, status: str, reason: str):
        import datetime
        report = {
            "module": module_name,
            "service": self.service_name,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "status": status,
            "skip_reason": reason,
            "findings": [],
        }
        p = Path(self.report_dir) / f"{module_name}.json"
        p.write_text(json.dumps(report, indent=2))

    def _log_skip_plan(self, to_run: list[str], skipped: dict[str, str]):
        logger.info("Modules to run  (%d): %s", len(to_run), ", ".join(to_run))
        if skipped:
            logger.info("Modules skipped (%d):", len(skipped))
            for name, reason in skipped.items():
                logger.info("  %-25s %s", name, reason)

    def _generate_markdown_report(self):
        try:
            from modules.reporting.markdown_report import generate
            generate(self.service_name, self.report_dir)
        except ImportError:
            logger.warning("markdown_report not yet available, skipping")
        except Exception as exc:
            logger.warning("markdown_report generation failed: %s", exc)


# ---------------------------------------------------------------------------
# Module init (importable as package)
# ---------------------------------------------------------------------------

def run_pipeline(
    service_root: str,
    service_name: str,
    report_dir: str,
    settings: dict,
    single_module: str | None = None,
    verbose: bool = False,
) -> dict[str, Any]:
    """Public API called by start.py."""
    orch = Orchestrator(
        service_root=service_root,
        service_name=service_name,
        report_dir=report_dir,
        settings=settings,
        single_module=single_module,
        verbose=verbose,
    )
    return orch.run()
