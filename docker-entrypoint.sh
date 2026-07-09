#!/usr/bin/env bash
# Entrypoint del container di analisi.
# Tutte le variabili sono iniettate da start.py via -e.
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-unknown}"
SERVICE_ROOT="${SERVICE_ROOT:-/service}"
REPORT_DIR="${REPORT_DIR:-/reports/${SERVICE_NAME}}"
SINGLE_MODULE="${SINGLE_MODULE:-}"
VERBOSE="${VERBOSE:-}"
DEBUG="${DEBUG:-}"

log() { echo "[entrypoint] $*"; }

log "Service: ${SERVICE_NAME}"
log "Source:  ${SERVICE_ROOT}"
log "Reports: ${REPORT_DIR}"

mkdir -p "${REPORT_DIR}"

# Build Python invocation
ARGS=(
    python3 -m orchestrator.run_pipeline
    --service-root "${SERVICE_ROOT}"
    --service-name "${SERVICE_NAME}"
    --report-dir "${REPORT_DIR}"
)
[ -n "${SINGLE_MODULE}" ] && ARGS+=(--module "${SINGLE_MODULE}")
[ -n "${VERBOSE}" ]       && ARGS+=(--verbose)
[ -n "${DEBUG}" ]         && ARGS+=(--debug)

log "Running: ${ARGS[*]}"
exec "${ARGS[@]}"
