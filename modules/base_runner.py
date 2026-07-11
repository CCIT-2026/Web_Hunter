"""
modules/base_runner.py

Base class condivisa dai runner. Evita di ripetere: subprocess wrapper,
report writing, endpoint loading, timeout handling, tool-not-found graceful exit.
"""

import datetime
import json
import logging
import subprocess
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class BaseRunner:
    MODULE_NAME: str = "base"

    def __init__(
        self,
        service_root: str,
        service_name: str,
        report_dir: str,
        settings: dict,
        stack: dict | None = None,
        endpoints: list | None = None,
    ):
        self.service_root = Path(service_root).resolve()
        self.service_name = service_name
        self.report_dir = Path(report_dir)
        self.settings = settings
        self.stack = stack or self._load_json("detected_stack.json") or {}
        self.endpoints = endpoints or self._load_json("endpoints_map.json") or []
        self.timeout = int(settings.get("timeout_seconds", 15))
        self._findings: list[dict] = []
        self.report_dir.mkdir(parents=True, exist_ok=True)

    # -----------------------------------------------------------------------
    # Subclasses implement this
    # -----------------------------------------------------------------------

    def execute(self) -> tuple[str, str | None]:
        """Return (status, skip_reason). Populate self._findings on success."""
        raise NotImplementedError

    # -----------------------------------------------------------------------
    # Public run() — called by orchestrator
    # -----------------------------------------------------------------------

    def run(self) -> dict:
        t0 = time.monotonic()
        try:
            status, skip_reason = self.execute()
        except Exception as exc:
            logger.exception("%s: unexpected error", self.MODULE_NAME)
            status, skip_reason = "error", str(exc)

        report = {
            "module": self.MODULE_NAME,
            "service": self.service_name,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": status,
            "skip_reason": skip_reason,
            "findings": self._findings if status == "completed" else [],
        }
        json_dir = self.report_dir / "json_reports"
        json_dir.mkdir(parents=True, exist_ok=True)
        (json_dir / f"{self.MODULE_NAME}.json").write_text(json.dumps(report, indent=2))
        logger.info("%s: %s in %.1fs (%d findings)", self.MODULE_NAME, status, time.monotonic() - t0, len(self._findings))
        return report

    # -----------------------------------------------------------------------
    # Subprocess helpers
    # -----------------------------------------------------------------------

    def sh(self, cmd: list[str], cwd: str | None = None, timeout: int | None = None) -> tuple[int, str, str]:
        """Run a command. Returns (returncode, stdout, stderr). Never raises on nonzero."""
        try:
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=cwd or str(self.service_root),
                timeout=timeout or self.timeout,
            )
            return r.returncode, r.stdout, r.stderr
        except FileNotFoundError:
            return -1, "", f"tool not found: {cmd[0]}"
        except subprocess.TimeoutExpired:
            return -2, "", f"timeout after {timeout or self.timeout}s"

    def tool_available(self, name: str) -> bool:
        rc, _, _ = self.sh(["which", name], cwd="/")
        return rc == 0

    # -----------------------------------------------------------------------
    # Finding helpers
    # -----------------------------------------------------------------------

    def add_finding(self, type_: str, file_: str | None, line: int | None,
                    endpoint: str | None, method: str | None, confidence: str,
                    detail: str, **extra):
        f = {
            "type": type_,
            "file": file_,
            "line": line,
            "endpoint": endpoint,
            "method": method,
            "confidence": confidence,
            "detail": detail,
            "source_module": self.MODULE_NAME,
            "requires_manual_review": extra.pop("requires_manual_review", False),
            "unlikely_path": extra.pop("unlikely_path", False),
        }
        f.update(extra)
        self._findings.append(f)

    # -----------------------------------------------------------------------
    # Data helpers
    # -----------------------------------------------------------------------

    def _load_json(self, filename: str) -> Any:
        p = self.report_dir / "json_reports" / filename
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text())
        except Exception:
            return None

    def endpoint_paths(self) -> list[str]:
        return list({ep["path"] for ep in self.endpoints})

    def endpoints_for_path(self, path: str) -> list[dict]:
        return [ep for ep in self.endpoints if ep["path"] == path]


# ---------------------------------------------------------------------------
# Module-level run() shim — lets orchestrator call module.run(...) directly
# without needing to instantiate the class.
# Usage in each runner: from modules.base_runner import make_run_fn
# ---------------------------------------------------------------------------

def make_run_fn(cls):
    """Ritorna la funzione run() che l'orchestratore si aspetta."""
    def run(service_root, service_name, report_dir, settings,
            stack=None, endpoints=None, **kwargs):
        instance = cls(service_root, service_name, report_dir, settings,
                       stack=stack, endpoints=endpoints, **kwargs)
        return instance.run()
    return run
