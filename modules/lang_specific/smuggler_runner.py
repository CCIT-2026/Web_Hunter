"""
modules/lang_specific/smuggler_runner.py — gated: has_proxy_configs

Esegue Smuggler (Request Smuggling / HTTP Desync detection) sull'URL bersaglio.
Utile per rilevare vulnerabilità di disincronizzazione in proxy (es. HAProxy, Nginx)
davanti a web server (es. Gunicorn, Tomcat).
"""

import subprocess
import os
import re
from pathlib import Path
from modules.base_runner import BaseRunner, make_run_fn

class SmugglerRunner(BaseRunner):
    MODULE_NAME = "smuggler"

    def execute(self):
        if not self.tool_available("smuggler"):
            return "skipped", "tool not available: smuggler"

        target_url = self.settings.get("target_url")
        if not target_url:
            return "skipped", "skip: target_url_missing"

        log_file = self.report_dir / "smuggler.log"

        cmd = [
            "smuggler",
            "-u", target_url,
            "-l", str(log_file),
            "-q"
        ]

        try:
            rc, stdout, stderr = self.sh(cmd, timeout=120)
        except Exception as e:
            return "error", str(e)

        if rc == -1:
            return "error", "tool not found: smuggler"
        if rc == -2:
            return "error", "timeout"

        if log_file.exists():
            log_content = log_file.read_text(errors="replace")
            # Cerchiamo VULNERABLE o CRITICAL nel log
            if "CRITICAL" in log_content or "VULNERABLE" in log_content:
                self.add_finding(
                    type_="request_smuggling",
                    file_="proxy",
                    line=0,
                    endpoint=target_url,
                    method="POST",
                    confidence="high",
                    detail="HTTP Request Smuggling Vulnerability detected by Smuggler.",
                    payload=None
                )
            
            # Leggiamo eventuali altre issue (POTENTIALLY VULNERABLE)
            if "POTENTIALLY" in log_content:
                self.add_finding(
                    type_="request_smuggling",
                    file_="proxy",
                    line=0,
                    endpoint=target_url,
                    method="POST",
                    confidence="low",
                    detail="Potential HTTP Request Smuggling Vulnerability detected.",
                    payload=None
                )

        return "completed", None

run = make_run_fn(SmugglerRunner)
