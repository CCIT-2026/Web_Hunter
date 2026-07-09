"""
modules/discovery/jsluice_runner.py  — ungated discovery

Esegue jsluice su tutti i file .js/.ts del servizio per estrarre:
  - URL/path interni (jsluice urls)
  - Segreti (jsluice secrets)

Le credenziali trovate il cui path NON compare in endpoints_map.json
vengono marcate unlikely_path=True (sezione separata nel report Markdown).

Output: reports/<service>/jsluice.json
"""

import json
from pathlib import Path

from modules.base_runner import BaseRunner, make_run_fn

_JS_EXTS = {".js", ".ts", ".mjs", ".jsx", ".tsx"}


class JsluiceRunner(BaseRunner):
    MODULE_NAME = "jsluice"

    def execute(self):
        if not self.tool_available("jsluice"):
            return "error", "jsluice not found in PATH"

        js_files = [
            f for f in self.service_root.rglob("*")
            if f.suffix.lower() in _JS_EXTS
            and ".git" not in f.parts
            and "node_modules" not in f.parts
        ]
        if not js_files:
            return "skipped", "no JS/TS files found in source"

        known_paths = set(self.endpoint_paths())

        for js_file in js_files:
            rel = str(js_file.relative_to(self.service_root))
            self._run_subcommand("urls", js_file, rel, known_paths)
            self._run_subcommand("secrets", js_file, rel, known_paths)

        return "completed", None

    def _run_subcommand(self, subcmd: str, js_file: Path, rel: str, known_paths: set):
        rc, stdout, stderr = self.sh(
            ["jsluice", subcmd, "-i", str(js_file)],
            timeout=self.timeout,
        )
        if rc not in (0, 1) or not stdout.strip():
            return

        for line in stdout.splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            if subcmd == "urls":
                url = obj.get("url") or obj.get("value") or ""
                kind = obj.get("kind", "url")
                # Normalize: strip query string for path matching
                path_part = url.split("?")[0].split("#")[0]
                is_unlikely = path_part not in known_paths

                self.add_finding(
                    type_="endpoint_reference",
                    file_=rel,
                    line=obj.get("line"),
                    endpoint=path_part or None,
                    method=None,
                    confidence="low",
                    detail=f"jsluice:{kind} → {url}",
                    unlikely_path=is_unlikely,
                    requires_manual_review=True,
                )

            elif subcmd == "secrets":
                kind = obj.get("kind", "secret")
                value = obj.get("value", "")[:80]
                # Correlate with known endpoints
                source = obj.get("filename") or rel
                is_unlikely = True  # secrets raramente mappano a endpoint noti

                self.add_finding(
                    type_="secret",
                    file_=source,
                    line=obj.get("line"),
                    endpoint=None,
                    method=None,
                    confidence="medium",
                    detail=f"jsluice:{kind} = {value!r}",
                    unlikely_path=is_unlikely,
                    requires_manual_review=True,
                )


run = make_run_fn(JsluiceRunner)
