"""
modules/injection/dalfox_runner.py

Esegue dalfox (fuzzer XSS) sugli endpoint parametrizzati.
Utilizza l'output JSON per parsare e riportare in modo strutturato i finding.
"""

import json
from pathlib import Path
from modules.base_runner import BaseRunner, make_run_fn

_TARGET_URL = "http://localhost"

class DalfoxRunner(BaseRunner):
    MODULE_NAME = "dalfox"

    def execute(self):
        if not self.tool_available("dalfox"):
            return "error", "dalfox not found in PATH"

        target_base = (self.settings.get("target_url") or _TARGET_URL).rstrip("/")
        
        # Filtriamo solo endpoint con parametri
        candidates = [ep for ep in self.endpoints if ep.get("params")]
        if not candidates:
            return "skipped", "skip: no parameterized endpoints"

        for ep in candidates:
            url = f"{target_base}{ep['path']}"
            self._test_endpoint(url, ep)

        return "completed", None

    def _load_auth_args(self) -> list[str]:
        state = self._load_json("auth_state.json") or {}
        if not state.get("logged_in"):
            return []
        args = []
        if state.get("cookie"):
            args += ["--cookie", state["cookie"]]
        if state.get("auth_header"):
            args += ["-H", state["auth_header"]]
        return args

    def _test_endpoint(self, url: str, ep: dict):
        cmd = [
            "dalfox", "url", url,
            "--format", "json",
            "--silence",
            "--skip-bav", # Salta blind testing per risparmiare tempo se non c'e un blind-server specificato
            "--timeout", str(self.timeout)
        ] + self._load_auth_args()

        # Dalfox supporta anche POST data
        body_params = [p for p in ep.get("params", []) if p["location"] == "body"]
        query_params = [p for p in ep.get("params", []) if p["location"] == "query"]

        if ep["method"] in ("POST", "PUT", "PATCH") and body_params:
            cmd += ["-d", "&".join(f"{p['name']}=DALFOXTEST" for p in body_params)]
            # Dalfox usa --data ma il flag corretto è -d
        elif query_params:
            qs = "&".join(f"{p['name']}=DALFOXTEST" for p in query_params)
            url = f"{url}?{qs}"
            cmd[cmd.index("url") + 1] = url

        rc, stdout, stderr = self.sh(cmd, timeout=self.timeout * 3)

        # Scrive l'output grezzo
        slug = ep["path"].replace("/", "_").strip("_") or "root"
        raw_dir = self.report_dir / "raw_datas"
        raw_dir.mkdir(parents=True, exist_ok=True)
        (raw_dir / f"dalfox_{slug}.json").write_text(stdout)

        if rc == -1 or not stdout.strip():
            return

        try:
            # Dalfox JSON output: [{"type": "V", ...}, {}]
            results = json.loads(stdout)
            for data in results:
                if not isinstance(data, dict):
                    continue
                if data.get("type") == "V":
                    param = data.get("param", "unknown")
                    poc = data.get("data", "")
                    self.add_finding(
                        type_="xss",
                        file_=ep["file"],
                        line=ep["line"],
                        endpoint=ep["path"],
                        method=ep["method"],
                        confidence="high",
                        detail=f"Dalfox XSS: param={param}",
                        param=param,
                        payload=poc,
                    )
        except json.JSONDecodeError:
            pass

run = make_run_fn(DalfoxRunner)
