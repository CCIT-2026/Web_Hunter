"""
modules/injection/nosqli_runner.py  — gated: has_nosql AND NOT has_sql_queries

Testa NoSQL injection con nosqli (o nosql-injection-tool se installato).
Usa payload dalla payload library (categoria "NoSQL Injection").

Output: reports/<service>/nosqli.json
"""

from modules.base_runner import BaseRunner, make_run_fn

_TARGET_URL = "http://localhost"


class NosqliRunner(BaseRunner):
    MODULE_NAME = "nosqli"

    def execute(self):
        if not (self.stack.get("has_nosql") and not self.stack.get("has_sql_queries")):
            return "skipped", "skip: trigger=has_nosql AND NOT has_sql_queries not met"

        tool = next((t for t in ("nosqli", "nosql-injection-tool", "nosqlmap") if self.tool_available(t)), None)
        if not tool:
            # Fallback: manual payload test via curl/requests
            return self._manual_test()

        target_base = self.settings.get("target_url", _TARGET_URL).rstrip("/")
        candidates = [
            ep for ep in self.endpoints
            if any(p["location"] in ("body", "query") for p in ep.get("params", []))
        ]
        if not candidates:
            return "skipped", "skip: no parameterized endpoints"

        for ep in candidates:
            url = f"{target_base}{ep['path']}"
            cmd = [tool, "-u", url, "--scan"]
            if ep["method"] == "POST" and ep.get("params"):
                data = "&".join(f"{p['name']}=TEST" for p in ep["params"] if p["location"] == "body")
                if data:
                    cmd += ["-d", data]

            rc, stdout, _ = self.sh(cmd, timeout=self.timeout * 2)
            for line in stdout.splitlines():
                if any(kw in line.lower() for kw in ["injectable", "vulnerable", "nosql"]):
                    self.add_finding(
                        type_="nosqli",
                        file_=ep["file"],
                        line=ep["line"],
                        endpoint=ep["path"],
                        method=ep["method"],
                        confidence="high",
                        detail=f"{tool}: {line.strip()[:200]}",
                    )

        return "completed", None

    def _manual_test(self):
        """Fallback: use payload library entries for NoSQL Injection."""
        try:
            from modules.payload_library.selector import get_candidates
        except ImportError:
            return "error", "no nosqli tool found and payload_library not available"

        target_base = self.settings.get("target_url", _TARGET_URL).rstrip("/")
        max_results = int(self.settings.get("payload_library_max_per_endpoint", 3))
        payloads = get_candidates("nosql", max_results=max_results)
        candidates = [ep for ep in self.endpoints if ep.get("params")]

        for ep in candidates:
            url = f"{target_base}{ep['path']}"
            for p_item in payloads:
                payload = p_item.get("payload", "")
                for param in ep.get("params", []):
                    if param["location"] not in ("body", "query"):
                        continue
                    self._curl_test(url, ep, param["name"], payload, p_item.get("category", "NoSQL Injection"))

        return "completed", None

    def _curl_test(self, url: str, ep: dict, param: str, payload: str, category: str):
        import json as _json
        body = _json.dumps({param: payload})
        rc, stdout, _ = self.sh(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "-X", ep["method"], url,
             "-H", "Content-Type: application/json",
             "-d", body,
             "--max-time", str(self.timeout)],
        )
        if rc == 0 and stdout.strip() in ("200", "201"):
            self.add_finding(
                type_="nosqli",
                file_=ep["file"],
                line=ep["line"],
                endpoint=ep["path"],
                method=ep["method"],
                confidence="low",
                detail=f"HTTP 2xx with NoSQL payload (requires manual verify) param={param}",
                payload=payload,
                payload_category=category,
                requires_manual_review=True,
            )


run = make_run_fn(NosqliRunner)
