"""
modules/injection/generic_category_runner.py

Runner leggero per categorie della payload library prive di tool dedicato:
  SSRF, GraphQL, XPath, Directory Traversal, LDAP.

L'orchestratore lo chiama più volte, una per categoria, passando category= via kwargs.
Il gating booleano avviene in trigger_rules.py; qui si assume il trigger già passato.

Per ogni categoria:
  1. Legge i *_locations dal detected_stack per sapere file:riga dei sink.
  2. Prende max N payload dalla payload library (get_candidates).
  3. Testa 1-2 richieste per endpoint con parametri plausibili.
  4. Non fa mai un giro esaustivo su tutti i payload disponibili.

Output: reports/<service>/<category>.json
"""

import json as _json
from modules.base_runner import BaseRunner, make_run_fn

_TARGET_URL = "http://localhost"

_CATEGORY_META = {
    "ssrf": {
        "stack_flag": "has_outbound_request_on_input",
        "locations_key": "ssrf_locations",
        "finding_type": "ssrf",
        "payload_category": "Server Side Request Forgery",
        "content_type": "application/x-www-form-urlencoded",
    },
    "graphql": {
        "stack_flag": "has_graphql_endpoint",
        "locations_key": "graphql_locations",
        "finding_type": "graphql_injection",
        "payload_category": "GraphQL Injection",
        "content_type": "application/json",
    },
    "xpath": {
        "stack_flag": "has_xpath_parser",
        "locations_key": "xpath_locations",
        "finding_type": "xpath_injection",
        "payload_category": "XPath Injection",
        "content_type": "application/x-www-form-urlencoded",
    },
    "directory_traversal": {
        "stack_flag": "has_file_path_from_input",
        "locations_key": "path_traversal_locations",
        "finding_type": "path_traversal",
        "payload_category": "Directory Traversal",
        "content_type": "application/x-www-form-urlencoded",
    },
    "ldap": {
        "stack_flag": "has_ldap_query",
        "locations_key": "ldap_locations",
        "finding_type": "ldap_injection",
        "payload_category": "LDAP Injection",
        "content_type": "application/x-www-form-urlencoded",
    },
}


class GenericCategoryRunner(BaseRunner):
    MODULE_NAME = "generic_category"  # overridden per istanza

    def __init__(self, *args, category: str = "ssrf", **kwargs):
        super().__init__(*args, **kwargs)
        self.category = category
        self.MODULE_NAME = category  # report scritto come <category>.json

    def execute(self):
        meta = _CATEGORY_META.get(self.category)
        if not meta:
            return "error", f"unknown category: {self.category!r}"

        if not self.stack.get(meta["stack_flag"]):
            return "skipped", f"skip: {meta['stack_flag']}=False"

        try:
            from modules.payload_library.selector import get_candidates
        except ImportError:
            return "error", "payload_library not available"

        max_n = int(self.settings.get("payload_library_max_per_endpoint", 3))
        # Filter payloads by language if meaningful (e.g. don't use PowerShell on Linux targets)
        lang = self.stack.get("language", "")
        payloads = get_candidates(
            meta["payload_category"],
            max_results=max_n,
            exclude_language="powershell" if lang != "csharp" else None,
        )

        if not payloads:
            return "skipped", f"skip: no payloads found for category={self.category!r}"

        # Sink locations tell us which files have the vulnerable pattern
        sink_files = {loc["file"] for loc in self.stack.get(meta["locations_key"], [])}

        # Candidate endpoints: those whose handler file matches a sink location
        candidates = [ep for ep in self.endpoints if ep["file"] in sink_files and ep.get("params")]
        if not candidates:
            # Fallback: all endpoints with params
            candidates = [ep for ep in self.endpoints if ep.get("params")]
        if not candidates:
            return "skipped", f"skip: no parameterized endpoints plausible for {self.category}"

        target_base = self.settings.get("target_url", _TARGET_URL).rstrip("/")

        for ep in candidates:
            url = f"{target_base}{ep['path']}"
            for p_item in payloads[:max_n]:
                payload_str = p_item.get("payload", "")
                self._probe(url, ep, payload_str, meta)

        return "completed", None

    def _probe(self, url: str, ep: dict, payload: str, meta: dict):
        method = ep["method"] if ep["method"] != "ANY" else "GET"
        content_type = meta["content_type"]

        # Pick first injectable param
        injectable = next(
            (p for p in ep.get("params", []) if p["location"] in ("body", "query")),
            None,
        )
        if not injectable:
            return

        param_name = injectable["name"]

        if method == "GET":
            from urllib.parse import urlencode, urlparse, parse_qs, urlencode
            sep = "&" if "?" in url else "?"
            full_url = f"{url}{sep}{param_name}={payload}"
            cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                   "-G", full_url, "--max-time", str(self.timeout)]
        else:
            if content_type == "application/json":
                body = _json.dumps({param_name: payload})
            else:
                body = f"{param_name}={payload}"
            cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                   "-X", method, url,
                   "-H", f"Content-Type: {content_type}",
                   "-d", body, "--max-time", str(self.timeout)]

        rc, stdout, _ = self.sh(cmd)
        http_code = stdout.strip() if rc == 0 else "?"

        # Low confidence: server responded with 2xx using a suspicious payload
        if rc == 0 and http_code.startswith("2"):
            self.add_finding(
                type_=meta["finding_type"],
                file_=ep["file"],
                line=ep["line"],
                endpoint=ep["path"],
                method=method,
                confidence="low",
                detail=f"[{self.category}] HTTP {http_code} with payload (manual verify required), param={param_name!r}",
                param=param_name,
                payload=payload,
                payload_category=meta["payload_category"],
                requires_manual_review=True,
            )


def run(service_root, service_name, report_dir, settings,
        stack=None, endpoints=None, category="ssrf", **kwargs):
    instance = GenericCategoryRunner(
        service_root, service_name, report_dir, settings,
        stack=stack, endpoints=endpoints, category=category,
    )
    return instance.run()
