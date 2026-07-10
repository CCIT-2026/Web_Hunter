"""
modules/mapping/endpoint_parser.py

Estrae tutti gli endpoint HTTP da un sorgente whitebox e scrive:
  reports/<service>/endpoints_map.json   (schema: schemas/endpoints_map.schema.json)
  reports/<service>/detected_stack.json  (stub, sovrascritta poi da stack_detector)

Supporta: Flask, Django, FastAPI, Express/Node.js, PHP (Symfony, Laravel), Go (Gin/Echo/net-http).

Architettura:
  EndpointParser  — orchestratore (cammina il sorgente, seleziona extractor, aggrega)
  _FlaskExtractor, _DjangoExtractor, _FastApiExtractor, _ExpressExtractor,
  _PhpExtractor, _GoExtractor  — per-framework, stateless, restituiscono lista di dict.

Ogni extractor segnala file:riga (basato su enumerate dei sorgenti),
mai parametri inventati — params=[] se non ricavabili staticamente.
"""

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------

_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ANY"}
_AUTH_PATTERNS = [
    # Flask
    (r"@(?:login_required|jwt_required|require_auth|token_required|auth\.login_required)", "decorator"),
    # Django
    (r"@(?:login_required|permission_required|staff_member_required)", "decorator"),
    # FastAPI Depends
    (r"Depends\((?:oauth2_scheme|get_current_user|verify_token|require_auth)", "depends"),
    # generic
    (r"@(?:requires_auth|authenticated|protected)", "decorator"),
    # PHP
    (r"#\[IsGranted\]|@IsGranted|@Security|->requiresAuth\(", "annotation"),
]
_AUTH_PATS_COMPILED = [(re.compile(p, re.IGNORECASE), t) for p, t in _AUTH_PATTERNS]

# JWT-specific checks (used to set auth.type)
_JWT_AUTH = re.compile(r"jwt|bearer|token", re.IGNORECASE)


def _norm_method(m: str) -> str:
    u = m.strip().upper()
    return u if u in _HTTP_METHODS else "ANY"


def _make_endpoint(path, method, file, line, handler=None, params=None, auth=None):
    return {
        "path": path,
        "method": _norm_method(method),
        "file": file,
        "line": line,
        "handler_function": handler,
        "params": params or [],
        "auth": auth,
    }


def _detect_auth_near(lines: list[str], center: int, window: int = 6):
    """Scan [center-window .. center] for known auth decorators/middleware."""
    start = max(0, center - window)
    for i in range(start, center + 1):
        line = lines[i]
        for pat, kind in _AUTH_PATS_COMPILED:
            if pat.search(line):
                auth_type = "jwt" if _JWT_AUTH.search(line) else "session"
                return {"required": True, "type": auth_type, "file": None, "line": i + 1}
    return None


# ---------------------------------------------------------------------------
# Path-param extraction helpers
# ---------------------------------------------------------------------------

# Body / query param patterns — direct access
_DIRECT_BODY: list[re.Pattern] = [
    # Flask: request.form / request.values
    re.compile(r"""request\s*\.\s*(?:form|values)\s*(?:\[['"]([^'"]+)['"]\]|\.get\s*\(\s*['"]([^'"]+)['"]\))"""),
    # Flask: request.json / request.get_json()
    re.compile(r"""request\s*\.\s*(?:json|get_json\s*\([^)]*\))\s*(?:\[['"]([^'"]+)['"]\]|\.get\s*\(\s*['"]([^'"]+)['"]\))"""),
    # Django: request.POST
    re.compile(r"""request\s*\.\s*POST\s*(?:\[['"]([^'"]+)['"]\]|\.get\s*\(\s*['"]([^'"]+)['"]\))"""),
    # Express: req.body
    re.compile(r"""req\s*\.\s*body\s*(?:\[['"`]([^'"`]+)['"`]\]|\.([a-zA-Z_]\w*))"""),
    # PHP: $_POST / $_REQUEST
    re.compile(r"""\$_(?:POST|REQUEST)\s*\[['"]([^'"]+)['"]\]"""),
]
_DIRECT_QUERY: list[re.Pattern] = [
    # Flask: request.args
    re.compile(r"""request\s*\.\s*args\s*(?:\[['"]([^'"]+)['"]\]|\.get\s*\(\s*['"]([^'"]+)['"]\))"""),
    # Django: request.GET
    re.compile(r"""request\s*\.\s*GET\s*(?:\[['"]([^'"]+)['"]\]|\.get\s*\(\s*['"]([^'"]+)['"]\))"""),
    # Express: req.query
    re.compile(r"""req\s*\.\s*query\s*(?:\[['"`]([^'"`]+)['"`]\]|\.([a-zA-Z_]\w*))"""),
    # PHP: $_GET
    re.compile(r"""\$_GET\s*\[['"]([^'"]+)['"]\]"""),
]
# Detects: varname = request.get_json() / request.form / request.json / request.args
_ASSIGN_REQUEST = re.compile(
    r"""(\w+)\s*=\s*request\s*\.\s*(form|json|get_json\s*\([^)]*\)|args|values)"""
)


def _scan_handler_params(lines: list[str], def_idx: int, max_lines: int = 50) -> list[dict]:
    """Scan handler body for request parameter accesses (direct and via alias variable)."""
    params: list[dict] = []
    seen: set[tuple] = set()

    # Stop at next top-level def / class / decorator (indent == 0) to avoid
    # leaking params from a subsequent handler into this one.
    end = min(def_idx + max_lines, len(lines))
    body: list[str] = []
    for idx in range(def_idx, end):
        ln = lines[idx]
        stripped = ln.lstrip()
        if stripped and len(ln) - len(stripped) == 0 and (
            stripped.startswith("def ")
            or stripped.startswith("async def ")
            or stripped.startswith("class ")
            or stripped.startswith("@")
        ):
            break
        body.append(ln)

    def _add(name: str, location: str, encoding: str = "form") -> None:
        k = (name, location)
        if k not in seen:
            seen.add(k)
            params.append({"name": name, "location": location, "type": "string", "encoding": encoding})

    def _first_group(m: re.Match) -> str | None:
        return next((m.group(g) for g in range(1, m.lastindex + 1) if m.group(g)), None)

    # Pass 1: collect alias assignments (data = request.get_json(), etc.)
    # Map varname → (location, encoding)
    aliases: dict[str, tuple[str, str]] = {}
    for line in body:
        m = _ASSIGN_REQUEST.search(line)
        if m:
            src = m.group(2).lower()
            if "args" in src:
                aliases[m.group(1)] = ("query", "form")
            elif "json" in src or "get_json" in src:
                aliases[m.group(1)] = ("body", "json")
            else:
                aliases[m.group(1)] = ("body", "form")

    # Compile alias patterns once
    alias_pats = {
        varname: (
            re.compile(
                r"\b" + re.escape(varname)
                + r"""\s*(?:\[['"]([^'"]+)['"]\]|\.get\s*\(\s*['"]([^'"]+)['"]\))"""
            ),
            loc_enc,
        )
        for varname, loc_enc in aliases.items()
    }

    # Body patterns with encoding hints: (pattern, encoding)
    _BODY_WITH_ENC = [
        (_DIRECT_BODY[0], "form"),   # request.form / request.values
        (_DIRECT_BODY[1], "json"),   # request.json / request.get_json()
        (_DIRECT_BODY[2], "form"),   # request.POST (Django)
        (_DIRECT_BODY[3], "json"),   # req.body (Express — assume JSON)
        (_DIRECT_BODY[4], "form"),   # $_POST / $_REQUEST
    ]

    # Pass 2: scan each line
    for line in body:
        for pat, enc in _BODY_WITH_ENC:
            for m in pat.finditer(line):
                name = _first_group(m)
                if name:
                    _add(name, "body", enc)
        for pat in _DIRECT_QUERY:
            for m in pat.finditer(line):
                name = _first_group(m)
                if name:
                    _add(name, "query", "form")
        for pat, (loc, enc) in alias_pats.values():
            for m in pat.finditer(line):
                name = _first_group(m)
                if name:
                    _add(name, loc, enc)

    return params


def _path_params(route_str: str) -> list[dict]:
    """Extract path params from Flask/Django/FastAPI/Express/Go templates."""
    seen: set[str] = set()
    params: list[dict] = []

    def _add(name: str) -> None:
        if name not in seen:
            seen.add(name)
            params.append({"name": name, "location": "path", "type": "string"})

    # Flask/Werkzeug/FastAPI/Django: <type:name> or <name>
    for m in re.finditer(r"<(?:[a-z_]+:)?([a-zA-Z_]\w*)>", route_str):
        _add(m.group(1))
    # Express/Go-gin: /:name  — requires leading / to avoid matching inside <int:name>
    for m in re.finditer(r"/(?::|\{)([a-zA-Z_]\w*)(?:\})?", route_str):
        _add(m.group(1))
    # Go wildcard: /*name
    for m in re.finditer(r"/\*([a-zA-Z_]\w*)", route_str):
        _add(m.group(1))

    return params


# ---------------------------------------------------------------------------
# Per-framework extractors
# ---------------------------------------------------------------------------

class _FlaskExtractor:
    """Flask / Flask-RESTX / Flask-Blueprint route decorators."""

    _ROUTE   = re.compile(r"""@\w+\.route\(\s*['"]([^'"]+)['"](?:[^)]*methods\s*=\s*\[([^\]]*)\])?""")
    _VERB    = re.compile(r"""@\w+\.(get|post|put|patch|delete|head|options)\(\s*['"]([^'"]+)['"]""", re.I)
    _DEF     = re.compile(r"""^def\s+([a-zA-Z_]\w*)\s*\(""")

    def extract(self, src: str, rel_path: str) -> list[dict]:
        lines = src.splitlines()
        results = []
        i = 0
        while i < len(lines):
            line = lines[i]
            # @app.route / @blueprint.route
            m = self._ROUTE.search(line)
            if m:
                route = m.group(1)
                methods_raw = m.group(2) or "GET"
                methods = [x.strip().strip("'\"") for x in methods_raw.split(",") if x.strip().strip("'\"")]
                if not methods:
                    methods = ["GET"]
                auth = _detect_auth_near(lines, i)
                handler = None
                def_idx = None
                for j in range(i + 1, min(i + 6, len(lines))):
                    dm = self._DEF.match(lines[j].strip())
                    if dm:
                        handler = dm.group(1)
                        def_idx = j
                        break
                params = _path_params(route)
                if def_idx is not None:
                    params = params + _scan_handler_params(lines, def_idx + 1)
                for method in methods:
                    results.append(_make_endpoint(route, method, rel_path, i + 1, handler, list(params), auth))
                i += 1
                continue
            # @app.get / @app.post shorthand (Flask 2.0+)
            m = self._VERB.search(line)
            if m:
                method, route = m.group(1).upper(), m.group(2)
                auth = _detect_auth_near(lines, i)
                handler = None
                def_idx = None
                for j in range(i + 1, min(i + 6, len(lines))):
                    dm = self._DEF.match(lines[j].strip())
                    if dm:
                        handler = dm.group(1)
                        def_idx = j
                        break
                params = _path_params(route)
                if def_idx is not None:
                    params = params + _scan_handler_params(lines, def_idx + 1)
                results.append(_make_endpoint(route, method, rel_path, i + 1, handler, params, auth))
            i += 1
        return results


class _DjangoExtractor:
    """Django urlpatterns (path/re_path/url)."""

    _URLPAT = re.compile(r"""(?:^|\s)(?:path|re_path|url)\(\s*r?['"]([^'"]+)['"]""")
    _VIEW   = re.compile(r""",\s*(?:views\.)?([a-zA-Z_]\w*)(?:\.as_view\(\))?""")

    def extract(self, src: str, rel_path: str) -> list[dict]:
        lines = src.splitlines()
        results = []
        for i, line in enumerate(lines):
            m = self._URLPAT.search(line)
            if not m:
                continue
            route = m.group(1)
            # Django URL confs list all methods implicitly
            vm = self._VIEW.search(line)
            handler = vm.group(1) if vm else None
            # Django CBVs (as_view) support multiple methods; we register ANY
            results.append(_make_endpoint(route, "ANY", rel_path, i + 1, handler, _path_params(route), None))
        return results


class _FastApiExtractor:
    """FastAPI @app.get / @router.post style decorators."""

    _VERB = re.compile(r"""@\w+\.(get|post|put|patch|delete|head|options)\(\s*['"]([^'"]+)['"]""", re.I)
    _DEF  = re.compile(r"""^(?:async\s+)?def\s+([a-zA-Z_]\w*)\s*\(""")

    def extract(self, src: str, rel_path: str) -> list[dict]:
        lines = src.splitlines()
        results = []
        for i, line in enumerate(lines):
            m = self._VERB.search(line)
            if not m:
                continue
            method, route = m.group(1).upper(), m.group(2)
            auth = _detect_auth_near(lines, i)
            handler = None
            def_idx = None
            for j in range(i + 1, min(i + 6, len(lines))):
                dm = self._DEF.match(lines[j].strip())
                if dm:
                    handler = dm.group(1)
                    def_idx = j
                    break
            params = _path_params(route)
            if def_idx is not None:
                params = params + _scan_handler_params(lines, def_idx + 1)
            results.append(_make_endpoint(route, method, rel_path, i + 1, handler, params, auth))
        return results


class _ExpressExtractor:
    """Express/Node.js router.get / app.post style."""

    _VERB = re.compile(
        r"""(?:app|router|server)\s*\.\s*(get|post|put|patch|delete|head|options|all)\s*\(\s*['"`]([^'"`]+)['"`]""",
        re.I,
    )
    # also .route('/path').get(handler)
    _CHAIN = re.compile(r"""\.route\(\s*['"`]([^'"`]+)['"`]\s*\)\s*\.(get|post|put|patch|delete|all)""", re.I)

    def extract(self, src: str, rel_path: str) -> list[dict]:
        lines = src.splitlines()
        results = []
        for i, line in enumerate(lines):
            m = self._VERB.search(line)
            if m:
                method = "ANY" if m.group(1).lower() == "all" else m.group(1).upper()
                route = m.group(2)
                auth = _detect_auth_near(lines, i)
                params = _path_params(route) + _scan_handler_params(lines, i + 1)
                results.append(_make_endpoint(route, method, rel_path, i + 1, None, params, auth))
                continue
            m = self._CHAIN.search(line)
            if m:
                route, method = m.group(1), m.group(2).upper()
                params = _path_params(route) + _scan_handler_params(lines, i + 1)
                results.append(_make_endpoint(route, method, rel_path, i + 1, None, params, None))
        return results


class _PhpExtractor:
    """Symfony (#[Route]) and Laravel (Route::get) route declarations."""

    # Symfony PHP8 attribute
    _SF_ATTR  = re.compile(r"""#\[Route\s*\(\s*['"]([^'"]+)['"](?:.*?methods\s*:\s*\[([^\]]*)\])?""", re.S)
    # Symfony docblock
    _SF_DOC   = re.compile(r"""@Route\s*\(\s*["']([^"']+)["'](?:.*?methods\s*=\s*\{([^}]*)\})?""", re.S)
    # Symfony handler (public function)
    _SF_DEF   = re.compile(r"""public\s+function\s+([a-zA-Z_]\w*)\s*\(""")
    # Laravel
    _LA       = re.compile(r"""Route::(get|post|put|patch|delete|any|options)\s*\(\s*['"]([^'"]+)['"]""", re.I)

    def extract(self, src: str, rel_path: str) -> list[dict]:
        lines = src.splitlines()
        results = []
        joined = "\n".join(lines)
        # Symfony: scan multi-line attribute/docblock
        for m in self._SF_ATTR.finditer(joined):
            route = m.group(1)
            methods_raw = m.group(2) or "ANY"
            methods = [x.strip().strip("'\"") for x in methods_raw.split(",") if x.strip()]
            if not methods:
                methods = ["ANY"]
            line_no = joined[: m.start()].count("\n") + 1
            handler = None
            for j in range(line_no, min(line_no + 6, len(lines))):
                dm = self._SF_DEF.search(lines[j])
                if dm:
                    handler = dm.group(1)
                    break
            auth = _detect_auth_near(lines, line_no - 1)
            for method in methods:
                results.append(_make_endpoint(route, method, rel_path, line_no, handler, _path_params(route), auth))
        # Symfony docblocks
        for m in self._SF_DOC.finditer(joined):
            route = m.group(1)
            methods_raw = m.group(2) or "ANY"
            methods = [x.strip().strip("'\"") for x in methods_raw.split(",") if x.strip()]
            if not methods:
                methods = ["ANY"]
            line_no = joined[: m.start()].count("\n") + 1
            handler = None
            for j in range(line_no, min(line_no + 8, len(lines))):
                dm = self._SF_DEF.search(lines[j])
                if dm:
                    handler = dm.group(1)
                    break
            auth = _detect_auth_near(lines, line_no - 1)
            for method in methods:
                results.append(_make_endpoint(route, method, rel_path, line_no, handler, _path_params(route), auth))
        # Laravel
        for i, line in enumerate(lines):
            m = self._LA.search(line)
            if m:
                method = "ANY" if m.group(1).lower() == "any" else m.group(1).upper()
                route = m.group(2)
                auth = _detect_auth_near(lines, i)
                results.append(_make_endpoint(route, method, rel_path, i + 1, None, _path_params(route), auth))
        return results


class _GoExtractor:
    """Gin, Echo, Fiber, chi, gorilla/mux, net/http HandleFunc."""

    _GIN_ECHO = re.compile(
        r"""(?:r|router|e|f|g)\s*\.\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Any|Handle)\s*\(\s*["']([^"']+)["']""",
        re.I,
    )
    _HTTP = re.compile(r"""(?:http\.HandleFunc|mux\.Handle|mux\.HandleFunc)\s*\(\s*["']([^"']+)["']""")

    def extract(self, src: str, rel_path: str) -> list[dict]:
        lines = src.splitlines()
        results = []
        for i, line in enumerate(lines):
            m = self._GIN_ECHO.search(line)
            if m:
                method = "ANY" if m.group(1).lower() in ("any", "handle") else m.group(1).upper()
                route = m.group(2)
                auth = _detect_auth_near(lines, i)
                results.append(_make_endpoint(route, method, rel_path, i + 1, None, _path_params(route), auth))
                continue
            m = self._HTTP.search(line)
            if m:
                route = m.group(1)
                results.append(_make_endpoint(route, "ANY", rel_path, i + 1, None, _path_params(route), None))
        return results


# ---------------------------------------------------------------------------
# Language → extractor mapping
# ---------------------------------------------------------------------------

_EXTRACTORS_BY_EXT: dict[str, list] = {
    ".py":  [_FlaskExtractor(), _DjangoExtractor(), _FastApiExtractor()],
    ".js":  [_ExpressExtractor()],
    ".ts":  [_ExpressExtractor(), _FastApiExtractor()],
    ".mjs": [_ExpressExtractor()],
    ".php": [_PhpExtractor()],
    ".go":  [_GoExtractor()],
}

_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "vendor", "dist", "build", ".mypy_cache"}


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

class EndpointParser:
    def __init__(self, service_root: str, service_name: str, report_dir: str):
        self.root = Path(service_root).resolve()
        self.service = service_name
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def run(self) -> list[dict]:
        endpoints: list[dict] = []
        seen: set[tuple] = set()

        for fpath in self._walk():
            ext = fpath.suffix.lower()
            extractors = _EXTRACTORS_BY_EXT.get(ext, [])
            if not extractors:
                continue
            try:
                src = fpath.read_text(errors="replace")
            except Exception as e:
                logger.warning("Cannot read %s: %s", fpath, e)
                continue
            rel = str(fpath.relative_to(self.root))
            for extractor in extractors:
                for ep in extractor.extract(src, rel):
                    key = (ep["path"], ep["method"], ep["file"], ep["line"])
                    if key not in seen:
                        seen.add(key)
                        endpoints.append(ep)

        out = self.report_dir / "endpoints_map.json"
        out.write_text(json.dumps(endpoints, indent=2))
        logger.info("Mapping: %d endpoints → %s", len(endpoints), out)
        return endpoints

    def _walk(self):
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fname in filenames:
                yield Path(dirpath) / fname


# ---------------------------------------------------------------------------
# CLI entry (also called by orchestrator/core.py as a subprocess or inline)
# ---------------------------------------------------------------------------

def run(service_root: str, service_name: str, report_dir: str, settings: dict | None = None) -> dict:
    """Runner interface expected by orchestrator/core.py."""
    import datetime

    t0 = time.monotonic()
    parser = EndpointParser(service_root, service_name, report_dir)
    try:
        endpoints = parser.run()
        status, skip_reason = "completed", None
    except Exception as exc:
        endpoints = []
        status, skip_reason = "error", str(exc)
        logger.exception("endpoint_parser failed")

    report = {
        "module": "mapping",
        "service": service_name,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "status": status,
        "skip_reason": skip_reason,
        "findings": [
            {
                "type": "endpoint",
                "file": ep["file"],
                "line": ep["line"],
                "endpoint": ep["path"],
                "method": ep["method"],
                "confidence": "high",
                "detail": f"handler={ep['handler_function']}, auth={'yes' if ep['auth'] else 'none'}",
                "source_module": "mapping",
                "requires_manual_review": False,
                "unlikely_path": False,
            }
            for ep in endpoints
        ],
    }
    rpath = Path(report_dir) / "mapping.json"
    rpath.write_text(json.dumps(report, indent=2))
    elapsed = time.monotonic() - t0
    logger.info("mapping done in %.1fs: %s endpoints", elapsed, len(endpoints))
    return report
