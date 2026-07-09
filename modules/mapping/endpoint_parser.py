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

def _path_params(route_str: str) -> list[dict]:
    """Extract path params from Flask/Django/FastAPI/Express/Go templates."""
    params = []
    # Flask/Werkzeug: <type:name> or <name>
    for m in re.finditer(r"<(?:[a-z_]+:)?([a-zA-Z_]\w*)>", route_str):
        params.append({"name": m.group(1), "location": "path", "type": "string"})
    # Express: :name
    for m in re.finditer(r":([a-zA-Z_]\w*)", route_str):
        params.append({"name": m.group(1), "location": "path", "type": "string"})
    # Go/gin: :name or *name (wildcard)
    for m in re.finditer(r"[/:]\*([a-zA-Z_]\w*)", route_str):
        params.append({"name": m.group(1), "location": "path", "type": "string"})
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
                # look ahead for def
                for j in range(i + 1, min(i + 4, len(lines))):
                    dm = self._DEF.match(lines[j].strip())
                    if dm:
                        handler = dm.group(1)
                        break
                params = _path_params(route)
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
                for j in range(i + 1, min(i + 4, len(lines))):
                    dm = self._DEF.match(lines[j].strip())
                    if dm:
                        handler = dm.group(1)
                        break
                results.append(_make_endpoint(route, method, rel_path, i + 1, handler, _path_params(route), auth))
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
            for j in range(i + 1, min(i + 4, len(lines))):
                dm = self._DEF.match(lines[j].strip())
                if dm:
                    handler = dm.group(1)
                    break
            params = _path_params(route)
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
                results.append(_make_endpoint(route, method, rel_path, i + 1, None, _path_params(route), auth))
                continue
            m = self._CHAIN.search(line)
            if m:
                route, method = m.group(1), m.group(2).upper()
                results.append(_make_endpoint(route, method, rel_path, i + 1, None, _path_params(route), None))
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
