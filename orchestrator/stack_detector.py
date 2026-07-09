"""
orchestrator/stack_detector.py

Analizza il sorgente di un servizio e scrive reports/<service>/detected_stack.json,
il contratto centrale usato da trigger_rules.py per attivare i moduli.

Design:
  - Una sola passata di walk; per ogni file accumula hits in strutture di dati.
  - Ogni "detector" è un metodo privato che riceve (src, rel_path, lines) e
    aggiorna lo stato interno self._stack via _add_location().
  - Nessun modulo downstream reimplementa detection: legge solo detected_stack.json.
  - Produce anche un stub endpoints_map.json se il mapping non è ancora stato eseguito
    (fail-safe: non blocca il resto della pipeline).
"""

import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "vendor", "dist", "build", ".mypy_cache"}


# ---------------------------------------------------------------------------
# Regex catalogues
# ---------------------------------------------------------------------------

class _RE:
    # --- language/framework detection ---
    FLASK       = re.compile(r"""from flask import|import flask""", re.I)
    DJANGO      = re.compile(r"""from django|import django|django\.conf""", re.I)
    FASTAPI     = re.compile(r"""from fastapi|import fastapi""", re.I)
    EXPRESS     = re.compile(r"""require\s*\(\s*['"]express['"]|from\s+['"]express['"]""")
    SYMFONY     = re.compile(r"""use Symfony\\|#\[Route\(|@Route\(""")
    LARAVEL     = re.compile(r"""use Illuminate\\|Route::|Artisan::""")
    GIN         = re.compile(r"""gin\.Default\(\)|gin\.New\(\)|"github\.com/gin-gonic/gin""")
    TWIG        = re.compile(r"""\.twig['"]|Twig\\|twig_template""", re.I)
    GRAPHQL_FW  = re.compile(r"""graphene|strawberry|ariadne|graphql-core|ApolloServer|makeExecutableSchema""", re.I)

    # --- PHP/gRPC ---
    PROTO       = re.compile(r"\.proto$")

    # --- SQL ---
    SQL_RAW     = re.compile(
        r"""(?:cursor\.execute|db\.execute|session\.execute|connection\.execute|"SELECT |'SELECT |"INSERT |'INSERT |"UPDATE |'UPDATE |"DELETE |'DELETE |"DROP |"TRUNCATE )""",
        re.I,
    )
    SQL_ORM_RAW = re.compile(r"""\.raw\s*\(|\.rawQuery\s*\(|text\s*\(""", re.I)

    # --- NoSQL ---
    NOSQL_FIND  = re.compile(r"""\.find\s*\(|\.findOne\s*\(|\.aggregate\s*\(|db\[|collection\[|r\.table\(""")
    NOSQL_REDIS = re.compile(r"""redis\.(?:get|set|hget|hset|lpush|rpush|zadd)|\.get\(|\.set\(""")
    NOSQL_MONGO = re.compile(r"""pymongo|MongoClient|mongoose|mongodb""", re.I)

    # --- JWT ---
    JWT_IMPORT  = re.compile(r"""import jwt|from jwt|jwt\.decode|jwt\.verify|verify_jwt|decode_token""", re.I)
    JWT_WEAK_NONE   = re.compile(r"""algorithms?\s*=\s*\[?\s*['"]none['"]|alg\s*=\s*['"]none['"]""", re.I)
    JWT_WEAK_VER    = re.compile(r"""verify\s*=\s*False|options\s*=\s*\{[^}]*verify[^}]*False""", re.I)
    JWT_WEAK_SECRET = re.compile(r"""(?:secret|key)\s*=\s*['"][^'"]{1,16}['"]""", re.I)

    # --- eval / pickle on input ---
    EVAL_EXEC   = re.compile(r"""\beval\s*\(|\bexec\s*\(""")
    PICKLE      = re.compile(r"""pickle\.loads?\s*\(|cPickle\.loads?\s*\(""")
    YAML_LOAD   = re.compile(r"""yaml\.load\s*\((?!\s*[^,)]+Loader\s*=\s*yaml\.(?:Safe|Base|Full)Loader)""")

    # --- file upload ---
    UPLOAD_PY   = re.compile(r"""request\.files|save\s*\(|secure_filename|werkzeug\.utils""", re.I)
    UPLOAD_JS   = re.compile(r"""multer|busboy|formidable|multipart|req\.files""", re.I)
    UPLOAD_PHP  = re.compile(r"""\$_FILES|move_uploaded_file|getClientOriginalExtension""")
    UPLOAD_GO   = re.compile(r"""FormFile\(|SaveUploadedFile|MultipartForm""")
    EXEC_MIME   = re.compile(r"""\.php['"]|\.sh['"]|\.py['"]|\.exe['"]|\.cgi['"]""", re.I)

    # --- SSRF (outbound request on input) ---
    SSRF_PY     = re.compile(r"""requests\.(get|post|put|delete|head|request)\s*\(|urllib\.request\.(urlopen|Request)""", re.I)
    SSRF_JS     = re.compile(r"""axios\.|fetch\(|http\.get\(|https\.get\(|request\(""")
    SSRF_INPUT  = re.compile(r"""request\.|req\.|params\.|query\.|body\.|args\.|form\.|data\[""", re.I)

    # --- GraphQL ---
    GRAPHQL_EP  = re.compile(r"""/graphql|graphiql|@strawberry|graphene\.Schema|makeExecutableSchema""", re.I)

    # --- XPath ---
    XPATH       = re.compile(r"""\.xpath\s*\(|etree\.XPath|lxml.*xpath|xpath\.find|selectNodes|evaluate\s*\(.*XPath""", re.I)

    # --- Path traversal ---
    PATH_TRAV   = re.compile(r"""open\s*\(|os\.path\.join\s*\(|Path\s*\(|send_file\s*\(|readFile\s*\(|fs\.read""", re.I)
    PATH_INPUT  = re.compile(r"""request\.|req\.|args\.|query\.|params\.|form\.""", re.I)

    # --- LDAP ---
    LDAP        = re.compile(r"""ldap3|python-ldap|ldap\.open|ldap\.initialize|ldap\.search|\.search_s\(""", re.I)

    # --- DB presence (credentials) ---
    DB_URL      = re.compile(
        r"""(?:DATABASE_URL|DB_URL|DB_HOST|MONGO_URI|REDIS_URL|POSTGRES_URI|MYSQL_URL|sqlite:///|mongodb://|postgresql://|mysql://|redis://)""",
        re.I,
    )
    DB_CONN     = re.compile(r"""connect\s*\(\s*['"]|psycopg2|pymysql|sqlite3\.connect|MongoClient\(""", re.I)


# ---------------------------------------------------------------------------
# Detector core
# ---------------------------------------------------------------------------

class StackDetector:
    def __init__(self, service_root: str, service_name: str, report_dir: str):
        self.root = Path(service_root).resolve()
        self.service = service_name
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self._reset()

    def _reset(self):
        self._stack: dict[str, Any] = {
            "language": "unknown",
            "framework": None,
            "has_php": False,
            "has_symfony_twig": False,
            "has_grpc": False,
            "grpc_proto_files": [],
            "has_file_upload": False,
            "file_upload_locations": [],
            "has_sql_queries": False,
            "sql_query_locations": [],
            "has_nosql": False,
            "nosql_locations": [],
            "uses_jwt": False,
            "jwt_verification_locations": [],
            "has_eval_on_input": False,
            "eval_locations": [],
            "db_present_in_domain": False,
            "has_outbound_request_on_input": False,
            "ssrf_locations": [],
            "has_graphql_endpoint": False,
            "graphql_locations": [],
            "has_xpath_parser": False,
            "xpath_locations": [],
            "has_file_path_from_input": False,
            "path_traversal_locations": [],
            "has_ldap_query": False,
            "ldap_locations": [],
        }
        self._ext_count: dict[str, int] = {}
        self._fw_hits: dict[str, int] = {}

    def _add_location(self, key: str, file: str, line: int, **extra):
        """Append a file:line hit to a *_locations list and flip the boolean."""
        bool_key = key  # e.g. "has_sql_queries"
        loc_key = key.replace("has_", "", 1) + "_locations"
        # handle irregular names
        _MAP = {
            "has_sql_queries": "sql_query_locations",
            "has_nosql": "nosql_locations",
            "uses_jwt": "jwt_verification_locations",
            "has_eval_on_input": "eval_locations",
            "has_outbound_request_on_input": "ssrf_locations",
            "has_graphql_endpoint": "graphql_locations",
            "has_file_upload": "file_upload_locations",
        }
        loc_key = _MAP.get(key, key.lstrip("has_").lstrip("uses_") + "_locations")
        if loc_key not in self._stack:
            loc_key = key + "_locations"
        loc = {"file": file, "line": line}
        loc.update(extra)
        if bool_key in self._stack:
            self._stack[bool_key] = True
        if loc_key in self._stack:
            # Deduplicate by (file, line)
            existing = {(l["file"], l["line"]) for l in self._stack[loc_key]}
            if (file, line) not in existing:
                self._stack[loc_key].append(loc)

    def run(self) -> dict:
        self._reset()
        for fpath in self._walk():
            self._process_file(fpath)
        self._finalize_language()
        self._finalize_framework()
        out = self.report_dir / "detected_stack.json"
        out.write_text(json.dumps(self._stack, indent=2))
        logger.info("StackDetector → %s", out)
        return self._stack

    # -----------------------------------------------------------------------
    # Walk helpers
    # -----------------------------------------------------------------------

    def _walk(self):
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fname in filenames:
                yield Path(dirpath) / fname

    def _process_file(self, fpath: Path):
        ext = fpath.suffix.lower()
        self._ext_count[ext] = self._ext_count.get(ext, 0) + 1
        rel = str(fpath.relative_to(self.root))

        # .proto → gRPC
        if ext == ".proto":
            self._stack["has_grpc"] = True
            if rel not in self._stack["grpc_proto_files"]:
                self._stack["grpc_proto_files"].append(rel)
            return
        # .php
        if ext == ".php":
            self._stack["has_php"] = True

        # Binary / non-text skip
        if ext not in {".py", ".js", ".ts", ".mjs", ".php", ".go", ".rb", ".java",
                       ".cs", ".rs", ".jsx", ".tsx", ".yml", ".yaml", ".env",
                       ".cfg", ".ini", ".toml", ".txt", ".json", ".xml", ".twig", ".html"}:
            return

        try:
            src = fpath.read_text(errors="replace")
        except Exception:
            return

        lines = src.splitlines()
        self._detect_framework_hints(src, rel)
        self._detect_twig(src, rel)
        self._detect_sql(lines, rel)
        self._detect_nosql(lines, rel, src)
        self._detect_jwt(lines, rel)
        self._detect_eval(lines, rel, ext)
        self._detect_upload(lines, rel, ext)
        self._detect_ssrf(lines, rel, ext)
        self._detect_graphql(lines, rel)
        self._detect_xpath(lines, rel)
        self._detect_path_traversal(lines, rel, ext)
        self._detect_ldap(lines, rel)
        self._detect_db_presence(src, rel)

    # -----------------------------------------------------------------------
    # Per-category detectors
    # -----------------------------------------------------------------------

    def _detect_framework_hints(self, src: str, rel: str):
        for name, pat in [
            ("flask", _RE.FLASK), ("django", _RE.DJANGO), ("fastapi", _RE.FASTAPI),
            ("express", _RE.EXPRESS), ("symfony", _RE.SYMFONY), ("laravel", _RE.LARAVEL),
            ("gin", _RE.GIN), ("graphql_fw", _RE.GRAPHQL_FW),
        ]:
            if pat.search(src):
                self._fw_hits[name] = self._fw_hits.get(name, 0) + 1

    def _detect_twig(self, src: str, rel: str):
        if _RE.TWIG.search(src) or rel.endswith(".twig"):
            self._stack["has_symfony_twig"] = True

    def _detect_sql(self, lines: list[str], rel: str):
        for i, line in enumerate(lines):
            if _RE.SQL_RAW.search(line) or _RE.SQL_ORM_RAW.search(line):
                self._add_location("has_sql_queries", rel, i + 1)

    def _detect_nosql(self, lines: list[str], rel: str, src: str):
        if not (_RE.NOSQL_MONGO.search(src) or _RE.NOSQL_REDIS.search(src)):
            return
        for i, line in enumerate(lines):
            if _RE.NOSQL_FIND.search(line) or _RE.NOSQL_REDIS.search(line):
                self._add_location("has_nosql", rel, i + 1)

    def _detect_jwt(self, lines: list[str], rel: str):
        in_jwt_context = False
        for i, line in enumerate(lines):
            if _RE.JWT_IMPORT.search(line):
                in_jwt_context = True
                # Classify weakness
                looks_weak = False
                weak_reason = None
                if _RE.JWT_WEAK_NONE.search(line):
                    looks_weak, weak_reason = True, "alg_none"
                elif _RE.JWT_WEAK_VER.search(line):
                    looks_weak, weak_reason = True, "verify_disabled"
                elif _RE.JWT_WEAK_SECRET.search(line):
                    looks_weak, weak_reason = True, "weak_secret"
                loc = {"file": rel, "line": i + 1, "looks_weak": looks_weak, "weak_reason": weak_reason}
                existing = {(l["file"], l["line"]) for l in self._stack["jwt_verification_locations"]}
                if (rel, i + 1) not in existing:
                    self._stack["uses_jwt"] = True
                    self._stack["jwt_verification_locations"].append(loc)
            elif in_jwt_context and (_RE.JWT_WEAK_NONE.search(line) or _RE.JWT_WEAK_VER.search(line)):
                # weakness on nearby line: annotate last JWT location
                if self._stack["jwt_verification_locations"]:
                    last = self._stack["jwt_verification_locations"][-1]
                    if not last["looks_weak"]:
                        last["looks_weak"] = True
                        last["weak_reason"] = (
                            "alg_none" if _RE.JWT_WEAK_NONE.search(line) else "verify_disabled"
                        )

    def _detect_eval(self, lines: list[str], rel: str, ext: str):
        if ext not in {".py"}:
            return
        for i, line in enumerate(lines):
            m = _RE.EVAL_EXEC.search(line) or _RE.PICKLE.search(line) or _RE.YAML_LOAD.search(line)
            if m:
                sink = "eval" if "eval" in line else "exec" if "exec" in line else \
                       "pickle.loads" if "pickle" in line else "yaml.load"
                self._add_location("has_eval_on_input", rel, i + 1, sink=sink)

    def _detect_upload(self, lines: list[str], rel: str, ext: str):
        for i, line in enumerate(lines):
            hit = False
            if ext == ".py" and _RE.UPLOAD_PY.search(line):
                hit = True
            elif ext in {".js", ".ts", ".mjs"} and _RE.UPLOAD_JS.search(line):
                hit = True
            elif ext == ".php" and _RE.UPLOAD_PHP.search(line):
                hit = True
            elif ext == ".go" and _RE.UPLOAD_GO.search(line):
                hit = True
            if hit:
                accepts_exec = bool(_RE.EXEC_MIME.search(line))
                self._add_location("has_file_upload", rel, i + 1, accepts_executable=accepts_exec)

    def _detect_ssrf(self, lines: list[str], rel: str, ext: str):
        """SSRF: outbound HTTP call where the URL might come from user input (same function context)."""
        for i, line in enumerate(lines):
            is_outbound = False
            if ext == ".py" and _RE.SSRF_PY.search(line):
                is_outbound = True
            elif ext in {".js", ".ts", ".mjs"} and _RE.SSRF_JS.search(line):
                is_outbound = True
            if not is_outbound:
                continue
            # Heuristic: scan surrounding ±8 lines for request/user-input reference
            window_start = max(0, i - 8)
            context = "\n".join(lines[window_start: i + 2])
            if _RE.SSRF_INPUT.search(context):
                self._add_location("has_outbound_request_on_input", rel, i + 1)

    def _detect_graphql(self, lines: list[str], rel: str):
        for i, line in enumerate(lines):
            if _RE.GRAPHQL_EP.search(line) or _RE.GRAPHQL_FW.search(line):
                self._add_location("has_graphql_endpoint", rel, i + 1)

    def _detect_xpath(self, lines: list[str], rel: str):
        for i, line in enumerate(lines):
            if _RE.XPATH.search(line):
                self._add_location("has_xpath_parser", rel, i + 1)

    def _detect_path_traversal(self, lines: list[str], rel: str, ext: str):
        for i, line in enumerate(lines):
            if _RE.PATH_TRAV.search(line):
                # Heuristic: is the argument constructed from user input?
                window_start = max(0, i - 5)
                context = "\n".join(lines[window_start: i + 2])
                if _RE.PATH_INPUT.search(context):
                    self._add_location("has_file_path_from_input", rel, i + 1)

    def _detect_ldap(self, lines: list[str], rel: str):
        for i, line in enumerate(lines):
            if _RE.LDAP.search(line):
                self._add_location("has_ldap_query", rel, i + 1)

    def _detect_db_presence(self, src: str, rel: str):
        if _RE.DB_URL.search(src) or _RE.DB_CONN.search(src):
            self._stack["db_present_in_domain"] = True

    # -----------------------------------------------------------------------
    # Finalize
    # -----------------------------------------------------------------------

    def _finalize_language(self):
        if not self._ext_count:
            return
        order = [
            (".py", "python"), (".js", "javascript"), (".ts", "javascript"),
            (".php", "php"), (".go", "go"), (".rb", "ruby"),
            (".java", "java"), (".cs", "csharp"), (".rs", "rust"),
        ]
        best_ext, best_count = max(
            ((e, self._ext_count.get(e, 0)) for e, _ in order),
            key=lambda x: x[1],
        )
        for ext, lang in order:
            if ext == best_ext:
                self._stack["language"] = lang
                break

    def _finalize_framework(self):
        priority = [
            ("fastapi", "fastapi"), ("flask", "flask"), ("django", "django"),
            ("symfony", "symfony"), ("laravel", "laravel"),
            ("express", "express"), ("gin", "gin"),
        ]
        for key, label in priority:
            if self._fw_hits.get(key, 0) > 0:
                self._stack["framework"] = label
                break
        # Symfony implies Twig by default
        if self._stack["framework"] == "symfony":
            self._stack["has_symfony_twig"] = True


# ---------------------------------------------------------------------------
# Runner interface
# ---------------------------------------------------------------------------

def run(service_root: str, service_name: str, report_dir: str, settings: dict | None = None) -> dict:
    import datetime

    t0 = time.monotonic()
    detector = StackDetector(service_root, service_name, report_dir)
    try:
        stack = detector.run()
        status, skip_reason = "completed", None
        findings = [
            {
                "type": "stack_flag",
                "file": None, "line": None,
                "endpoint": None, "method": None,
                "confidence": "high",
                "detail": f"{k}={v}" if not isinstance(v, list) else f"{k}: {len(v)} locations",
                "source_module": "stack_detector",
                "requires_manual_review": False,
                "unlikely_path": False,
            }
            for k, v in stack.items()
            if isinstance(v, bool) and v
        ]
    except Exception as exc:
        findings = []
        status, skip_reason = "error", str(exc)
        logger.exception("stack_detector failed")

    report = {
        "module": "stack_detector",
        "service": service_name,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "status": status,
        "skip_reason": skip_reason,
        "findings": findings,
    }
    (Path(report_dir) / "stack_detector.json").write_text(json.dumps(report, indent=2))
    logger.info("stack_detector done in %.1fs", time.monotonic() - t0)
    return report
