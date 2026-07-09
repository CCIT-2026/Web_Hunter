"""
Integration test: orchestrator pipeline su fixture reali.
Verifica che:
  1. L'orchestratore triggeri solo i moduli attesi dato un detected_stack di esempio.
  2. Il parallelismo rispetti i lock (mutex groups non si sovrappongono).
  3. La payload library si carichi e restituisca candidati.
  4. Il Markdown report venga generato correttamente.
"""
import sys
import time
import threading
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pytest
from orchestrator.trigger_rules import modules_to_run, skipped_modules
from orchestrator.job_queue import JobQueue, DEFAULT_MUTEX_GROUPS


# ── 1. Trigger consistency ────────────────────────────────────────────────────

def _make_stack(**kwargs):
    base = {
        "language": "python", "framework": "flask",
        "has_php": False, "has_symfony_twig": False,
        "has_grpc": False, "grpc_proto_files": [],
        "has_file_upload": False, "file_upload_locations": [],
        "has_sql_queries": False, "sql_query_locations": [],
        "has_nosql": False, "nosql_locations": [],
        "uses_jwt": False, "jwt_verification_locations": [],
        "has_eval_on_input": False, "eval_locations": [],
        "db_present_in_domain": False,
        "has_outbound_request_on_input": False, "ssrf_locations": [],
        "has_graphql_endpoint": False, "graphql_locations": [],
        "has_xpath_parser": False, "xpath_locations": [],
        "has_file_path_from_input": False, "path_traversal_locations": [],
        "has_ldap_query": False, "ldap_locations": [],
    }
    base.update(kwargs)
    return base


def test_sqli_stack_triggers_sqlmap_ghauri_not_nosqli():
    stack = _make_stack(has_sql_queries=True)
    to_run = modules_to_run(stack)
    assert "sqlmap" in to_run
    assert "ghauri" in to_run
    assert "nosqli" not in to_run


def test_php_stack_triggers_phpggc():
    stack = _make_stack(has_php=True, has_symfony_twig=True)
    to_run = modules_to_run(stack)
    assert "phpggc" in to_run
    assert "symfony" in to_run
    assert "fickling" not in to_run  # language=python not PHP
    assert "nodejsscan" not in to_run


def test_secret_scan_only_when_db():
    no_db_stack = _make_stack(db_present_in_domain=False)
    db_stack = _make_stack(db_present_in_domain=True)
    assert "trufflehog" not in modules_to_run(no_db_stack)
    assert "gitleaks" not in modules_to_run(no_db_stack)
    assert "trufflehog" in modules_to_run(db_stack)
    assert "gitleaks" in modules_to_run(db_stack)


# ── 2. Mutex groups / parallelism ─────────────────────────────────────────────

def test_mutex_group_serializes_sqli_tools():
    """sqlmap and ghauri are in the same mutex group: they must not overlap."""
    execution_windows = {}
    lock = threading.Lock()

    def fake_runner(name, delay=0.1):
        start = time.monotonic()
        time.sleep(delay)
        end = time.monotonic()
        with lock:
            execution_windows[name] = (start, end)

    settings = {"max_workers": 4, "rate_limit_rps": None}
    queue = JobQueue(settings, mutex_groups=DEFAULT_MUTEX_GROUPS)
    queue.submit("sqlmap", fake_runner, "sqlmap", 0.1)
    queue.submit("ghauri", fake_runner, "ghauri", 0.1)
    queue.join()

    # Their execution windows must NOT overlap
    s1, e1 = execution_windows["sqlmap"]
    s2, e2 = execution_windows["ghauri"]
    overlaps = s1 < e2 and s2 < e1
    assert not overlaps, f"sqlmap [{s1:.3f},{e1:.3f}] and ghauri [{s2:.3f},{e2:.3f}] overlapped"


def test_independent_modules_run_in_parallel():
    """Modules in different mutex groups should overlap."""
    start_times = {}
    lock = threading.Lock()

    def slow_job(name):
        with lock:
            start_times[name] = time.monotonic()
        time.sleep(0.15)

    settings = {"max_workers": 4, "rate_limit_rps": None}
    queue = JobQueue(settings, mutex_groups={})  # no mutex groups
    queue.submit("semgrep", slow_job, "semgrep")
    queue.submit("nuclei", slow_job, "nuclei")
    total_start = time.monotonic()
    queue.join()
    total_elapsed = time.monotonic() - total_start
    # If they ran in parallel, total time < 2 * 0.15
    assert total_elapsed < 0.25, f"Expected parallel execution, got {total_elapsed:.3f}s"


# ── 3. Payload library ─────────────────────────────────────────────────────────

def test_payload_library_loads(tmp_path):
    lib_path = Path(__file__).parent.parent.parent.parent / "context" / "payloadsallthethings.json"
    if not lib_path.exists():
        pytest.skip("payloadsallthethings.json not available")
    from modules.payload_library.loader import get_library, PayloadLibrary
    # Reset singleton for test isolation
    PayloadLibrary._instance = None
    lib = get_library(str(lib_path))
    assert len(lib._raw) > 0
    sqli = lib.get_by_category("sqli")
    assert len(sqli) > 0

def test_selector_get_candidates(tmp_path):
    lib_path = Path(__file__).parent.parent.parent.parent / "context" / "payloadsallthethings.json"
    if not lib_path.exists():
        pytest.skip("payloadsallthethings.json not available")
    from modules.payload_library.loader import PayloadLibrary
    from modules.payload_library.selector import get_candidates
    PayloadLibrary._instance = None
    candidates = get_candidates("sqli", max_results=3, library_path=str(lib_path))
    assert len(candidates) <= 3
    assert all("payload" in c for c in candidates)

def test_selector_excludes_powershell(tmp_path):
    lib_path = Path(__file__).parent.parent.parent.parent / "context" / "payloadsallthethings.json"
    if not lib_path.exists():
        pytest.skip("payloadsallthethings.json not available")
    from modules.payload_library.loader import PayloadLibrary
    from modules.payload_library.selector import get_candidates
    PayloadLibrary._instance = None
    candidates = get_candidates(
        "command_injection", max_results=20,
        exclude_language="powershell",
        library_path=str(lib_path),
    )
    for c in candidates:
        lang = (c.get("language") or "").lower()
        payload = (c.get("payload") or "").lower()
        assert "powershell" not in lang and "powershell" not in payload


# ── 4. Markdown report generation ─────────────────────────────────────────────

def test_markdown_report_generated(tmp_path):
    import json, datetime
    # Write fake artifacts
    stack = {
        "language": "python", "framework": "flask",
        "has_php": False, "has_symfony_twig": False, "has_grpc": False,
        "grpc_proto_files": [], "has_file_upload": False, "file_upload_locations": [],
        "has_sql_queries": True, "sql_query_locations": [{"file": "app.py", "line": 42}],
        "has_nosql": False, "nosql_locations": [], "uses_jwt": False,
        "jwt_verification_locations": [], "has_eval_on_input": False, "eval_locations": [],
        "db_present_in_domain": False, "has_outbound_request_on_input": False,
        "ssrf_locations": [], "has_graphql_endpoint": False, "graphql_locations": [],
        "has_xpath_parser": False, "xpath_locations": [], "has_file_path_from_input": False,
        "path_traversal_locations": [], "has_ldap_query": False, "ldap_locations": [],
    }
    endpoints = [
        {"path": "/api/login", "method": "POST", "file": "app.py", "line": 10,
         "handler_function": "login", "params": [{"name": "username", "location": "body", "type": "string"}],
         "auth": None}
    ]
    sqlmap_report = {
        "module": "sqlmap", "service": "test", "status": "completed",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "skip_reason": None,
        "findings": [{"type": "sqli", "file": "app.py", "line": 42, "endpoint": "/api/login",
                       "method": "POST", "confidence": "high", "detail": "SQLi confirmed",
                       "source_module": "sqlmap", "requires_manual_review": False, "unlikely_path": False}],
    }
    (tmp_path / "detected_stack.json").write_text(json.dumps(stack))
    (tmp_path / "endpoints_map.json").write_text(json.dumps(endpoints))
    (tmp_path / "sqlmap.json").write_text(json.dumps(sqlmap_report))

    from modules.reporting.markdown_report import generate
    out = generate("test_service", str(tmp_path))

    content = out.read_text()
    assert "# test_service" in content
    assert "/api/login" in content
    assert "SQLi confirmed" in content
    assert "## Mapping" in content
    assert "## Injection — SQL (sqlmap)" in content
    # Skipped modules (empty stack flags) must NOT appear
    assert "PHP: N/A" not in content
    assert "phpggc" not in content.lower()
