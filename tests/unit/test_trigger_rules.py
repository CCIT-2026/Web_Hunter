"""Unit test: trigger_rules — verifica che la tabella TRIGGERS rispetti i contratti."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from orchestrator.trigger_rules import TRIGGERS, ALWAYS_RUN, UNGATED_DISCOVERY, modules_to_run, skipped_modules


def _empty_stack() -> dict:
    return {
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


def test_all_triggers_callable():
    stack = _empty_stack()
    for name, pred in TRIGGERS.items():
        result = pred(stack)
        assert isinstance(result, bool), f"TRIGGERS[{name!r}] must return bool, got {type(result)}"


def test_empty_stack_no_module_triggered():
    stack = _empty_stack()
    triggered = [name for name, pred in TRIGGERS.items() if pred(stack)]
    assert triggered == [], f"Expected no triggers on empty stack, got: {triggered}"


def test_sqli_triggers():
    stack = {**_empty_stack(), "has_sql_queries": True}
    assert TRIGGERS["sqlmap"](stack) is True
    assert TRIGGERS["ghauri"](stack) is True
    assert TRIGGERS["nosqli"](stack) is False  # has_sql_queries blocks nosqli


def test_nosqli_only_without_sql():
    stack = {**_empty_stack(), "has_nosql": True, "has_sql_queries": False}
    assert TRIGGERS["nosqli"](stack) is True

def test_nosqli_blocked_when_sql():
    stack = {**_empty_stack(), "has_nosql": True, "has_sql_queries": True}
    assert TRIGGERS["nosqli"](stack) is False


def test_jwt_tool_only_on_weak():
    weak_loc = {"file": "auth.py", "line": 10, "looks_weak": True, "weak_reason": "alg_none"}
    strong_loc = {"file": "auth.py", "line": 10, "looks_weak": False, "weak_reason": None}

    weak_stack = {**_empty_stack(), "uses_jwt": True, "jwt_verification_locations": [weak_loc]}
    strong_stack = {**_empty_stack(), "uses_jwt": True, "jwt_verification_locations": [strong_loc]}
    no_jwt_stack = _empty_stack()

    assert TRIGGERS["jwt_tool"](weak_stack) is True
    assert TRIGGERS["jwt_tool"](strong_stack) is False
    assert TRIGGERS["jwt_tool"](no_jwt_stack) is False


def test_phpggc_on_php_only():
    php_stack = {**_empty_stack(), "has_php": True}
    assert TRIGGERS["phpggc"](php_stack) is True
    assert TRIGGERS["phpggc"](_empty_stack()) is False


def test_fickling_python_only():
    py_eval = {**_empty_stack(), "language": "python", "has_eval_on_input": True}
    js_eval = {**_empty_stack(), "language": "javascript", "has_eval_on_input": True}
    assert TRIGGERS["fickling"](py_eval) is True
    assert TRIGGERS["fickling"](js_eval) is False


def test_exiftool_requires_executable():
    upload_exec = {
        **_empty_stack(),
        "has_file_upload": True,
        "file_upload_locations": [{"file": "a.py", "line": 1, "accepts_executable": True}],
    }
    upload_no_exec = {
        **_empty_stack(),
        "has_file_upload": True,
        "file_upload_locations": [{"file": "a.py", "line": 1, "accepts_executable": False}],
    }
    assert TRIGGERS["exiftool"](upload_exec) is True
    assert TRIGGERS["exiftool"](upload_no_exec) is False


def test_modules_to_run_always_includes_core():
    stack = _empty_stack()
    result = modules_to_run(stack)
    for m in ALWAYS_RUN:
        assert m in result
    for m in UNGATED_DISCOVERY:
        assert m in result


def test_skipped_modules_complement():
    stack = {**_empty_stack(), "has_sql_queries": True}
    to_run = modules_to_run(stack)
    skipped = skipped_modules(stack)
    # to_run and skipped together must cover all TRIGGERS keys
    trigger_keys = set(TRIGGERS.keys())
    run_set = set(to_run)
    skip_set = set(skipped.keys())
    assert trigger_keys == (run_set & trigger_keys) | (skip_set & trigger_keys)


def test_missing_stack_key_fails_closed():
    """A stack missing a key that a trigger reads must not activate that trigger."""
    incomplete = {"language": "python"}  # missing all flags
    for name, pred in TRIGGERS.items():
        result = pred(incomplete)
        assert result is False, f"TRIGGERS[{name!r}] should fail closed on incomplete stack"
