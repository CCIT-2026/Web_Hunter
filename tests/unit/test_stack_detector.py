"""Unit test: stack_detector."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pytest
from orchestrator.stack_detector import StackDetector, _RE


# ── Regex checks ─────────────────────────────────────────────────────────────

def test_sql_raw():
    assert _RE.SQL_RAW.search("cursor.execute(\"SELECT * FROM users WHERE id=%s\", (uid,))")
    assert _RE.SQL_RAW.search("db.execute('INSERT INTO logs VALUES (?)', (val,))")
    assert not _RE.SQL_RAW.search("print('hello')")

def test_jwt_weak_verify_false():
    assert _RE.JWT_WEAK_VER.search("options={\"verify_signature\": False}")
    assert _RE.JWT_WEAK_VER.search("verify = False")
    assert not _RE.JWT_WEAK_VER.search("verify = True")

def test_jwt_alg_none():
    assert _RE.JWT_WEAK_NONE.search("algorithms=['none']")
    assert _RE.JWT_WEAK_NONE.search("algorithm='none'")
    assert not _RE.JWT_WEAK_NONE.search("algorithms=['HS256']")

def test_eval_on_input():
    assert _RE.EVAL_EXEC.search("result = eval(user_input)")
    assert _RE.PICKLE.search("obj = pickle.loads(data)")
    assert _RE.YAML_LOAD.search("yaml.load(stream)")
    assert not _RE.YAML_LOAD.search("yaml.load(stream, Loader=yaml.SafeLoader)")

def test_ssrf_pattern():
    assert _RE.SSRF_PY.search("response = requests.get(target_url)")
    assert _RE.SSRF_PY.search("urllib.request.urlopen(url)")

def test_upload_py():
    assert _RE.UPLOAD_PY.search("f = request.files.get('upload')")
    assert _RE.UPLOAD_PHP.search("move_uploaded_file($_FILES['f']['tmp_name'], $dest)")

def test_nosql():
    assert _RE.NOSQL_FIND.search("result = db.collection.find({'user': username})")
    assert _RE.NOSQL_MONGO.search("import pymongo")


# ── Stack detection from fixtures ─────────────────────────────────────────────

def test_detect_flask_sqli_fixture(tmp_path):
    fixture = Path(__file__).parent.parent / "fixtures" / "flask_sqli"
    if not fixture.exists():
        pytest.skip("fixture not found")
    det = StackDetector(str(fixture), "flask_sqli", str(tmp_path))
    stack = det.run()

    assert stack["language"] == "python"
    assert stack["framework"] == "flask"
    assert stack["has_sql_queries"] is True
    assert len(stack["sql_query_locations"]) >= 1
    assert stack["uses_jwt"] is True
    # The fixture has verify=False → should be detected as weak
    weak = [l for l in stack["jwt_verification_locations"] if l["looks_weak"]]
    assert len(weak) >= 1

def test_detect_flask_eval_fixture(tmp_path):
    fixture = Path(__file__).parent.parent / "fixtures" / "flask_eval"
    if not fixture.exists():
        pytest.skip("fixture not found")
    det = StackDetector(str(fixture), "flask_eval", str(tmp_path))
    stack = det.run()

    assert stack["has_eval_on_input"] is True
    sinks = [l["sink"] for l in stack["eval_locations"]]
    assert "eval" in sinks
    assert "pickle.loads" in sinks
    assert stack["has_file_upload"] is True
    assert stack["has_file_path_from_input"] is True

def test_detect_node_express_fixture(tmp_path):
    fixture = Path(__file__).parent.parent / "fixtures" / "node_express"
    if not fixture.exists():
        pytest.skip("fixture not found")
    det = StackDetector(str(fixture), "node_express", str(tmp_path))
    stack = det.run()

    assert stack["language"] == "javascript"
    assert stack["has_nosql"] is True

def test_detect_php_symfony_fixture(tmp_path):
    fixture = Path(__file__).parent.parent / "fixtures" / "php_symfony"
    if not fixture.exists():
        pytest.skip("fixture not found")
    det = StackDetector(str(fixture), "php_symfony", str(tmp_path))
    stack = det.run()

    assert stack["has_php"] is True
    assert stack["has_symfony_twig"] is True
    assert stack["has_sql_queries"] is True

def test_detect_go_grpc_fixture(tmp_path):
    fixture = Path(__file__).parent.parent / "fixtures" / "go_grpc"
    if not fixture.exists():
        pytest.skip("fixture not found")
    det = StackDetector(str(fixture), "go_grpc", str(tmp_path))
    stack = det.run()

    assert stack["language"] == "go"
    assert stack["has_grpc"] is True
    assert "service.proto" in stack["grpc_proto_files"]
    assert stack["has_outbound_request_on_input"] is True
