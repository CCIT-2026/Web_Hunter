"""Unit test: endpoint_parser extractors."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pytest
from modules.mapping.endpoint_parser import (
    _FlaskExtractor, _DjangoExtractor, _FastApiExtractor,
    _ExpressExtractor, _PhpExtractor, _GoExtractor,
    _path_params, EndpointParser,
)


# ── _path_params ─────────────────────────────────────────────────────────────

def test_path_params_flask():
    p = _path_params("/api/users/<int:id>")
    assert len(p) == 1
    assert p[0]["name"] == "id"
    assert p[0]["location"] == "path"

def test_path_params_express():
    p = _path_params("/api/users/:id/posts/:post_id")
    names = [x["name"] for x in p]
    assert "id" in names and "post_id" in names

def test_path_params_empty():
    assert _path_params("/api/login") == []


# ── Flask extractor ───────────────────────────────────────────────────────────

def test_flask_basic_route():
    src = """
@app.route('/api/login', methods=['GET', 'POST'])
def login():
    pass
"""
    eps = _FlaskExtractor().extract(src, "app.py")
    assert len(eps) == 2
    paths = [e["path"] for e in eps]
    assert "/api/login" in paths
    methods = {e["method"] for e in eps}
    assert methods == {"GET", "POST"}

def test_flask_auth_decorator():
    src = """
@login_required
@app.route('/admin')
def admin():
    pass
"""
    eps = _FlaskExtractor().extract(src, "app.py")
    assert len(eps) == 1
    assert eps[0]["auth"] is not None
    assert eps[0]["auth"]["required"] is True

def test_flask_verb_shorthand():
    src = """
@app.get('/api/health')
def health():
    pass

@app.post('/api/data')
def data():
    pass
"""
    eps = _FlaskExtractor().extract(src, "app.py")
    methods = {e["method"] for e in eps}
    assert "GET" in methods and "POST" in methods


# ── Django extractor ──────────────────────────────────────────────────────────

def test_django_path():
    src = """
urlpatterns = [
    path('api/login/', views.login, name='login'),
    re_path(r'^api/users/(?P<pk>[0-9]+)/$', views.UserDetail.as_view()),
]
"""
    eps = _DjangoExtractor().extract(src, "urls.py")
    assert len(eps) == 2
    paths = [e["path"] for e in eps]
    assert "api/login/" in paths


# ── FastAPI extractor ─────────────────────────────────────────────────────────

def test_fastapi_decorators():
    src = """
@app.get('/items/{item_id}')
async def read_item(item_id: int):
    pass

@router.post('/users/')
def create_user():
    pass
"""
    eps = _FastApiExtractor().extract(src, "main.py")
    assert any(e["method"] == "GET" for e in eps)
    assert any(e["method"] == "POST" for e in eps)
    # path param from /items/{item_id} should NOT be picked up (FastAPI uses {}, not <>/:)
    # We only pick up Flask/Express style — FastAPI params must be treated as fixed


# ── Express extractor ─────────────────────────────────────────────────────────

def test_express_basic():
    src = """
app.get('/api/health', (req, res) => res.json({ok: true}));
router.post('/api/login', authHandler);
app.all('/api/data', handler);
"""
    eps = _ExpressExtractor().extract(src, "app.js")
    methods = {e["method"] for e in eps}
    assert "GET" in methods
    assert "POST" in methods
    assert "ANY" in methods  # 'all' → ANY


# ── PHP extractor ─────────────────────────────────────────────────────────────

def test_php_symfony_attribute():
    src = """<?php
class LoginController {
    #[Route('/api/login', methods: ['GET', 'POST'])]
    public function login() {}
}
"""
    eps = _PhpExtractor().extract(src, "LoginController.php")
    assert len(eps) == 2
    methods = {e["method"] for e in eps}
    assert "GET" in methods and "POST" in methods

def test_php_laravel():
    src = """<?php
Route::get('/api/users', [UserController::class, 'index']);
Route::post('/api/login', 'AuthController@login');
"""
    eps = _PhpExtractor().extract(src, "web.php")
    assert any(e["method"] == "GET" for e in eps)
    assert any(e["method"] == "POST" for e in eps)


# ── Go extractor ──────────────────────────────────────────────────────────────

def test_go_gin():
    src = """
r.GET("/api/health", healthHandler)
r.POST("/api/data", dataHandler)
r.Any("/api/upload", uploadHandler)
"""
    eps = _GoExtractor().extract(src, "main.go")
    methods = {e["method"] for e in eps}
    assert "GET" in methods
    assert "POST" in methods


# ── Integration: parse fixture directory ─────────────────────────────────────

def test_parse_flask_sqli_fixture(tmp_path):
    fixture = Path(__file__).parent.parent / "fixtures" / "flask_sqli"
    if not fixture.exists():
        pytest.skip("fixture not found")
    parser = EndpointParser(str(fixture), "flask_sqli", str(tmp_path))
    eps = parser.run()
    assert len(eps) >= 2
    paths = [e["path"] for e in eps]
    assert "/api/login" in paths
    assert "/api/profile" in paths

def test_parse_php_symfony_fixture(tmp_path):
    fixture = Path(__file__).parent.parent / "fixtures" / "php_symfony"
    if not fixture.exists():
        pytest.skip("fixture not found")
    parser = EndpointParser(str(fixture), "php_symfony", str(tmp_path))
    eps = parser.run()
    assert any(e["path"] == "/api/login" for e in eps)
