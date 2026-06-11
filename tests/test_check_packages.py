"""Tests for scripts/check_packages.py — the anti-slopsquatting guard."""

import urllib.error
from unittest.mock import patch

import check_packages as cp


class _FakeResp:
    def __init__(self, status: int = 200):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _write(tmp_path, name, body):
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


# ── stdlib exclusion ─────────────────────────────────────────────────────────

def test_stdlib_names_excluded(tmp_path):
    src = _write(tmp_path, "a.py", "import os\nimport sys\nimport json\n")
    assert cp.extract_python_imports(src) == set()


def test_stdlib_constant_covers_common_modules():
    for mod in ("os", "sys", "json", "subprocess", "hashlib"):
        assert mod in cp.PYTHON_STDLIB


# ── import extraction ────────────────────────────────────────────────────────

def test_extract_plain_import(tmp_path):
    src = _write(tmp_path, "a.py", "import requests\n")
    assert cp.extract_python_imports(src) == {"requests"}


def test_extract_from_import_takes_top_level(tmp_path):
    src = _write(tmp_path, "a.py", "from foo.bar import baz\n")
    assert cp.extract_python_imports(src) == {"foo"}


def test_extract_aliased_import(tmp_path):
    src = _write(tmp_path, "a.py", "import numpy as np\n")
    assert cp.extract_python_imports(src) == {"numpy"}


def test_extract_multiple_and_dotted(tmp_path):
    src = _write(
        tmp_path,
        "a.py",
        "import os\nimport flask\nfrom requests.sessions import Session\n",
    )
    # os is stdlib and dropped; flask + requests remain.
    assert cp.extract_python_imports(src) == {"flask", "requests"}


def test_syntax_error_returns_empty(tmp_path):
    src = _write(tmp_path, "a.py", "import (((\n")
    assert cp.extract_python_imports(src) == set()


# ── registry existence checks (mocked — no real network) ─────────────────────

def test_known_good_package_passes():
    with patch.object(cp.urllib.request, "urlopen", return_value=_FakeResp(200)):
        assert cp.pypi_exists("requests") is True


def test_hallucinated_package_fails_on_404():
    err = urllib.error.HTTPError("u", 404, "Not Found", {}, None)
    with patch.object(cp.urllib.request, "urlopen", side_effect=err):
        assert cp.pypi_exists("flaskutils_ai") is False


def test_network_error_collapses_to_false_in_boolean_api():
    # The boolean back-compat wrapper can't express tri-state; the status API
    # reports "error" (WARN, never blocks) — see test_check_packages_v2.
    with patch.object(cp.urllib.request, "urlopen", side_effect=OSError("boom")):
        assert cp.pypi_exists("anything") is False


def test_npm_existence_uses_registry():
    with patch.object(cp.urllib.request, "urlopen", return_value=_FakeResp(200)):
        assert cp.npm_exists("express") is True
