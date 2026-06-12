"""V2 tests for the anti-slopsquatting impl (scanners.packages.slopsquatting,
re-exported by scripts/check_packages.py) — scan() behavior, false-positive
controls, import->package mapping, JS globbing, and outage=warn gating."""

import http.client

from scanners.packages import slopsquatting as cp  # patches must hit scan()'s own namespace


def _w(tmp_path, name, body):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return p


def test_scan_ignores_relative_and_first_party(tmp_path, monkeypatch):
    _w(tmp_path, "myapp/__init__.py", "")
    _w(tmp_path, "myapp/main.py",
       "from . import helpers\nfrom myapp.auth import login\nimport requests\n")
    seen = []
    monkeypatch.setattr(cp, "pypi_status", lambda pkg, **k: seen.append(pkg) or "exists")
    res = cp.scan(tmp_path)
    assert "requests" in seen
    assert "myapp" not in seen          # first-party package, not checked
    assert res["blocked"] == []


def test_scan_maps_import_name_to_distribution(tmp_path, monkeypatch):
    _w(tmp_path, "a.py", "import PIL\nimport yaml\nimport cv2\n")
    seen = []
    monkeypatch.setattr(cp, "pypi_status", lambda pkg, **k: seen.append(pkg) or "exists")
    cp.scan(tmp_path)
    assert {"pillow", "PyYAML", "opencv-python"} <= set(seen)
    assert "PIL" not in seen and "yaml" not in seen


def test_nested_first_party_module_not_checked(tmp_path, monkeypatch):
    # A foo.py anywhere in the tree means `import foo` resolves locally.
    _w(tmp_path, "scripts/blast_radius.py", "x = 1\n")
    _w(tmp_path, "tests/test_x.py", "import blast_radius\nimport requests\n")
    seen = []
    monkeypatch.setattr(cp, "pypi_status", lambda pkg, **k: seen.append(pkg) or "exists")
    cp.scan(tmp_path)
    assert "blast_radius" not in seen          # first-party, nested
    assert "requests" in seen


def test_js_node_builtins_and_host_modules_ignored(tmp_path, monkeypatch):
    _w(tmp_path, "ext.ts",
       "import * as fs from 'fs'\n"
       "import * as path from 'path'\n"
       "import { spawn } from 'node:child_process'\n"
       "import * as vscode from 'vscode'\n"
       "import express from 'express'\n")
    seen = []
    monkeypatch.setattr(cp, "npm_status", lambda pkg, **k: seen.append(pkg) or "exists")
    cp.scan(tmp_path)
    assert seen == ["express"]                 # builtins + vscode skipped


def test_scan_finds_js_ts_imports(tmp_path, monkeypatch):
    # The old brace-glob bug meant JS/TS scanning matched nothing.
    _w(tmp_path, "x.ts", "import express from 'express'\nimport './local'\n")
    _w(tmp_path, "y.jsx", "const r = require('react')\n")
    seen = []
    monkeypatch.setattr(cp, "npm_status", lambda pkg, **k: seen.append(pkg) or "exists")
    cp.scan(tmp_path)
    assert set(seen) == {"express", "react"}   # './local' relative import skipped


def test_scan_scoped_npm_package_reduced_to_base(tmp_path, monkeypatch):
    _w(tmp_path, "x.ts", "import { x } from '@scope/pkg/sub'\n")
    seen = []
    monkeypatch.setattr(cp, "npm_status", lambda pkg, **k: seen.append(pkg) or "exists")
    cp.scan(tmp_path)
    assert seen == ["@scope/pkg"]


def test_js_multiline_string_not_extracted(tmp_path):
    # A require()/import string that runs across lines must NOT be captured as
    # a package name. It used to build a registry URL containing newlines and
    # crash urllib with http.client.InvalidURL.
    bad = _w(tmp_path, "bad.js",
             "const x = require('\n"
             "  if (config.application.social.twitterUrl) {\n"
             "    this.tweetText += config.application.social.twitterUrl.replace('\n")
    names = cp.extract_js_imports(bad)
    assert all(" " not in n and "\n" not in n for n in names)


def test_scan_does_not_crash_on_malformed_js(tmp_path, monkeypatch):
    _w(tmp_path, "bad.js",
       "const x = require('\n  if (cfg.url) { t += cfg.url.replace('\n")
    _w(tmp_path, "ok.js", "import express from 'express'\n")
    seen = []
    monkeypatch.setattr(cp, "npm_status", lambda pkg, **k: seen.append(pkg) or "exists")
    res = cp.scan(tmp_path)                         # must not raise
    assert "express" in seen
    assert all(" " not in s and "\n" not in s for s in seen)
    assert res["blocked"] == []


def test_query_invalid_url_is_treated_as_error(monkeypatch):
    # http.client.InvalidURL is an HTTPException (NOT a ValueError) — the gate
    # must treat it as a registry error, never let it propagate.
    def boom(*a, **k):
        raise http.client.InvalidURL("URL can't contain control characters. '/\\n'")

    monkeypatch.setattr(cp.urllib.request, "urlopen", boom)
    assert cp._query("https://x", attempts=1, backoff=0) == "error"


def test_node_prefixed_imports_never_hit_npm(tmp_path, monkeypatch):
    # `node:` is reserved for core modules and can't be an npm package — even
    # newer builtins missing from NODE_BUILTINS (test, sqlite) must be skipped,
    # not queried (a query 404s and used to hard-block valid code).
    _w(tmp_path, "x.ts",
       "import { test } from 'node:test'\nimport sq from 'node:sqlite'\n")
    seen = []
    monkeypatch.setattr(cp, "npm_status", lambda pkg, **k: seen.append(pkg) or "exists")
    res = cp.scan(tmp_path)
    assert seen == []
    assert res["blocked"] == []


def test_scan_blocks_missing_warns_on_outage(tmp_path, monkeypatch):
    _w(tmp_path, "a.py", "import realpkg\nimport fakepkg\nimport flakypkg\n")
    status = {"realpkg": "exists", "fakepkg": "missing", "flakypkg": "error"}
    monkeypatch.setattr(cp, "pypi_status", lambda pkg, **k: status[pkg])
    res = cp.scan(tmp_path)
    assert [b["package"] for b in res["blocked"]] == ["fakepkg"]
    assert [w["package"] for w in res["warnings"]] == ["flakypkg"]


def test_main_blocks_on_missing(tmp_path, monkeypatch):
    _w(tmp_path, "a.py", "import fakepkg\n")
    monkeypatch.setattr(cp, "pypi_status", lambda pkg, **k: "missing")
    assert cp.main([str(tmp_path)]) == 1


def test_main_outage_does_not_block(tmp_path, monkeypatch):
    _w(tmp_path, "a.py", "import flaky\n")
    monkeypatch.setattr(cp, "pypi_status", lambda pkg, **k: "error")
    assert cp.main([str(tmp_path)]) == 0     # registry outage warns, never blocks


def test_main_writes_json(tmp_path, monkeypatch):
    _w(tmp_path, "a.py", "import fakepkg\n")
    monkeypatch.setattr(cp, "pypi_status", lambda pkg, **k: "missing")
    out = tmp_path / "report.json"
    cp.main([str(tmp_path), "--json", str(out)])
    import json
    data = json.loads(out.read_text())
    assert data["blocked"][0]["package"] == "fakepkg"


def test_query_retries_then_errors_without_real_sleep(monkeypatch):
    import urllib.error
    calls = {"n": 0}

    def boom(*a, **k):
        calls["n"] += 1
        raise urllib.error.URLError("down")

    monkeypatch.setattr(cp.urllib.request, "urlopen", boom)
    assert cp._query("https://x", attempts=3, backoff=0) == "error"
    assert calls["n"] == 3          # retried


def test_query_404_is_missing_no_retry(monkeypatch):
    import urllib.error
    calls = {"n": 0}

    def nf(*a, **k):
        calls["n"] += 1
        raise urllib.error.HTTPError("u", 404, "nf", {}, None)

    monkeypatch.setattr(cp.urllib.request, "urlopen", nf)
    assert cp._query("https://x", attempts=3, backoff=0) == "missing"
    assert calls["n"] == 1          # 404 is definitive — no retry
