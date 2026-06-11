"""Tests for scripts/run_pipeline.py — the local gate runner."""

import run_pipeline as rp


def _write(tmp_path, name, body):
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def _sast_rule_ids(tmp_path, code):
    src = _write(tmp_path, "snippet.py", code)
    return {f.rule_id for f in rp.stage1_sast(src)}


# ── SAST rules fire on bad code, stay quiet on clean code ────────────────────

def test_tls_verify_false_fires(tmp_path):
    assert "tls-verify-false" in _sast_rule_ids(
        tmp_path, "resp = requests.get(url, verify=False)\n"
    )


def test_tls_verify_clean(tmp_path):
    assert "tls-verify-false" not in _sast_rule_ids(
        tmp_path, "resp = requests.get(url)\n"
    )


def test_flask_debug_true_fires(tmp_path):
    assert "flask-debug-true" in _sast_rule_ids(
        tmp_path, "app.run(host='0.0.0.0', debug=True)\n"
    )


def test_flask_debug_clean(tmp_path):
    assert "flask-debug-true" not in _sast_rule_ids(
        tmp_path, "app.run(host='0.0.0.0')\n"
    )


def test_sql_injection_fstring_fires(tmp_path):
    assert "sql-injection-fstring" in _sast_rule_ids(
        tmp_path, 'cursor.execute(f"SELECT * FROM t WHERE n=\'{name}\'")\n'
    )


def test_sql_injection_clean(tmp_path):
    assert "sql-injection-fstring" not in _sast_rule_ids(
        tmp_path, 'cursor.execute("SELECT * FROM t WHERE n=?", (name,))\n'
    )


# ── requirements parser ──────────────────────────────────────────────────────

def test_requirements_parser_handles_comments_and_blanks(tmp_path):
    req = _write(
        tmp_path,
        "requirements.txt",
        "# a comment\n\nFlask==1.0\n  requests==2.18.0  # inline\nflask-cors==3.0.10\n",
    )
    parsed = rp.parse_requirements(req)
    assert ("flask", "1.0") in parsed
    assert ("requests", "2.18.0") in parsed
    # Hyphen normalised to underscore.
    assert ("flask_cors", "3.0.10") in parsed
    # Comment / blank lines produced no entries.
    assert len(parsed) == 3


# ── CVE lookup ───────────────────────────────────────────────────────────────

def test_cve_lookup_for_flask_1_0(tmp_path):
    req = _write(tmp_path, "requirements.txt", "Flask==1.0\n")
    cves = {f.rule_id for f in rp.stage1_sca(req)}
    assert "CVE-2023-30861" in cves
    assert "CVE-2018-1000656" in cves


def test_clean_requirements_no_cves(tmp_path):
    req = _write(tmp_path, "requirements.txt", "flask==3.0.0\n")
    # flask 3.0.0 is real (no CVE entry) and recognised, so no findings.
    assert rp.stage1_sca(req) == []


# ── blocking decision (exit-code logic) ──────────────────────────────────────

def test_blocking_when_vulnerable(tmp_path):
    src = _write(tmp_path, "app.py", "app.run(debug=True)\n")
    req = _write(tmp_path, "requirements.txt", "Flask==1.0\n")
    findings = rp.stage1_sast(src) + rp.stage1_sca(req)
    assert any(f.action == "BLOCK" for f in findings)


def test_not_blocking_when_clean(tmp_path):
    src = _write(tmp_path, "app.py", "app.run(host='0.0.0.0')\n")
    req = _write(tmp_path, "requirements.txt", "flask==3.0.0\n")
    findings = (
        rp.stage0_packages(src)
        + rp.stage0_secrets(src)
        + rp.stage1_sast(src)
        + rp.stage1_sca(req)
    )
    assert not any(f.action == "BLOCK" for f in findings)


# ── regression: review fixes ─────────────────────────────────────────────────

def test_relative_imports_not_flagged(tmp_path):
    # `from .utils import x` resolves locally — never a registry package.
    src = _write(tmp_path, "mod.py", "from .utils import helper\nfrom . import other\n")
    assert rp.stage0_packages(src) == []


def test_unknown_import_warns_never_blocks(tmp_path):
    # scrapy is real but outside the offline list — the offline heuristic must
    # WARN (verify with check_packages), never hard-block a real package.
    src = _write(tmp_path, "app.py", "import scrapy\n")
    findings = rp.stage0_packages(src)
    assert [f.rule_id for f in findings] == ["unverified-package"]
    assert findings[0].action == "WARN"


def test_stdlib_shared_with_check_packages(tmp_path):
    # These broke the old duplicated stdlib copy (it was missing ~40 modules).
    src = _write(tmp_path, "app.py", "import fnmatch\nimport shlex\nimport select\n")
    assert rp.stage0_packages(src) == []


def test_secret_value_containing_example_still_blocks(tmp_path):
    # Substring placeholder matching let real keys through; only WHOLE-value
    # placeholders may be skipped.
    src = _write(tmp_path, "app.py", 'api_key = "examplecorp_prod_8f3a9b2c11dd"\n')
    assert "hardcoded-api-key" in {f.rule_id for f in rp.stage0_secrets(src)}


def test_placeholder_values_skipped(tmp_path):
    src = _write(tmp_path, "app.py",
                 'api_key = "your_api_key_here"\ntoken = "placeholder"\n')
    assert rp.stage0_secrets(src) == []


def test_parameterized_percent_s_is_clean(tmp_path):
    # The canonical SAFE form — the rule's own fix text recommends it.
    assert "sql-injection-fstring" not in _sast_rule_ids(
        tmp_path, 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
    )


def test_percent_operator_after_string_fires(tmp_path):
    assert "sql-injection-fstring" in _sast_rule_ids(
        tmp_path, 'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)\n'
    )


def test_missing_requirements_path_warns(tmp_path):
    # A typo'd path must say "SCA skipped", not print a green PASS.
    findings = rp.stage1_sca(tmp_path / "nope.txt")
    assert [f.rule_id for f in findings] == ["requirements-not-found"]
    assert findings[0].action == "WARN"
