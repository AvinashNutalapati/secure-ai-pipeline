"""Tests for scripts/scan_all.py — the unified orchestrator + tabular UX."""

import scan_all as sa


def _w(tmp_path, rel, body):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return p


# ── built-in fallbacks ───────────────────────────────────────────────────────

def test_builtin_secrets_flags_provider_token_not_base64(tmp_path):
    _w(tmp_path, "a.js",
       "const t = 'ghp_0123456789abcdefghij0123456789abcd'\n"
       "const data = 'aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IGJsb2I1234='\n")
    findings = sa.builtin_secrets(tmp_path)
    titles = [f.title for f in findings]
    assert any("GitHub token" in t for t in titles)
    # The base64 blob must NOT be flagged — the generic high-entropy rule is
    # intentionally NOT used in the built-in fallback (false-positive flood).
    assert all("high-entropy" not in t.lower() for t in titles)


def test_builtin_secrets_skips_comment_lines(tmp_path):
    _w(tmp_path, "a.py", "# token = 'ghp_0123456789abcdefghij0123456789abcd'\n")
    assert sa.builtin_secrets(tmp_path) == []


def test_inline_suppression_silences_secret(tmp_path):
    _w(tmp_path, "a.py",
       "token = 'ghp_0123456789abcdefghij0123456789abcd'  # nosemgrep: known test fixture\n")
    assert sa.builtin_secrets(tmp_path) == []


def test_inline_suppression_silences_sast(tmp_path):
    _w(tmp_path, "app.py", "app.run(debug=True)  # nosec\n")
    assert sa.builtin_sast(tmp_path) == []


def test_builtin_sast_flags_insecure_python(tmp_path):
    _w(tmp_path, "app.py", "app.run(host='0.0.0.0', debug=True)\n")
    titles = " ".join(f.title for f in sa.builtin_sast(tmp_path))
    assert "Flask" in titles or "debug" in titles


def test_builtin_sast_skips_rule_source_files(tmp_path):
    # A rule-definition file (pattern strings that look insecure) must NOT be
    # flagged by the regex fallback — it carries the rule-source marker.
    _w(tmp_path, "catalog.py",
       '"""secure-ai-pipeline:rule-source"""\n'
       'PATTERNS = ["app.run(..., debug=True, ...)", "subprocess.x(..., shell=True)"]\n')
    assert sa.builtin_sast(tmp_path) == []
    # But the same code in a normal file IS flagged.
    _w(tmp_path, "real.py", "app.run(debug=True)\n")
    assert any("Flask" in f.title or "debug" in f.title for f in sa.builtin_sast(tmp_path))


def test_builtin_sca_offline_is_empty_without_requirements(tmp_path):
    _w(tmp_path, "app.py", "import os\n")
    assert sa.builtin_sca(tmp_path, offline=True) == []


def test_builtin_sca_curated_cve(tmp_path):
    _w(tmp_path, "requirements.txt", "Flask==1.0\n")
    findings = sa.builtin_sca(tmp_path, offline=True)
    assert any("CVE-2023-30861" in f.detail for f in findings)


def test_builtin_sca_drops_unknown_package_note(tmp_path):
    # An unverifiable package must NOT show in SCA with a bogus "Upgrade to a
    # patched release" fix — that's the packages layer's job (regression).
    _w(tmp_path, "requirements.txt", "totallyfakepkg==1.0\n")
    findings = sa.builtin_sca(tmp_path, offline=True)
    assert findings == []


def test_render_handles_whitespace_only_fix(tmp_path):
    # A finding whose fix/detail is whitespace-only must not crash any renderer
    # (regression: `'\\n'.strip().splitlines()[0]` was an IndexError).
    f = sa.ScanFinding("sast", "HIGH", "x", "  \n ", "a.py", 1, "\n  ", "tool")
    result = {"root": str(tmp_path), "layers": {"sast": sa.Layer("sast", "tool", [f])},
              "tools": {}}
    sa.render_detail(result, "sast", no_color=True)
    sa.render_html(result)
    sa.fix_prompt("sast", [f], str(tmp_path))
    sa.write_fix_prompts(result, tmp_path / ".sap")    # the default-run path


# ── orchestration ────────────────────────────────────────────────────────────

def test_orchestrate_only_subset(tmp_path):
    _w(tmp_path, "app.py", "app.run(debug=True)\n")
    result = sa.orchestrate(tmp_path, offline=True, only=["sast"])
    assert set(result["layers"]) == {"sast"}
    assert result["layers"]["sast"].engine == "built-in"   # no semgrep installed


def test_orchestrate_default_runs_all_non_dast(tmp_path):
    result = sa.orchestrate(tmp_path, offline=True, only=[])
    # The core layers (built-in scanners) always run. Tool-only layers like
    # iac/ci_cd appear when their scanner is installed (e.g. the Action installs
    # checkov/zizmor), so assert the guaranteed set as a subset to stay env-stable.
    assert {"secrets", "packages", "sca", "sast", "ai_posture"} <= set(result["layers"])
    assert "dast" not in result["layers"]                   # DAST only with a URL


def test_orchestrate_packages_layer_is_split_from_sca(tmp_path):
    # Slopsquatting now lives in its own 'packages' layer, not folded into sca.
    result = sa.orchestrate(tmp_path, offline=True, only=["packages", "sca"])
    assert "packages" in result["layers"] and "sca" in result["layers"]


def test_ai_posture_merges_external_adapter(tmp_path):
    # An external ai_posture adapter (e.g. mcp-scan) merges into the built-in
    # blast-radius layer rather than replacing it.
    from scanners import registry as reg
    fake = reg.ToolAdapter(
        "fake-mcp-xyz", "ai_posture", available_fn=lambda: True,
        run=lambda ctx: [reg.finding("HIGH", "tool poisoning", tool="fake-mcp-xyz")])
    reg.register(fake)
    try:
        layer = sa.orchestrate(tmp_path, offline=True, only=["ai_posture"])["layers"]["ai_posture"]
        assert "fake-mcp-xyz" in layer.engine and "built-in" in layer.engine
        assert any(f.title == "tool poisoning" for f in layer.findings)
    finally:
        reg._ADAPTERS.pop("fake-mcp-xyz", None)


def test_from_ext_normalizes_severity():
    rows = [{"severity": "error", "title": "x", "file": "a", "line": 3, "tool": "semgrep"}]
    out = sa._from_ext("sast", rows)
    assert out[0].severity == "HIGH" and out[0].scan_type == "sast" and out[0].line == 3


# ── rendering + fix prompts ──────────────────────────────────────────────────

def test_group_aggregates_by_title():
    fs = [sa.ScanFinding("sast", "HIGH", "A"), sa.ScanFinding("sast", "HIGH", "A"),
          sa.ScanFinding("sast", "MEDIUM", "B")]
    groups = sa._group(fs)
    assert ("HIGH", "A", 2) in groups and ("MEDIUM", "B", 1) in groups
    assert groups[0][0] == "HIGH"                           # critical/high first


def test_render_compact_runs_and_labels(tmp_path):
    _w(tmp_path, "app.py", "app.run(debug=True)\n")
    result = sa.orchestrate(tmp_path, offline=True, only=["sast", "secrets"])
    txt = sa.render_compact(result, no_color=True)
    assert "STATIC ANALYSIS" in txt and "SECRETS" in txt


def test_render_html_has_collapsible_sections(tmp_path):
    result = sa.orchestrate(tmp_path, offline=True, only=["sast"])
    out = sa.render_html(result)
    assert "<details" in out and "STATIC ANALYSIS" in out and "<!doctype html>" in out


def test_fix_prompt_contains_findings_and_role():
    f = sa.ScanFinding("sast", "HIGH", "SQL injection via f-string", "detail",
                       "app.py", 10, "use parameterised queries", "semgrep")
    text = sa.fix_prompt("sast", [f], "/repo")
    assert "SQL injection via f-string" in text
    assert "app.py:10" in text
    assert "security engineer" in text.lower()


def test_render_sarif_shape():
    result = {"layers": {"sast": sa.Layer("sast", "built-in", [
        sa.ScanFinding("sast", "HIGH", "SQL injection", "detail", "app.py", 10,
                       "use parameterised queries", "built-in"),
        sa.ScanFinding("sast", "INFO", "noise", "", "x", 0, "", "built-in")])}}
    doc = sa.render_sarif(result)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Secure AI Pipeline"
    assert len(run["results"]) == 1                       # INFO excluded
    res = run["results"][0]
    assert res["level"] == "error"
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 10
    assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "8.0"


def test_render_sarif_clamps_zero_line():
    result = {"layers": {"secrets": sa.Layer("secrets", "built-in", [
        sa.ScanFinding("secrets", "CRITICAL", "key", "", "a.env", 0, "rotate", "built-in")])}}
    res = sa.render_sarif(result)["runs"][0]["results"][0]
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 1  # SARIF needs >=1


def test_write_fix_prompts_only_for_layers_with_findings(tmp_path):
    _w(tmp_path, "app.py", "app.run(debug=True)\n")
    result = sa.orchestrate(tmp_path, offline=True, only=["sast", "sca"])
    written = sa.write_fix_prompts(result, tmp_path / ".sap")
    names = {p.name for p in written}
    assert "fix-sast.md" in names          # sast has a finding
    assert "fix-sca.md" not in names       # sca is clean offline → no prompt file
