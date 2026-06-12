"""Tests for scripts/job_summary.py — the GitHub Actions job summary builder."""

import json

import job_summary as js


def _sarif(results, rules=None):
    return {"runs": [{"tool": {"driver": {"rules": rules or []}}, "results": results}]}


def _w(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


def _result(rid, level, text, uri="a", line=1):
    return {"ruleId": rid, "level": level, "message": {"text": text},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                                                "region": {"startLine": line}}}]}


def test_load_states(tmp_path):
    assert js.load(None) is None
    assert js.load(str(tmp_path / "missing.sarif")) is None
    assert js.load(_w(tmp_path, "clean.sarif", _sarif([]))) == []
    rows = js.load(_w(tmp_path, "f.sarif", _sarif([_result("R", "error", "boom")])))
    assert len(rows) == 1 and rows[0]["rule"] == "R"


def test_load_never_raises_on_bad_json(tmp_path):
    p = tmp_path / "bad.sarif"
    p.write_text("{not json", encoding="utf-8")
    assert js.load(str(p)) is None


# ── Trivy fixed-version extraction (the user's ask) ──────────────────────────

def test_sca_extracts_fixed_version():
    f = {"msg": "Package: lodash\nInstalled Version: 4.17.0\nFixed Version: 4.17.21",
         "rule": "CVE-1", "rule_obj": {}}
    title, fix = js.title_and_fix("sca", f)
    assert "lodash" in title and "4.17.0" in title and "CVE-1" in title
    assert fix == "Upgrade lodash to 4.17.21."


def test_sca_no_fixed_version():
    f = {"msg": "Package: x\nInstalled Version: 1.0", "rule": "CVE-2", "rule_obj": {}}
    _, fix = js.title_and_fix("sca", f)
    assert "No fixed version" in fix


def test_secrets_fix_says_rotate():
    _, fix = js.title_and_fix("secrets", {"msg": "AWS key", "rule": "aws", "rule_obj": {}})
    assert "rotate" in fix.lower()


# ── full summary: tables + per-type prompt + overall prompt ──────────────────

def test_build_has_tables_prompts_and_fix_versions(tmp_path):
    sca = _w(tmp_path, "trivy.sarif", _sarif([_result(
        "CVE-1", "error",
        "Package: lodash\nInstalled Version: 4.17.0\nFixed Version: 4.17.21",
        "package-lock.json", 1)]))
    sec = _w(tmp_path, "results.sarif", _sarif([]))
    md, log = js.build([("secrets", "Secrets (Gitleaks)", sec),
                        ("sca", "Dependencies (Trivy SCA)", sca)])
    # Secrets rendered in the same format (a section heading, clean state).
    assert "### Secrets (Gitleaks) — ✅ no findings" in md
    # SCA table with the fixed version as the suggested fix.
    assert "Dependencies (Trivy SCA) — ⚠️ 1 finding" in md
    assert "Upgrade lodash to 4.17.21." in md
    # Per-type prompt + combined prompt, both collapsible copy-paste code blocks.
    assert "Fix prompt — Dependencies (Trivy SCA)" in md
    assert "Fix everything" in md
    assert md.count("```text") == 2          # one per-type + one combined
    assert md.count("<details>") == 2        # both prompts are dropdowns


def test_clean_type_gets_no_prompt(tmp_path):
    # A scan type with no findings must NOT get a fix prompt (regression: SAST
    # with zero findings used to look like it had a copy of the SCA prompt).
    sast = _w(tmp_path, "semgrep.sarif", _sarif([]))
    sca = _w(tmp_path, "trivy.sarif", _sarif([_result("CVE-1", "error", "Fixed Version: 1.2")]))
    md, _ = js.build([("sast", "SAST (Semgrep)", sast),
                     ("sca", "Dependencies (Trivy SCA)", sca)])
    assert "SAST (Semgrep) — ✅ no findings" in md
    assert "Fix prompt — SAST" not in md                 # no SAST prompt
    assert md.count("Fix prompt —") == 1                 # only the SCA one


def test_build_all_clear():
    md, _ = js.build([("secrets", "Secrets", None)])
    assert "All clear" in md
    assert "Fix everything" not in md
    assert "Fix prompt" not in md


def test_main_writes_step_summary_and_exits_zero(tmp_path, monkeypatch):
    p = _w(tmp_path, "t.sarif", _sarif([_result("CVE-9", "error", "Fixed Version: 2.0")]))
    summ = tmp_path / "sum.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summ))
    assert js.main(["--scan", "sca", "SCA", p]) == 0
    assert "2.0" in summ.read_text(encoding="utf-8")


def test_main_never_fails_on_missing(tmp_path):
    assert js.main(["--scan", "sast", "SAST", str(tmp_path / "nope.sarif")]) == 0


# ── AI Blast Radius + anti-slopsquatting sections (the test-repo additions) ──

def test_load_blast_radius_maps_severity_and_drops_info(tmp_path):
    p = _w(tmp_path, "blast.json", {"findings": [
        {"severity": "CRITICAL", "rule_id": "gha-prt", "title": "pull_request_target",
         "fix": "Prefer pull_request.", "file": ".github/workflows/x.yml", "line": 4},
        {"severity": "MEDIUM", "rule_id": "gha-unpinned", "title": "unpinned",
         "fix": "Pin to SHA.", "file": "x.yml", "line": 1},
        {"severity": "INFO", "rule_id": "mcp-inv", "title": "inventory", "fix": "", "file": "m", "line": 0},
    ]})
    rows = js.load_blast_radius(p)
    assert [r["level"] for r in rows] == ["error", "warning"]   # INFO dropped
    title, fix = js.title_and_fix("ai_posture", rows[0])
    assert title == "pull_request_target" and fix == "Prefer pull_request."


def test_load_packages_blocked_is_error(tmp_path):
    p = _w(tmp_path, "pkg.json", {
        "blocked": [{"package": "flaskutils_ai", "import": "flaskutils_ai",
                     "registry": "pypi", "file": "app.py"}],
        "warnings": [{"package": "x", "registry": "npm", "file": "x.js", "reason": "unreachable"}],
        "ok": ["requests"]})
    rows = js.load_packages(p)
    assert rows[0]["level"] == "error" and "flaskutils_ai" in rows[0]["msg"]
    assert rows[1]["level"] == "note"
    title, fix = js.title_and_fix("packages", rows[0])
    assert "flaskutils_ai" in title and "verify the real package name" in fix


def test_build_renders_blast_radius_and_packages_sections(tmp_path):
    blast = _w(tmp_path, "b.json", {"findings": [
        {"severity": "HIGH", "rule_id": "r", "title": "Unpinned action",
         "fix": "Pin it.", "file": "ci.yml", "line": 2}]})
    pkgs = _w(tmp_path, "p.json", {"blocked": [
        {"package": "evilpkg", "registry": "pypi", "file": "app.py"}], "warnings": [], "ok": []})
    md, _ = js.build([("packages", "Dependency Trust (anti-slopsquatting)", pkgs),
                     ("ai_posture", "AI Workflow Blast Radius", blast)])
    assert "Dependency Trust (anti-slopsquatting) — ⚠️" in md
    assert "AI Workflow Blast Radius — ⚠️" in md
    assert "evilpkg" in md and "Unpinned action" in md
    assert "Fix prompt — AI Workflow Blast Radius" in md


def test_section_only_omits_header_and_combined_prompt(tmp_path):
    pkgs = _w(tmp_path, "p.json", {"blocked": [
        {"package": "evilpkg", "registry": "pypi", "file": "a"}], "warnings": [], "ok": []})
    md, _ = js.build([("packages", "Dependency Trust", pkgs)], section_only=True)
    assert "## 🔒 Secure AI Pipeline — results" not in md   # no top header
    assert "Fix everything" not in md                        # no combined prompt
    assert "Dependency Trust — ⚠️" in md                     # the section is present
