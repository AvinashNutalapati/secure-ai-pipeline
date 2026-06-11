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
    # Per-type prompt + combined prompt, both copy-paste code blocks.
    assert "Copy the fix prompt for Dependencies (Trivy SCA)" in md
    assert "## 🤖 Fix everything — one prompt" in md
    assert md.count("```text") >= 2


def test_build_all_clear():
    md, _ = js.build([("secrets", "Secrets", None)])
    assert "All clear" in md
    assert "Fix everything" not in md


def test_main_writes_step_summary_and_exits_zero(tmp_path, monkeypatch):
    p = _w(tmp_path, "t.sarif", _sarif([_result("CVE-9", "error", "Fixed Version: 2.0")]))
    summ = tmp_path / "sum.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summ))
    assert js.main(["--scan", "sca", "SCA", p]) == 0
    assert "2.0" in summ.read_text(encoding="utf-8")


def test_main_never_fails_on_missing(tmp_path):
    assert js.main(["--scan", "sast", "SAST", str(tmp_path / "nope.sarif")]) == 0
