"""Tests for scripts/sarif_summary.py — the report-only SARIF summarizer."""

import json

import sarif_summary as ss


def _sarif(results, rules=None):
    return {"runs": [{"tool": {"driver": {"rules": rules or []}}, "results": results}]}


def test_collect_sorts_by_severity():
    data = _sarif([
        {"ruleId": "w", "level": "warning", "message": {"text": "med"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a"},
                                             "region": {"startLine": 2}}}]},
        {"ruleId": "e", "level": "error", "message": {"text": "crit"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "b"},
                                             "region": {"startLine": 9}}}]},
    ])
    rows = ss.collect(data)
    assert [r[0] for r in rows] == ["error", "warning"]   # error first
    assert rows[0][1] == "e" and rows[0][3] == "b:9"


def test_level_falls_back_to_rule_default():
    data = _sarif(
        [{"ruleId": "r", "message": {"text": "x"}, "locations": []}],
        rules=[{"id": "r", "defaultConfiguration": {"level": "error"}}],
    )
    assert ss.collect(data)[0][0] == "error"


def test_main_missing_file_exits_zero(tmp_path, capsys):
    assert ss.main([str(tmp_path / "nope.sarif"), "--label", "X"]) == 0
    assert "no report produced" in capsys.readouterr().out


def test_main_writes_step_summary(tmp_path, monkeypatch, capsys):
    p = tmp_path / "x.sarif"
    p.write_text(json.dumps(_sarif(
        [{"ruleId": "CVE-1", "level": "error", "message": {"text": "boom"},
          "locations": [{"physicalLocation": {"artifactLocation": {"uri": "f"},
                                              "region": {"startLine": 1}}}]}])), encoding="utf-8")
    summ = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summ))
    assert ss.main([str(p), "--label", "SCA"]) == 0
    md = summ.read_text(encoding="utf-8")
    assert "SCA" in md and "CVE-1" in md and "| Severity |" in md


def test_main_never_fails_on_bad_json(tmp_path):
    p = tmp_path / "bad.sarif"
    p.write_text("{not json", encoding="utf-8")
    assert ss.main([str(p)]) == 0
