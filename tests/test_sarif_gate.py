"""Tests for scripts/sarif_gate.py — the severity-aware SARIF gate."""

import json

import sarif_gate as sg


def _sarif(tmp_path, name, results, rules=None):
    doc = {
        "runs": [
            {
                "tool": {"driver": {"rules": rules or []}},
                "results": results,
            }
        ]
    }
    p = tmp_path / name
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(p)


def _run(path, fail_on_warnings, monkeypatch):
    monkeypatch.setenv("FAIL_ON_WARNINGS", "true" if fail_on_warnings else "false")
    return sg.main([path, "--label", "Semgrep"])


# ── error-level findings always block ────────────────────────────────────────

def test_error_blocks_even_when_flag_off(tmp_path, monkeypatch):
    path = _sarif(tmp_path, "e.sarif", [{"ruleId": "sql-injection-fstring", "level": "error"}])
    assert _run(path, fail_on_warnings=False, monkeypatch=monkeypatch) == 1


def test_suppressed_error_is_ignored(tmp_path, monkeypatch):
    # A nosemgrep-suppressed finding carries a SARIF `suppressions` entry and
    # must not gate the build.
    path = _sarif(tmp_path, "sup.sarif", [
        {"ruleId": "detect-child-process", "level": "error",
         "suppressions": [{"kind": "inSource"}]},
    ])
    assert _run(path, fail_on_warnings=False, monkeypatch=monkeypatch) == 0


def test_rejected_suppression_still_gates(tmp_path, monkeypatch):
    # A `rejected` suppression was NOT applied, so the finding must still block.
    path = _sarif(tmp_path, "rej.sarif", [
        {"ruleId": "x", "level": "error",
         "suppressions": [{"kind": "external", "status": "rejected"}]},
    ])
    assert _run(path, fail_on_warnings=False, monkeypatch=monkeypatch) == 1


def test_error_blocks_when_flag_on(tmp_path, monkeypatch):
    path = _sarif(tmp_path, "e.sarif", [{"ruleId": "tls-verify-false", "level": "error"}])
    assert _run(path, fail_on_warnings=True, monkeypatch=monkeypatch) == 1


# ── warning-level findings gated by the flag ─────────────────────────────────

def test_warning_does_not_block_by_default(tmp_path, monkeypatch):
    path = _sarif(tmp_path, "w.sarif", [{"ruleId": "wildcard-cors", "level": "warning"}])
    assert _run(path, fail_on_warnings=False, monkeypatch=monkeypatch) == 0


def test_warning_blocks_when_flag_on(tmp_path, monkeypatch):
    path = _sarif(tmp_path, "w.sarif", [{"ruleId": "wildcard-cors", "level": "warning"}])
    assert _run(path, fail_on_warnings=True, monkeypatch=monkeypatch) == 1


# ── level falls back to the rule's default configuration ─────────────────────

def test_level_falls_back_to_rule_default(tmp_path, monkeypatch):
    path = _sarif(
        tmp_path,
        "r.sarif",
        [{"ruleId": "wildcard-cors"}],  # no per-result level
        rules=[{"id": "wildcard-cors", "defaultConfiguration": {"level": "warning"}}],
    )
    assert _run(path, fail_on_warnings=False, monkeypatch=monkeypatch) == 0
    assert _run(path, fail_on_warnings=True, monkeypatch=monkeypatch) == 1


# ── clean and missing inputs ─────────────────────────────────────────────────

def test_clean_sarif_passes(tmp_path, monkeypatch):
    path = _sarif(tmp_path, "c.sarif", [])
    assert _run(path, fail_on_warnings=True, monkeypatch=monkeypatch) == 0


def test_missing_file_is_treated_as_clean(tmp_path, monkeypatch):
    missing = str(tmp_path / "nope.sarif")
    assert _run(missing, fail_on_warnings=True, monkeypatch=monkeypatch) == 0


def test_truthy_env_values(tmp_path, monkeypatch):
    path = _sarif(tmp_path, "w.sarif", [{"ruleId": "wildcard-cors", "level": "warning"}])
    for val in ("1", "yes", "on", "TRUE"):
        monkeypatch.setenv("FAIL_ON_WARNINGS", val)
        assert sg.main([path, "--label", "Semgrep"]) == 1
