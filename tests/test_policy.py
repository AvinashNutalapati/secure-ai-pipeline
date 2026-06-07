"""Tests for scripts/policy.py — YAML-subset parsing, loading, and application."""

import json

import policy as pol


SAMPLE = """\
# a comment
fail_on:
  - critical
  - high
ignore:
  - gha-unpinned-action
github_actions:
  require_sha_pinning: true
  block_pull_request_target: false
mcp:
  allowed_servers:
    - github-readonly
    - docs-search
inline: [a, b, c]
"""


def test_parse_yaml_subset():
    d = pol.parse_yaml_subset(SAMPLE)
    assert d["fail_on"] == ["critical", "high"]
    assert d["ignore"] == ["gha-unpinned-action"]
    assert d["github_actions"]["require_sha_pinning"] is True
    assert d["github_actions"]["block_pull_request_target"] is False
    assert d["mcp"]["allowed_servers"] == ["github-readonly", "docs-search"]
    assert d["inline"] == ["a", "b", "c"]


def test_parse_example_policy_file(tmp_path):
    src = __import__("pathlib").Path(__file__).resolve().parent.parent
    text = (src / "examples" / "secure-ai-pipeline.example.yml").read_text()
    d = pol.parse_yaml_subset(text)
    assert "critical" in d["fail_on"]
    assert d["github_actions"]["require_sha_pinning"] is True


def test_load_defaults_when_missing_is_report_only(tmp_path):
    p = pol.load_policy(tmp_path)
    assert p["fail_on"] == []          # no policy file → never gates
    assert p["github_actions"]["require_sha_pinning"] is True


def test_load_json_policy_merges(tmp_path):
    (tmp_path / "secure-ai-pipeline.json").write_text(
        json.dumps({"fail_on": ["critical"], "mcp": {"allowed_servers": ["x"]}}))
    p = pol.load_policy(tmp_path)
    assert p["fail_on"] == ["critical"]
    assert p["mcp"]["allowed_servers"] == ["x"]
    # default github_actions still present via deep-merge
    assert p["github_actions"]["require_sha_pinning"] is True


def test_load_yaml_policy(tmp_path):
    (tmp_path / "secure-ai-pipeline.yml").write_text(SAMPLE)
    p = pol.load_policy(tmp_path)
    assert p["github_actions"]["block_pull_request_target"] is False


def _report(findings):
    return {"score": 0, "grade": "F", "counts": {}, "by_category": {}, "findings": findings}


def test_apply_suppresses_ignored_and_toggled():
    findings = [
        {"rule_id": "gha-unpinned-action", "severity": "HIGH", "category": "CI/CD",
         "title": "x", "detail": "", "fix": "", "file": "w.yml", "line": 1},
        {"rule_id": "gha-pull-request-target", "severity": "CRITICAL", "category": "CI/CD",
         "title": "x", "detail": "", "fix": "", "file": "w.yml", "line": 1},
        {"rule_id": "mcp-secret-env", "severity": "CRITICAL", "category": "MCP",
         "title": "x", "detail": "", "fix": "", "file": "mcp.json", "line": 0},
    ]
    policy = {
        "fail_on": ["critical"],
        "ignore": ["gha-unpinned-action"],
        "github_actions": {"require_sha_pinning": True, "block_pull_request_target": False},
        "mcp": {"allowed_servers": []},
    }
    out = pol.apply(_report(findings), policy)
    ids = {f["rule_id"] for f in out["findings"]}
    assert ids == {"mcp-secret-env"}                 # both gha findings dropped
    assert out["policy"]["gate_failed"] is True       # critical remains
    assert out["policy"]["triggered_by"] == ["CRITICAL"]
    assert out["score"] == 70                          # 100 - 30 for one critical


def test_apply_allowlist_flags_unlisted_server():
    findings = [
        {"rule_id": "mcp-server-inventory", "severity": "INFO", "category": "MCP",
         "title": "MCP server configured: sketchy", "detail": "", "fix": "",
         "file": "mcp.json", "line": 0},
    ]
    policy = {"fail_on": ["high"], "ignore": [],
              "github_actions": {}, "mcp": {"allowed_servers": ["github-readonly"]}}
    out = pol.apply(_report(findings), policy)
    ids = {f["rule_id"] for f in out["findings"]}
    assert "mcp-server-not-allowlisted" in ids
    assert out["policy"]["gate_failed"] is True       # the new finding is HIGH


def test_apply_no_gate_when_clean():
    out = pol.apply(_report([]), {"fail_on": ["critical", "high"], "ignore": [],
                                  "github_actions": {}, "mcp": {}})
    assert out["policy"]["gate_failed"] is False
    assert out["score"] == 100
