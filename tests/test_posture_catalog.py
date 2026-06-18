"""Tests for the cross-channel posture-rule catalog (E3).

The catalog is the single source of truth for AI-workflow posture-rule metadata;
gen_rules ships it into the MCP bundle. These guard that it stays well-formed and
in sync across channels.
"""

from scanners.posture.catalog import POSTURE_RULES, POSTURE_RULE_IDS

_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def test_catalog_well_formed():
    ids = [r["id"] for r in POSTURE_RULES]
    assert len(ids) == len(set(ids)), "duplicate rule ids in the posture catalog"
    for r in POSTURE_RULES:
        assert set(r) == {"id", "category", "severity", "title"}, f"bad keys: {r}"
        assert r["severity"] in _SEVERITIES, f"bad severity: {r}"
        assert r["id"] and r["category"] and r["title"]


def test_catalog_covers_key_rules():
    # The distinctive AI-security rules must be catalogued (cross-channel visibility).
    must = {
        "ai-unicode-tag", "mcp-tool-poisoning", "mcp-cross-server-exfil",
        "integrity-drift", "ai-exfiltration-compound", "gha-prtarget-untrusted-checkout",
        "pkg-known-malicious", "pkg-typosquat-suspect", "ai-ide-prompt-injection",
        "claude-broad-read",
    }
    missing = must - POSTURE_RULE_IDS
    assert not missing, f"key posture rules missing from catalog: {missing}"


def test_catalog_shipped_to_mcp_bundle_in_sync():
    # gen_rules --check enforces freshness; this asserts the bundled copy matches.
    from extensions.claude_mcp._rules_data import POSTURE_RULES as bundled
    assert bundled == POSTURE_RULES, "MCP bundle posture catalog drifted — run gen_rules.py"


def test_mcp_posture_catalog_helper():
    # The data behind the list_posture_checks MCP tool (testable without the mcp SDK).
    from extensions.claude_mcp import rules
    full = rules.posture_catalog()
    assert full["count"] == len(POSTURE_RULES)
    assert "MCP" in full["categories"]
    # every grouped entry is a compact {id, severity, title}
    for rows in full["categories"].values():
        for r in rows:
            assert set(r) == {"id", "severity", "title"}
    # category filter is a case-insensitive substring
    mcp_only = rules.posture_catalog("mcp")
    assert mcp_only["count"] >= 1
    assert set(mcp_only["categories"]) == {"MCP"}
    assert mcp_only["count"] < full["count"]
    assert rules.posture_catalog("no-such-category")["count"] == 0
