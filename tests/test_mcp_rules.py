"""Tests for extensions/claude_mcp/rules.py — the shared MCP/REST scan engine."""

from extensions.claude_mcp import rules


# ── de-dup: the MCP engine INHERITS the canonical rules, never hand-copies ───

def test_rules_derived_from_canonical_catalog():
    from scanners.sast.ai_insecure_defaults import RULES as canon_sast
    from scanners.sca.known_cves import KNOWN_CVES as canon_cves
    # Every canonical SAST rule (incl. hardcoded-api-key via its JS trigger) is
    # present, and the CVE table matches the canonical — so they can't drift.
    assert {r.rule_id for r in rules.SAST_RULES} == {r["id"] for r in canon_sast}
    assert rules.KNOWN_CVES == canon_cves


def test_bundled_rules_data_matches_canonical():
    # The MCP/REST servers read from the bundled _rules_data.py (so they work
    # pip-installed, with no scripts/). It must equal the canonical source;
    # gen_rules.py --check (test_rule_parity) keeps it from going stale.
    from extensions.claude_mcp import _rules_data
    from scanners.sast.ai_insecure_defaults import RULES as canon_sast
    from scanners.sca.known_cves import KNOWN_CVES as canon_cves
    assert _rules_data.RULES == canon_sast
    assert _rules_data.KNOWN_CVES == canon_cves


# ── full_scan package semantics ──────────────────────────────────────────────

def test_full_scan_unknown_dep_warns_without_registry():
    # Without a registry checker, an unknown pinned dep is UNVERIFIED — a
    # 20-name allowlist is not grounds to call a real package non-existent.
    out = rules.full_scan(requirements="cryptography==42.0.5")
    assert out["blocked"] is False
    pkgs = out["findings"]["packages"]
    assert pkgs[0]["package"] == "cryptography"
    assert "verify" in pkgs[0]["warning"]


def test_full_scan_blocks_only_confirmed_missing():
    out = rules.full_scan(
        requirements="totallyfakepkg==1.0",
        check_registry=lambda pkg, reg: {"exists": False, "warning": "404"},
    )
    assert out["blocked"] is True

    # Unreachable registry (exists=None) must warn, never block.
    out2 = rules.full_scan(
        requirements="totallyfakepkg==1.0",
        check_registry=lambda pkg, reg: {"exists": None, "warning": "unreachable"},
    )
    assert out2["blocked"] is False
    assert out2["findings"]["packages"][0]["warning"] == "unreachable"


def test_full_scan_known_real_package_skips_registry():
    def explode(pkg, reg):
        raise AssertionError("known packages must not hit the registry")

    out = rules.full_scan(requirements="flask==3.0.0", check_registry=explode)
    assert out["blocked"] is False
    assert out["findings"]["packages"] == []


def test_full_scan_checker_crash_degrades_to_unverified():
    def boom(pkg, reg):
        raise RuntimeError("network stack on fire")

    out = rules.full_scan(requirements="somepkg==1.0", check_registry=boom)
    assert out["blocked"] is False
    assert "registry check failed" in out["findings"]["packages"][0]["warning"]


# ── SAST regression: parameterised SQL must stay clean ───────────────────────

def test_sqli_rule_ignores_parameterised_form():
    safe = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
    assert rules.sast_scan(safe) == []


def test_sqli_rule_fires_on_percent_operator():
    bad = 'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)\n'
    assert [f.rule for f in rules.sast_scan(bad)] == ["sql-injection-fstring"]


def test_requirements_parser_accepts_dotted_names():
    assert rules.parse_requirements("zope.interface==5.0\n") == [
        ("zope.interface", "5.0")
    ]


def test_sast_catches_uppercase_secret_names():
    # Regression: a leading \b in the trigger used to miss UPPER_SNAKE secret
    # names (OPENAI_API_KEY, DB_PASSWORD, AWS_SECRET) — the most common shape.
    for name in ("OPENAI_API_KEY", "DB_PASSWORD", "AWS_SECRET"):
        out = rules.sast_scan(f'{name} = "sk-proj-abcd1234efgh"')
        assert any(f.rule == "hardcoded-api-key" for f in out), name
    # A short value must still be ignored (the {8,} guard).
    assert rules.sast_scan('API_KEY = "x"') == []
