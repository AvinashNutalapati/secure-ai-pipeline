"""Tests for extensions/claude_mcp/rules.py — the shared MCP/REST scan engine."""

from extensions.claude_mcp import rules


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
