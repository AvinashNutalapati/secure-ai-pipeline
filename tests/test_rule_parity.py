"""Cross-channel rule parity.

The canonical scanner rules live once, per scan type, under scripts/scanners/.
scripts/gen_rules.py emits the cross-language mirrors (the Semgrep ruleset + the
VS Code rule table) from that source; the Python channels import it directly.

These tests FAIL if a canonical rule isn't reflected in the MCP server, the
Semgrep ruleset, or the VS Code extension, AND if the generated mirrors are
stale relative to the source — so "edit in one place, regenerate" is enforced,
not just hoped.
"""

import re
from pathlib import Path

import gen_rules
from scanners.sast.ai_insecure_defaults import SAST_REGEX_RULES
from scanners.sca.known_cves import KNOWN_CVES

ROOT = Path(__file__).resolve().parent.parent
CANONICAL_SAST = {r[0] for r in SAST_REGEX_RULES}


def _ids_in(path, pattern):
    text = (ROOT / path).read_text(encoding="utf-8")
    return set(re.findall(pattern, text, re.MULTILINE))


def test_canonical_sast_rules_present_in_semgrep():
    semgrep_ids = _ids_in(".semgrep/ai-insecure-defaults.yml", r"^\s*- id:\s*(\S+)")
    missing = CANONICAL_SAST - semgrep_ids
    assert not missing, f"SAST rules missing from the Semgrep ruleset: {missing}"


def test_canonical_sast_rules_present_in_vscode():
    # The VS Code rules table is generated from the canonical catalog; ids live
    # in rules.generated.ts (diagnostics.ts only holds the fix functions).
    ts_ids = _ids_in("extensions/vscode/src/rules.generated.ts", r'id:\s*"([^"]+)"')
    missing = CANONICAL_SAST - ts_ids
    assert not missing, f"SAST rules missing from the VS Code extension: {missing}"


def test_generated_mirrors_not_stale():
    # gen_rules --check exits non-zero if the on-disk Semgrep YAML / VS Code
    # table differ from what the canonical catalog would emit right now.
    assert gen_rules.main(["--check"]) == 0, (
        "Generated mirrors are stale — run `python scripts/gen_rules.py` and commit"
    )


def test_canonical_sast_rules_present_in_mcp():
    from extensions.claude_mcp import rules as mcp_rules
    mcp_ids = {r.rule_id for r in mcp_rules.SAST_RULES}
    missing = CANONICAL_SAST - mcp_ids
    assert not missing, f"SAST rules missing from the MCP server: {missing}"


def test_known_cves_match_mcp():
    from extensions.claude_mcp import rules as mcp_rules
    assert set(KNOWN_CVES) == set(mcp_rules.KNOWN_CVES), \
        "KNOWN_CVES drifted between scanners/sca/known_cves.py and the MCP server"
