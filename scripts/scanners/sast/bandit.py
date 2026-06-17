"""Bandit adapter — SAST (Python). https://github.com/PyCQA/bandit

PyCQA's Python security linter (AST-based). Adds deep Python coverage alongside
Semgrep + the built-in AI-insecure-default rules.
Registered into the scanner registry; returns None when the binary is absent.

stdlib only.
"""

from __future__ import annotations

from typing import Optional

from external_tools import _which
from scanners.registry import ScanContext, ToolAdapter, finding, register, run_json

_INSTALL = "pip install bandit"

# Bandit test_id → CWE number, for the overlaps with our canonical AI-insecure
# rules + semgrep/gosec, so the same weakness at one line collapses cross-tool.
# (Only the common security checks; unmapped tests dedup by rule_key instead.)
_BANDIT_CWE = {
    "B102": "94", "B307": "95",                       # exec / eval
    "B201": "94",                                       # flask debug=True
    "B602": "78", "B603": "78", "B604": "78",          # subprocess shell
    "B605": "78", "B606": "78", "B607": "78", "B609": "78",
    "B608": "89",                                       # SQL injection
    "B303": "327", "B304": "327", "B305": "327", "B324": "327",  # weak crypto
    "B301": "502", "B302": "502", "B506": "502",        # insecure deserialization
    "B311": "330",                                       # insecure random
    "B105": "798", "B106": "798", "B107": "798",        # hardcoded credentials
    "B104": "605",                                       # bind all interfaces
    "B501": "295", "B502": "295", "B503": "295",        # TLS verification
}


def parse(data) -> list:
    """`bandit -f json` → {"results": [{filename, line_number, issue_severity,
    issue_text, test_id, more_info, ...}]}."""
    out = []
    for r in (data or {}).get("results", []) or []:
        tid = r.get("test_id", "")
        name = r.get("test_name", "")
        out.append(finding(
            r.get("issue_severity", "MEDIUM"),
            f"{r.get('issue_text', name) or tid}" + (f" [{tid}]" if tid else ""),
            (r.get("issue_text", "") or name) +
            f"\nconfidence: {r.get('issue_confidence', '')}  test: {name}",
            r.get("filename", ""), int(r.get("line_number") or 0),
            r.get("more_info", "") or "Apply the secure pattern this Bandit rule describes.",
            "bandit", rule_key=tid, cwe_id=_BANDIT_CWE.get(tid, "")))
    return out


def run(ctx: ScanContext) -> Optional[list]:
    if not _which("bandit"):
        return None
    # -r recurse, -f json to stdout, -q quiet. Non-zero exit on findings is fine.
    return run_json(ctx, ["bandit", "-r", str(ctx.root), "-f", "json", "-q"],
                    parse, gate=("*.py",))


register(ToolAdapter(name="bandit", scan_type="sast", binary="bandit",
                     run=run, install=_INSTALL, ci_install="pip install bandit"))
