"""Brakeman adapter — SAST (Ruby on Rails). https://brakemanscanner.org

Static analysis for Rails apps (SQLi, XSS, mass-assignment, unsafe redirects, …).
Only runs when the repo has Ruby; most repos have none, so it stays quiet.
Registered into the scanner registry; returns None when the binary is absent.

stdlib only.
"""

from __future__ import annotations

from typing import Optional

from external_tools import _which
from scanners.registry import ScanContext, ToolAdapter, finding, register, run_json

_INSTALL = "gem install brakeman"

# Brakeman reports confidence, not severity — map it.
_CONFIDENCE = {"High": "HIGH", "Medium": "MEDIUM", "Weak": "LOW"}

# Brakeman warning_type → CWE number, so a Rails flaw collapses cross-tool by
# weakness (same key shape as bandit/gosec/semgrep). Unmapped types dedup by rule_key.
_BRAKEMAN_CWE = {
    "SQL Injection": "89", "Command Injection": "78", "Cross-Site Scripting": "79",
    "Cross Site Scripting": "79", "Mass Assignment": "915", "Remote Code Execution": "94",
    "Dangerous Eval": "95", "File Access": "22", "Path Traversal": "22",
    "Redirect": "601", "Cross-Site Request Forgery": "352", "Dangerous Send": "94",
    "Format Validation": "20", "Session Setting": "1004",
}


def parse(data) -> list:
    """`brakeman -f json` → {"warnings": [{warning_type, message, file, line,
    confidence, link, ...}]}."""
    out = []
    for w in (data or {}).get("warnings", []) or []:
        wtype = w.get("warning_type", "")
        msg = w.get("message", "")
        out.append(finding(
            _CONFIDENCE.get(w.get("confidence", ""), "MEDIUM"),
            f"{wtype}: {msg}"[:120] if wtype else (msg or "Brakeman warning"),
            f"{msg}\nconfidence: {w.get('confidence', '')}  check: {w.get('check_name', '')}",
            w.get("file", ""), int(w.get("line") or 0),
            w.get("link", "") or "Apply the secure Rails pattern Brakeman describes.",
            "brakeman", rule_key=w.get("check_name", "") or wtype,
            cwe_id=_BRAKEMAN_CWE.get(wtype, "")))
    return out


def run(ctx: ScanContext) -> Optional[list]:
    if not _which("brakeman"):
        return None
    return run_json(ctx, ["brakeman", "-f", "json", "-q", "--no-progress", str(ctx.root)],
                    parse, gate=("Gemfile", "*.rb"))


register(ToolAdapter(name="brakeman", scan_type="sast", binary="brakeman",
                     run=run, install=_INSTALL, ci_install="gem install brakeman"))
