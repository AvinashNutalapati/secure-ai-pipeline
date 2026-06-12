"""Bandit adapter — SAST (Python). https://github.com/PyCQA/bandit

PyCQA's Python security linter (AST-based). Adds deep Python coverage alongside
Semgrep + the built-in AI-insecure-default rules.
Registered into the scanner registry; returns None when the binary is absent.

stdlib only.
"""

from __future__ import annotations

import json
from typing import Optional

from external_tools import _run, _which
from scanners.registry import ScanContext, ToolAdapter, finding, has_files, register

_INSTALL = "pip install bandit"


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
            "bandit"))
    return out


def run(ctx: ScanContext) -> Optional[list]:
    if not _which("bandit"):
        return None
    if not has_files(ctx.root, "*.py"):
        return []
    # -r recurse, -f json to stdout, -q quiet. Non-zero exit on findings is fine.
    proc = _run(["bandit", "-r", str(ctx.root), "-f", "json", "-q"])
    if proc is None:
        return []
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return []
    return parse(data)


register(ToolAdapter(name="bandit", scan_type="sast", binary="bandit",
                     run=run, install=_INSTALL, ci_install="pip install bandit"))
