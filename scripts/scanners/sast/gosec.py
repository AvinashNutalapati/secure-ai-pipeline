"""gosec adapter — SAST (Go). https://github.com/securego/gosec

Go security checker (AST/SSA). Only runs when the repo actually contains Go;
most repos have none, so it stays quiet.
Registered into the scanner registry; returns None when the binary is absent.

stdlib only.
"""

from __future__ import annotations

from typing import Optional

from external_tools import _which
from scanners.registry import ScanContext, ToolAdapter, finding, register, run_json

_INSTALL = ("brew install gosec   (or: curl -sfL "
            "https://raw.githubusercontent.com/securego/gosec/master/install.sh | sh)")


def parse(data) -> list:
    """`gosec -fmt=json` → {"Issues": [{severity, rule_id, details, file, line,
    cwe, ...}]}. `line` is a string (may be a range like "10-12")."""
    out = []
    for i in (data or {}).get("Issues", []) or []:
        line = str(i.get("line", "0")).split("-")[0]
        cwe = (i.get("cwe", {}) or {}).get("id") or (i.get("cwe", {}) or {}).get("ID", "")
        rid = i.get("rule_id", "")
        out.append(finding(
            i.get("severity", "MEDIUM"),
            f"{i.get('details', '') or rid}" + (f" [{rid}]" if rid else ""),
            (i.get("details", "") or rid) +
            (f"\nCWE-{cwe}" if cwe else "") + f"\nconfidence: {i.get('confidence', '')}",
            i.get("file", ""), int(line) if line.isdigit() else 0,
            "Apply the secure Go idiom this gosec rule describes.",
            "gosec"))
    return out


def run(ctx: ScanContext) -> Optional[list]:
    if not _which("gosec"):
        return None
    # gosec takes Go package globs; run it from the repo root so ./... resolves.
    return run_json(ctx, ["gosec", "-fmt=json", "-quiet", "./..."],
                    parse, gate=("*.go",), cwd=ctx.root)


register(ToolAdapter(name="gosec", scan_type="sast", binary="gosec",
                     run=run, install=_INSTALL,
                     ci_install="curl -sfL https://raw.githubusercontent.com/securego/gosec/"
                                "master/install.sh | sh -s -- -b /usr/local/bin"))
