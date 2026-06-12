"""detect-secrets adapter — secrets. https://github.com/Yelp/detect-secrets

Yelp's plugin-based secret scanner (entropy + keyword + provider plugins). Runs
the working tree and reports each detected secret by file + line.
Registered into the scanner registry; returns None when the binary is absent.

stdlib only.
"""

from __future__ import annotations

from typing import Optional

from external_tools import _which
from scanners.registry import ScanContext, ToolAdapter, finding, register, run_json

_INSTALL = "pip install detect-secrets"


def parse(data) -> list:
    """`detect-secrets scan` → {"results": {file: [{type, line_number, ...}]}}."""
    out = []
    for file, secrets in ((data or {}).get("results", {}) or {}).items():
        for s in secrets or []:
            kind = s.get("type", "Secret")
            verified = s.get("is_verified")
            out.append(finding(
                "CRITICAL" if verified else "HIGH",
                f"Potential secret: {kind}",
                f"detect-secrets flagged a '{kind}' here. Confirm it isn't a real "
                "credential; if it is, rotate it.",
                file, int(s.get("line_number") or 0),
                "Remove the secret, load it from the environment / a secrets manager, and rotate it.",
                "detect-secrets"))
    return out


def run(ctx: ScanContext) -> Optional[list]:
    if not _which("detect-secrets"):
        return None
    # `scan <path>` walks the tree and prints a baseline JSON to stdout.
    return run_json(ctx, ["detect-secrets", "scan", str(ctx.root)], parse)


register(ToolAdapter(name="detect-secrets", scan_type="secrets", binary="detect-secrets",
                     run=run, install=_INSTALL, ci_install="pip install detect-secrets"))
