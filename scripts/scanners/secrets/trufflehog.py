"""TruffleHog adapter — secrets. https://github.com/trufflesecurity/trufflehog

Finds AND verifies leaked credentials. A verified secret is a confirmed live
credential → CRITICAL; an unverified match is still a likely secret → HIGH.
Registered into the scanner registry; returns None when the binary is absent.

stdlib only.
"""

from __future__ import annotations

import json
from typing import Optional

from external_tools import _run, _which
from scanners.registry import ScanContext, ToolAdapter, finding, register

_INSTALL = ("brew install trufflehog   (or: curl -sSfL "
            "https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh)")


def parse(stdout: str) -> list:
    """TruffleHog emits NDJSON — one result object per line. Non-result log
    lines (no DetectorName) are skipped."""
    out = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        detector = obj.get("DetectorName")
        if not detector:
            continue
        verified = bool(obj.get("Verified"))
        meta = (obj.get("SourceMetadata") or {}).get("Data", {}) or {}
        src = meta.get("Filesystem") or meta.get("Git") or meta.get("Directory") or {}
        file = src.get("file", "")
        line_no = int(src.get("line") or 0)
        out.append(finding(
            "CRITICAL" if verified else "HIGH",
            f"{'Verified' if verified else 'Potential'} secret: {detector}",
            ("TruffleHog " + ("VERIFIED this credential against the live provider — "
             "it works right now. " if verified else "matched this credential shape. ") +
             "Rotate it immediately; a leaked secret is valid until revoked."),
            file, line_no,
            "Remove the secret, load it from the environment / a secrets manager, and ROTATE it.",
            "trufflehog"))
    return out


def run(ctx: ScanContext) -> Optional[list]:
    if not _which("trufflehog"):
        return None
    proc = _run(["trufflehog", "filesystem", str(ctx.root),
                 "--json", "--no-update"])
    if proc is None:
        return []
    return parse(proc.stdout or "")


register(ToolAdapter(name="trufflehog", scan_type="secrets", binary="trufflehog",
                     run=run, install=_INSTALL,
                     ci_install="curl -sSfL https://raw.githubusercontent.com/trufflesecurity/"
                                "trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin"))
