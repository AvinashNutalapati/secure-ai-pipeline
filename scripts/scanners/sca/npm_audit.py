"""npm audit adapter — SCA (npm). https://docs.npmjs.com/cli/commands/npm-audit

Audits the npm dependency tree against the npm advisory database. npm ships with
Node, so this runs on any runner that has Node without an extra install. Audits
each package-lock.json in the repo (skips when there are none).
Registered into the scanner registry; returns None when npm is absent.

stdlib only.
"""

from __future__ import annotations

import json
import re
from typing import Optional

from external_tools import _run, _which
from scanners.registry import ScanContext, ToolAdapter, finding, has_files, register

_INSTALL = "npm ships with Node.js (https://nodejs.org)"


def parse(data, source: str = "") -> list:
    """`npm audit --json` (npm v7+) → {"vulnerabilities": {pkg: {severity, via,
    range, fixAvailable, ...}}}. `via` entries are advisory dicts or pkg-name strings."""
    out = []
    for name, info in ((data or {}).get("vulnerabilities", {}) or {}).items():
        if not isinstance(info, dict):
            continue
        title, url = "", ""
        for v in info.get("via", []) or []:
            if isinstance(v, dict):
                title, url = v.get("title", ""), v.get("url", "")
                break
        # GHSA id from the advisory URL is the cross-tool dedup key (OSV/Trivy
        # surface the same GHSA); fall back to none so it keys by location.
        m = re.search(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", url or "", re.I)
        vid = m.group(0).upper() if m else ""
        fix = info.get("fixAvailable")
        if fix is True:
            fixtext = "Run `npm audit fix`."
        elif isinstance(fix, dict):
            fixtext = (f"Upgrade {fix.get('name', name)} to "
                       f"{fix.get('version', 'a fixed version')} (may need `npm audit fix --force`).")
        else:
            fixtext = "No automatic fix — review the advisory and upgrade manually."
        out.append(finding(
            info.get("severity", "moderate"),
            f"{name} — {title or 'known vulnerability'}",
            (title or "") + (f"\n{url}" if url else "")
            + f"\nPackage: {name} ({info.get('range', '')})" + (f"  ({source})" if source else ""),
            source, 0, fixtext, "npm-audit", vuln_id=vid, signature=name))
    return out


def run(ctx: ScanContext) -> Optional[list]:
    if not _which("npm"):
        return None
    if not has_files(ctx.root, "package-lock.json"):
        return []
    from scanners.base import skip
    out = []
    for lock in sorted(ctx.root.rglob("package-lock.json")):
        if skip(lock):
            continue
        proc = _run(["npm", "audit", "--json"], cwd=lock.parent)
        if proc is None:
            continue
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            continue
        rel = str(lock.relative_to(ctx.root)) if lock.is_relative_to(ctx.root) else str(lock)
        out += parse(data, source=rel)
    return out


register(ToolAdapter(name="npm-audit", scan_type="sca", binary="npm",
                     run=run, install=_INSTALL))
