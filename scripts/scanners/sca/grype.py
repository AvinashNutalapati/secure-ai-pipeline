"""Grype adapter — SCA. https://github.com/anchore/grype

Anchore's vulnerability scanner for filesystems / SBOMs / images. A second
opinion alongside Trivy + OSV — different DBs surface different CVEs.
Registered into the scanner registry; returns None when the binary is absent.

stdlib only.
"""

from __future__ import annotations

from typing import Optional

from external_tools import _which
from scanners.registry import ScanContext, ToolAdapter, finding, register, run_json

_INSTALL = ("brew install grype   (or: curl -sSfL "
            "https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh)")


def parse(data) -> list:
    """`grype dir:<path> -o json` → {"matches": [{vulnerability, artifact}]}."""
    out = []
    for m in (data or {}).get("matches", []) or []:
        vuln = m.get("vulnerability", {}) or {}
        art = m.get("artifact", {}) or {}
        vid = vuln.get("id", "")
        name = art.get("name", "")
        version = art.get("version", "")
        locs = art.get("locations", []) or []
        path = locs[0].get("path", "") if locs else ""
        fix = vuln.get("fix", {}) or {}
        fixed = ", ".join(fix.get("versions", []) or []) if fix.get("state") == "fixed" else ""
        out.append(finding(
            vuln.get("severity", "MEDIUM"),
            f"{name} {version} — {vid}",
            (vuln.get("description") or vid)[:400] +
            f"\nPackage: {name}@{version}" + (f"  ({path})" if path else ""),
            path, 0,
            (f"Upgrade {name} to {fixed}." if fixed
             else "No fixed version published yet — assess exposure or replace the dependency."),
            "grype", vuln_id=vid, signature=name))
    return out


def run(ctx: ScanContext) -> Optional[list]:
    if not _which("grype"):
        return None
    return run_json(ctx, ["grype", f"dir:{ctx.root}", "-o", "json", "-q"], parse)


register(ToolAdapter(name="grype", scan_type="sca", binary="grype",
                     run=run, install=_INSTALL,
                     ci_install="curl -sSfL https://raw.githubusercontent.com/anchore/grype/"
                                "main/install.sh | sh -s -- -b /usr/local/bin"))
