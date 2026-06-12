"""pip-audit adapter — SCA (Python). https://github.com/pypa/pip-audit

PyPA's auditor for Python dependencies, using the PyPI Advisory + OSV data.
Audits each requirements*.txt in the repo (skips when there are none).
Registered into the scanner registry; returns None when the binary is absent.

stdlib only.
"""

from __future__ import annotations

import json
from typing import Optional

from external_tools import _run, _which
from scanners.registry import ScanContext, ToolAdapter, finding, has_files, register

_INSTALL = "pip install pip-audit"


def parse(data, source: str = "") -> list:
    """pip-audit JSON is either {"dependencies": [...]} (newer) or a bare list."""
    deps = data.get("dependencies", data) if isinstance(data, dict) else data
    out = []
    for dep in deps or []:
        name = dep.get("name", "")
        version = dep.get("version", "")
        for v in dep.get("vulns", []) or []:
            vid = v.get("id", "")
            aliases = ", ".join(v.get("aliases", []) or [])
            fixed = ", ".join(v.get("fix_versions", []) or [])
            out.append(finding(
                "HIGH",  # pip-audit reports known advisories without a CVSS band
                f"{name} {version} — {vid}" + (f" ({aliases})" if aliases else ""),
                (v.get("description") or vid)[:400] + f"\nPackage: {name}@{version}"
                + (f"  ({source})" if source else ""),
                source, 0,
                (f"Upgrade {name} to {fixed}." if fixed
                 else "No fixed version published — assess exposure or replace the dependency."),
                "pip-audit"))
    return out


def run(ctx: ScanContext) -> Optional[list]:
    if not _which("pip-audit"):
        return None
    if not has_files(ctx.root, "requirements*.txt"):
        return []
    out = []
    for req in sorted(ctx.root.rglob("requirements*.txt")):
        from scanners.base import skip
        if skip(req):
            continue
        proc = _run(["pip-audit", "-f", "json", "--no-deps", "-r", str(req)])
        if proc is None:
            continue
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            continue
        rel = str(req.relative_to(ctx.root)) if req.is_relative_to(ctx.root) else str(req)
        out += parse(data, source=rel)
    return out


register(ToolAdapter(name="pip-audit", scan_type="sca", binary="pip-audit",
                     run=run, install=_INSTALL, ci_install="pip install pip-audit"))
