"""Checkov adapter — IaC. https://github.com/bridgecrewio/checkov

Prisma/Bridgecrew's IaC scanner: Terraform, CloudFormation, Kubernetes, Helm,
Dockerfile, ARM, Serverless, and CI configs. The primary engine for the `iac`
scan type. Returns [] cleanly on repos with no infrastructure code.
Registered into the scanner registry; returns None when the binary is absent.

stdlib only.
"""

from __future__ import annotations

import json
from typing import Optional

from external_tools import _run, _which
from scanners.registry import ScanContext, ToolAdapter, finding, register

_INSTALL = "pip install checkov"


def parse(data) -> list:
    """`checkov -o json` → a framework dict, or a LIST of them (multi-framework).
    We read each block's results.failed_checks."""
    blocks = data if isinstance(data, list) else [data]
    out = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        results = block.get("results", {}) or {}
        for c in results.get("failed_checks", []) or []:
            cid = c.get("check_id", "")
            name = c.get("check_name", "")
            rng = c.get("file_line_range", [0]) or [0]
            path = (c.get("file_path", "") or "").lstrip("/")
            res = c.get("resource", "")
            out.append(finding(
                c.get("severity") or "MEDIUM",
                f"{name} [{cid}]" if name else cid,
                f"{name}\nresource: {res}  ({block.get('check_type', 'iac')})",
                path, int(rng[0] or 0),
                c.get("guideline") or "Apply the secure configuration this Checkov policy describes.",
                "checkov"))
    return out


def run(ctx: ScanContext) -> Optional[list]:
    if not _which("checkov"):
        return None
    proc = _run(["checkov", "-d", str(ctx.root), "-o", "json",
                 "--compact", "--quiet"])
    if proc is None:
        return []
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return []
    return parse(data)


register(ToolAdapter(name="checkov", scan_type="iac", binary="checkov",
                     run=run, install=_INSTALL, ci_install="pip install checkov"))
