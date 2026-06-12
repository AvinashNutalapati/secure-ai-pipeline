"""zizmor adapter — CI/CD. https://github.com/zizmorcore/zizmor

Static analysis for GitHub Actions workflows: unpinned actions, dangerous
`pull_request_target` + checkout, template-injection in `run:`, excessive
permissions, self-hosted-runner risks. The primary engine for the `ci_cd` type.
Emits SARIF, parsed through the shared SARIF reader.
Registered into the scanner registry; returns None when the binary is absent.

stdlib only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from external_tools import _run, _which, parse_sarif
from scanners.registry import ScanContext, ToolAdapter, register

_INSTALL = "pip install zizmor   (or: cargo install zizmor)"


def parse(data) -> list:
    """zizmor `--format sarif` → a standard SARIF document."""
    return parse_sarif(data, tool="zizmor")


def run(ctx: ScanContext) -> Optional[list]:
    if not _which("zizmor"):
        return None
    if not (Path(ctx.root) / ".github" / "workflows").is_dir():
        return []
    # --format sarif → stdout. zizmor exits non-zero on findings (fine, we read
    # the output). --offline avoids needing a GitHub token for online audits.
    proc = _run(["zizmor", "--format", "sarif", "--offline", str(ctx.root)])
    if proc is None:
        return []
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return []
    return parse(data)


register(ToolAdapter(name="zizmor", scan_type="ci_cd", binary="zizmor",
                     run=run, install=_INSTALL, ci_install="pip install zizmor"))
