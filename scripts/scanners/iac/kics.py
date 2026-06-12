"""KICS adapter — IaC. https://github.com/Checkmarx/kics

Checkmarx's IaC scanner (Terraform, K8s, Docker, CloudFormation, Ansible, Helm,
OpenAPI, …). A second opinion alongside Checkov on the `iac` type. Emits SARIF,
parsed through the shared reader.

KICS needs its bundled query assets, so we don't auto-install it in CI — the
adapter activates when a working `kics` is on PATH (or run via its Docker image).
Returns None when kics is absent.

stdlib only.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Optional

from external_tools import _run, _which, parse_sarif
from scanners.registry import ScanContext, ToolAdapter, register

_INSTALL = ("see https://docs.kics.io/latest/getting-started/ "
            "(the binary needs its bundled query assets; Docker image checkmarx/kics also works)")


def parse(data) -> list:
    """KICS `--report-formats sarif` → a standard SARIF document."""
    return parse_sarif(data, tool="kics")


def run(ctx: ScanContext) -> Optional[list]:
    if not _which("kics"):
        return None
    with tempfile.TemporaryDirectory() as outdir:
        # KICS exits non-zero when it finds issues; it still writes the report.
        _run(["kics", "scan", "--no-progress", "-p", str(ctx.root),
              "--report-formats", "sarif", "--output-path", outdir, "--output-name", "kics"])
        sarifs = list(Path(outdir).glob("*.sarif"))
        if not sarifs:
            return []
        try:
            data = json.loads(sarifs[0].read_text(encoding="utf-8") or "{}")
        except (OSError, json.JSONDecodeError):
            return []
        return parse(data)


register(ToolAdapter(name="kics", scan_type="iac", binary="kics",
                     run=run, install=_INSTALL))
