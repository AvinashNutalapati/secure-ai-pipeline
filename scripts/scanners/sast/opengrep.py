"""opengrep adapter — SAST. https://github.com/opengrep/opengrep

opengrep is the LGPL open-source fork of Semgrep's engine (no telemetry, no
registry-login). It runs the SAME rule syntax, so it's a drop-in *replacement*
for semgrep, not a second opinion — running both would double-report every
finding. So this adapter is available ONLY when opengrep is installed AND semgrep
is not (mutual exclusion); when both are present, semgrep wins and opengrep stays
quiet, leaving the consolidation layer nothing to dedup here.

It runs the repo's canonical AI-insecure-defaults ruleset plus any community packs
vendored under `.semgrep/community/` (drop MIT-licensed rule files there). Returns
None when the binary is absent.

stdlib only.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Optional

import external_tools as ext
from external_tools import _which
from scanners.registry import ScanContext, ToolAdapter, register

_INSTALL = "see https://github.com/opengrep/opengrep (LGPL OSS Semgrep fork)"


def _configs(ctx: ScanContext) -> list:
    configs: list = []
    if ctx.semgrep_ruleset and Path(ctx.semgrep_ruleset).exists():
        configs += ["--config", str(ctx.semgrep_ruleset)]
    community = Path(ctx.root) / ".semgrep" / "community"
    if community.is_dir():
        configs += ["--config", str(community)]
    if not configs:  # nothing local → fall back to the bundled security pack
        configs = ["--config", "auto"]
    return configs


def run(ctx: ScanContext) -> Optional[list]:
    if not _which("opengrep"):
        return None
    with tempfile.NamedTemporaryFile("r", suffix=".sarif", delete=False) as tf:
        out_file = tf.name
    try:
        proc = ext._run(["opengrep", "scan", *_configs(ctx), "--sarif",
                         "--output", out_file, "--quiet", str(ctx.root)])
        if proc is None:
            return []
        try:
            data = json.loads(Path(out_file).read_text(encoding="utf-8") or "{}")
        except (json.JSONDecodeError, OSError):
            return []
        return ext.parse_sarif(data, tool="opengrep")
    finally:
        try:
            os.unlink(out_file)
        except OSError:
            pass


# Mutually exclusive with semgrep: only run opengrep when semgrep is NOT installed,
# so the two never duplicate (they share the exact same ruleset).
register(ToolAdapter(
    name="opengrep", scan_type="sast",
    available_fn=lambda: _which("opengrep") is not None and _which("semgrep") is None,
    run=run, install=_INSTALL))
