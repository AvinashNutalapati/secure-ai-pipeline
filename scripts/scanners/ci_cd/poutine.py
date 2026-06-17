"""poutine adapter — CI/CD security. https://github.com/boostsecurityio/poutine

poutine (Apache-2.0, single Go binary) analyses GitHub Actions, GitLab CI, Azure
Pipelines and Tekton — the non-GitHub platforms zizmor/actionlint are structurally
blind to. It overlaps zizmor on GitHub Actions (unpinned actions, injection), so to
honour the no-duplicate-findings mandate it is marked heavy=True: it runs only under
--deep, where the user has opted into broader/overlapping coverage. On a default
scan, zizmor owns GitHub Actions and poutine stays quiet.

Returns None when the binary is absent.

stdlib only.
"""

from __future__ import annotations

from typing import Optional

import external_tools as ext
from external_tools import _which
from scanners.registry import ScanContext, ToolAdapter, register, run_json

_INSTALL = ("brew install poutine   (or: see "
            "https://github.com/boostsecurityio/poutine#installation)")


def parse(data) -> list:
    return ext.parse_sarif(data, tool="poutine")


def run(ctx: ScanContext) -> Optional[list]:
    if not _which("poutine"):
        return None
    # analyze_local emits a SARIF document on stdout; gate on the presence of any
    # pipeline YAML so it no-ops on repos without CI config.
    return run_json(ctx, ["poutine", "--format", "sarif", "analyze_local", str(ctx.root)],
                    parse, gate=("*.yml", "*.yaml"))


register(ToolAdapter(
    name="poutine", scan_type="ci_cd", binary="poutine",
    run=run, install=_INSTALL, heavy=True,
    ci_install="curl -sSfL https://raw.githubusercontent.com/boostsecurityio/poutine/"
               "main/install.sh | sh -s -- -b /usr/local/bin"))
