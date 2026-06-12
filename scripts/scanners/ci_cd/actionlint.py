"""actionlint adapter — CI/CD. https://github.com/rhysd/actionlint

Static checker for GitHub Actions workflows: syntax/schema errors plus the
security-relevant ones — shell-injection via untrusted `${{ }}` in `run:`,
unsafe expressions, shellcheck findings. Complements zizmor on the `ci_cd` type.
Registered into the scanner registry; returns None when the binary is absent.

stdlib only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from external_tools import _run, _which
from scanners.registry import ScanContext, ToolAdapter, finding, register

_INSTALL = ("brew install actionlint   (or: bash <(curl -s "
            "https://raw.githubusercontent.com/rhysd/actionlint/main/scripts/download-actionlint.bash))")

# Injection/untrusted-input findings are the security-critical ones.
_HIGH_HINTS = ("inject", "untrusted", "${{", "shellcheck")


def parse(data) -> list:
    """`actionlint -format '{{json .}}'` → a JSON array of error objects:
    {message, filepath, line, column, kind, snippet}."""
    out = []
    for e in data or []:
        msg = e.get("message", "")
        kind = e.get("kind", "")
        sev = "HIGH" if any(h in (msg + kind).lower() for h in _HIGH_HINTS) else "MEDIUM"
        out.append(finding(
            sev,
            f"{msg[:120]}" + (f" [{kind}]" if kind else ""),
            f"{msg}\nkind: {kind}",
            e.get("filepath", ""), int(e.get("line") or 0),
            "Fix the workflow per actionlint; for injection, pass untrusted input via an "
            "env: var instead of inlining ${{ }} in run:.",
            "actionlint"))
    return out


def run(ctx: ScanContext) -> Optional[list]:
    if not _which("actionlint"):
        return None
    if not (Path(ctx.root) / ".github" / "workflows").is_dir():
        return []
    # actionlint auto-discovers .github/workflows; run from the repo root.
    proc = _run(["actionlint", "-format", "{{json .}}", "-no-color"], cwd=ctx.root)
    if proc is None:
        return []
    try:
        data = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        return []
    return parse(data)


register(ToolAdapter(name="actionlint", scan_type="ci_cd", binary="actionlint",
                     run=run, install=_INSTALL,
                     ci_install="bash <(curl -s https://raw.githubusercontent.com/rhysd/"
                                "actionlint/main/scripts/download-actionlint.bash) && "
                                "sudo mv actionlint /usr/local/bin/"))
