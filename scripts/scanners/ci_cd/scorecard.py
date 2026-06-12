"""OpenSSF Scorecard adapter — CI/CD + supply-chain posture. https://github.com/ossf/scorecard

Scores a repo's security posture (branch protection, pinned dependencies, token
permissions, dangerous workflows, signed releases, …) 0–10 per check. We surface
the low-scoring checks as findings. The richest checks need a repo URL + a GitHub
token; `--local` covers the offline subset.

No auto-install (it wants a token/repo for full coverage) — activates when a
`scorecard` binary is on PATH. Returns None when it's absent.

stdlib only.
"""

from __future__ import annotations

from typing import Optional

from external_tools import _which
from scanners.registry import ScanContext, ToolAdapter, finding, register, run_json

_INSTALL = ("see https://github.com/ossf/scorecard#installation "
            "(full checks need --repo + GITHUB_TOKEN; --local covers the offline subset)")


def _severity(score) -> Optional[str]:
    """Scorecard checks score 0–10. <0 = didn't run; 8–10 = fine (no finding)."""
    if score is None or score < 0:
        return None
    if score <= 2:
        return "HIGH"
    if score <= 5:
        return "MEDIUM"
    if score <= 7:
        return "LOW"
    return None


def parse(data) -> list:
    """`scorecard --format json` → {"score": float, "checks": [{name, score,
    reason, documentation: {short, url}}]}."""
    out = []
    for c in (data or {}).get("checks", []) or []:
        sev = _severity(c.get("score"))
        if sev is None:
            continue
        name = c.get("name", "")
        doc = c.get("documentation", {}) or {}
        out.append(finding(
            sev, f"{name}: {c.get('score')}/10 posture",
            f"{c.get('reason', '')}\n{doc.get('short', '')}".strip(),
            "", 0,
            doc.get("url", "") or f"Improve the OpenSSF Scorecard '{name}' check.",
            "scorecard"))
    return out


def run(ctx: ScanContext) -> Optional[list]:
    if not _which("scorecard"):
        return None
    return run_json(ctx, ["scorecard", "--local", str(ctx.root), "--format", "json"], parse)


register(ToolAdapter(name="scorecard", scan_type="ci_cd", binary="scorecard",
                     run=run, install=_INSTALL))
