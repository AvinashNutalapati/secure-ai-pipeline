"""AI-assisted-development risk scanners.

Each module exposes ``scan(root: Path) -> list[Finding]`` and inspects one slice
of the AI coding attack surface (AI IDE rules, Claude permissions, MCP configs,
GitHub Actions). ``blast_radius`` aggregates them into a single score.

stdlib only — importable and testable anywhere.
"""

from .base import Finding, SEVERITY_WEIGHT, SEVERITIES  # noqa: F401
