"""Shared types and helpers for the AI-posture scanners."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Penalty each finding subtracts from the 100-point blast-radius score.
SEVERITY_WEIGHT = {
    "CRITICAL": 30,
    "HIGH": 15,
    "MEDIUM": 7,
    "LOW": 3,
    "INFO": 0,
}

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
    ".tox", ".mypy_cache", ".pytest_cache", "site-packages", ".next", "out",
}


@dataclass
class Finding:
    scanner: str          # which scanner produced it (e.g. "mcp")
    category: str         # grouping for the score (e.g. "MCP")
    rule_id: str          # stable id (e.g. "mcp-secret-env")
    severity: str         # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str            # short headline
    detail: str           # what was found and why it matters
    fix: str              # concrete remediation
    file: str = ""        # path relative to scan root
    line: int = 0         # 1-based line number, 0 if N/A

    def to_dict(self) -> dict:
        return asdict(self)


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def find_files(root: Path, names=(), globs=()) -> list[Path]:
    """Return existing files matching exact basenames (anywhere) or glob patterns."""
    out: list[Path] = []
    names = set(names)
    for pattern in globs:
        for p in root.rglob(pattern):
            if p.is_file() and not skip(p):
                out.append(p)
    if names:
        for p in root.rglob("*"):
            if p.is_file() and p.name in names and not skip(p):
                out.append(p)
    # de-dupe, stable order
    seen, uniq = set(), []
    for p in sorted(out):
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq
