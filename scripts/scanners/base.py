"""Shared types and helpers for the AI-posture scanners."""

from __future__ import annotations

import re
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


def score_from_counts(by_severity: dict) -> int:
    """0–100 blast-radius score from severity counts. Single source of truth —
    blast_radius.py and policy.py must never diverge on scoring."""
    penalty = sum(SEVERITY_WEIGHT.get(s, 0) * n for s, n in (by_severity or {}).items())
    return max(0, 100 - penalty)


def grade_of(score: int) -> str:
    return ("A" if score >= 90 else "B" if score >= 75 else
            "C" if score >= 60 else "D" if score >= 40 else "F")


# Credential-shaped value patterns shared by the secrets_in_config and
# prompt_privacy scanners (one list — additions propagate to both).
# The sk- patterns cover classic (sk-<32+>), project (sk-proj-…), Anthropic
# API/admin (sk-ant-api03-…, sk-ant-admin01-…) and OpenAI service-account
# (sk-svcacct-…) key shapes.
SECRET_VALUE_PATTERNS = [
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{16,}\b"), "GitHub token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{16,}\b"), "GitHub fine-grained PAT"),
    (re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"), "OpenAI API key"),
    (re.compile(r"\bsk-(?:[a-z]+\d*-)+[A-Za-z0-9_-]{24,}\b"), "OpenAI/Anthropic API key"),
    (re.compile(r"\bAKIA[0-9A-Z]{12,}\b"), "AWS access key id"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private key"),
]


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
