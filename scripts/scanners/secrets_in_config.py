"""Hardcoded-secret scanner for .env files and AI/tool config.

AI configs (`mcp.json`, `.claude/*.json`) and `.env` files routinely accumulate
real tokens. This flags credential-shaped values committed in those files.
Complements Gitleaks (git history, in CI) with a local, scan-time check.

References to environment variables (`${VAR}`, `$VAR`) and obvious placeholders
are ignored.
"""

from __future__ import annotations

import re
from pathlib import Path

from .base import Finding, rel, skip

CONFIG_BASENAMES = {
    "mcp.json", ".mcp.json", "claude_desktop_config.json",
}
CONFIG_GLOBS = ("**/.vscode/mcp.json", "**/.cursor/mcp.json", "**/.claude/*.json")

# Credential-shaped values (high confidence regardless of key name).
VALUE_PATTERNS = [
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{16,}\b"), "GitHub token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{16,}\b"), "GitHub fine-grained PAT"),
    (re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{16,}\b"), "OpenAI/Anthropic API key"),
    (re.compile(r"\bAKIA[0-9A-Z]{12,}\b"), "AWS access key id"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private key"),
]

SECRET_KEY = re.compile(
    r"(?i)\b([A-Z0-9_]*(SECRET|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY|PASSWORD|PRIVATE[_-]?KEY))\b"
)
ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$")
PLACEHOLDER = ("${", "$(", "$", "<", "changeme", "your_", "your-", "example",
               "placeholder", "redacted", "xxxx", "...", "dummy", "fake", "todo")


def _is_placeholder(value: str) -> bool:
    v = value.strip().strip("'\"")
    if not v or len(v) < 8:
        return True
    low = v.lower()
    return any(tok in low for tok in PLACEHOLDER)


def _env_files(root: Path) -> list[Path]:
    out = []
    for p in root.rglob(".env*"):
        if p.is_file() and not skip(p) and not p.name.endswith((".example", ".sample", ".template")):
            out.append(p)
    return out


def _config_files(root: Path) -> list[Path]:
    out = []
    for p in root.rglob("*"):
        if p.is_file() and p.name in CONFIG_BASENAMES and not skip(p):
            out.append(p)
    for g in CONFIG_GLOBS:
        for p in root.glob(g):
            if p.is_file() and not skip(p):
                out.append(p)
    return out


def _scan_lines(path: Path, root: Path, env_mode: bool) -> list[Finding]:
    where = rel(path, root)
    findings: list[Finding] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return findings
    for i, line in enumerate(lines, 1):
        if line.lstrip().startswith("#"):
            continue
        # High-confidence credential-shaped values.
        matched = False
        for pat, label in VALUE_PATTERNS:
            if pat.search(line):
                findings.append(Finding(
                    "secrets", "Secrets", "config-hardcoded-secret", "CRITICAL",
                    f"Hardcoded {label} in {where}",
                    f"{where}:{i} contains a committed {label}. Tokens in configs are a "
                    "top source of leaks (GitGuardian flagged 24k+ secrets in MCP configs).",
                    "Remove it; load from the environment / a secrets manager and rotate it.",
                    where, i,
                ))
                matched = True
                break
        if matched:
            continue
        # .env: secret-named key assigned a real-looking value.
        if env_mode:
            m = ENV_LINE.match(line)
            if m and SECRET_KEY.search(m.group(1)) and not _is_placeholder(m.group(2)):
                findings.append(Finding(
                    "secrets", "Secrets", "env-hardcoded-secret", "HIGH",
                    f"Secret-named variable with a hardcoded value in {where}",
                    f"{where}:{i} sets {m.group(1)} to a literal value rather than "
                    "referencing the environment / a secrets manager.",
                    "Move the value to a secrets manager; commit only ${VAR} references.",
                    where, i,
                ))
    return findings


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for p in _env_files(root):
        findings.extend(_scan_lines(p, root, env_mode=True))
    seen = set()
    for p in _config_files(root):
        if p in seen:
            continue
        seen.add(p)
        findings.extend(_scan_lines(p, root, env_mode=False))
    return findings
