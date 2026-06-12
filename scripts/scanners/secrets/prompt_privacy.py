"""Prompt / rules privacy linter.

AI rules and instruction files get fed to models and shared across a team, so
secrets, internal URLs, private IPs, and contact emails embedded in them leak
into prompts and provider logs. This flags that content in the files agents treat
as trusted instructions.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..base import SECRET_VALUE_PATTERNS, Finding, rel, skip

# Files whose text becomes model context / agent instructions.
PROMPT_GLOBS = [
    ".cursorrules", ".clinerules", ".windsurfrules",
    "**/.cursor/rules/*", "**/.cursor/rules/**/*.mdc", "**/.windsurf/rules/*",
    "**/.github/copilot-instructions.md", "**/AGENTS.md", "**/CLAUDE.md",
    "**/.claude/*.md",
]

# Shared with secrets_in_config via base so the two scanners can never drift.
SECRET_PATTERNS = SECRET_VALUE_PATTERNS

PRIVATE_IP = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
)
INTERNAL_URL = re.compile(
    r"https?://[A-Za-z0-9.-]+\.(?:internal|corp|local|lan|intranet|int)\b", re.IGNORECASE
)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# Don't flag obvious example/placeholder addresses.
EMAIL_SAFE = ("example.com", "example.org", "yourapp", "domain.com", "email.com")


def _collect(root: Path) -> list[Path]:
    out: list[Path] = []
    for g in PROMPT_GLOBS:
        it = root.glob(g) if ("*" in g or "/" in g) else [root / g]
        for p in it:
            if p.is_file() and not skip(p):
                out.append(p)
    seen, uniq = set(), []
    for p in sorted(out, key=str):
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in _collect(root):
        where = rel(path, root)
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            for pat, label in SECRET_PATTERNS:
                if pat.search(line):
                    findings.append(Finding(
                        "prompt_privacy", "Prompt privacy", "prompt-secret", "HIGH",
                        f"{label} embedded in an AI rules/prompt file",
                        f"{where}:{i} contains what looks like a {label}. Anything in "
                        "this file is sent to the model and shared with the team.",
                        "Remove the secret; reference it from the environment at runtime.",
                        where, i,
                    ))
                    break
            # Independent checks: one line can leak more than one of these.
            if INTERNAL_URL.search(line):
                findings.append(Finding(
                    "prompt_privacy", "Prompt privacy", "prompt-internal-url", "MEDIUM",
                    "Internal URL in an AI rules/prompt file",
                    f"{where}:{i} references an internal host. It leaks topology into "
                    "prompts/provider logs.",
                    "Avoid internal hostnames in rules; keep them out of model context.",
                    where, i,
                ))
            if PRIVATE_IP.search(line):
                findings.append(Finding(
                    "prompt_privacy", "Prompt privacy", "prompt-private-ip", "MEDIUM",
                    "Private IP address in an AI rules/prompt file",
                    f"{where}:{i} contains a private IP — internal-topology disclosure "
                    "via prompts.",
                    "Remove internal IPs from rules/prompt files.",
                    where, i,
                ))
            # Check every email on the line — a real address after a
            # safe-listed example.com one must still be flagged.
            m = next((x for x in EMAIL.finditer(line)
                      if not any(s in x.group(0).lower() for s in EMAIL_SAFE)), None)
            if m:
                findings.append(Finding(
                    "prompt_privacy", "Prompt privacy", "prompt-email", "LOW",
                    "Email address in an AI rules/prompt file",
                    f"{where}:{i} contains an email ({m.group(0)}) that becomes part "
                    "of model context.",
                    "Drop personal/customer emails from rules files.",
                    where, i,
                ))
    return findings
