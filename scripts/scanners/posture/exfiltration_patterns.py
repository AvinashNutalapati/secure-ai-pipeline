"""Compound credential-exfiltration detector for agent skill / rule files.

secure-ai-pipeline:rule-source — excluded from the built-in scan (its regexes
contain finding-shaped strings like requests.post / ~/.ssh).


A single "read a secret" OR "make a network call" is normal DevOps tooling and
flagging either alone floods false positives. The malicious shape is the PAIR:
an instruction/skill file that BOTH reads a credential AND transmits it off-box.
This scanner fires only when both appear in the same file — the high-precision
"compound read + transmit" pattern from agent-skill malware research.

Distinct from ai_ide's single-keyword `ai-ide-exfiltration` (which matches one
"send secrets" phrase); this requires a read-sink pair, so it's higher-confidence
and emits its own rule id.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..base import Finding, rel, skip

WATCHED_NAMES = {
    ".cursorrules", ".clinerules", ".windsurfrules",
    "CLAUDE.md", "AGENTS.md", "SKILL.md", "GEMINI.md", "copilot-instructions.md",
}
WATCHED_GLOBS = (
    "**/.cursor/rules/**/*", "**/.clinerules/*", "**/.windsurf/rules/*",
    "**/.github/copilot-instructions.md", "**/*.mdc", "**/SKILL.md", "**/AGENTS.md",
)
_MAX_BYTES = 1_000_000

# A credential / sensitive-material READ.
_READ_RE = re.compile(
    r"(?i)("
    r"os\.(?:getenv|environ)"
    r"|process\.env\b"
    r"|read\b[^\n]{0,40}(?:secret|token|credential|password|api[_ -]?key|\.env\b)"
    r"|(?:cat|type|open)\b[^\n]{0,40}(?:~/\.ssh|~/\.aws|\.npmrc|id_rsa|\.env\b|credentials)"
    r"|~/\.(?:ssh|aws|config/gcloud)"
    r"|\.env\b"
    r")"
)
# An EXTERNAL transmit (off-box). localhost is excluded so local dev isn't flagged.
_SEND_RE = re.compile(
    r"(?i)("
    r"requests\.(?:post|put|patch)\b"
    r"|urllib\b[^\n]{0,40}urlopen"
    r"|fetch\s*\(\s*[\x22\x27]https?://"
    r"|(?:curl|wget)\b[^\n]{0,60}https?://"
    r"|POST\b[^\n]{0,40}https?://"
    r"|socket\.(?:socket|connect)"
    r"|webhook"
    r")"
)
_LOCALHOST_RE = re.compile(r"(?i)localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0")


def _first_match(pattern, lines):
    for i, line in enumerate(lines, 1):
        if pattern.search(line) and not _LOCALHOST_RE.search(line):
            return i, line.strip()[:100]
    return None


def _collect(root: Path) -> list[Path]:
    out: list[Path] = []
    for p in root.rglob("*"):
        if p.is_file() and p.name in WATCHED_NAMES and not skip(p):
            out.append(p)
    for g in WATCHED_GLOBS:
        for p in root.glob(g):
            if p.is_file() and not skip(p):
                out.append(p)
    seen, uniq = set(), []
    for p in sorted(out):
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in _collect(root):
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        read_hit = _first_match(_READ_RE, lines)
        send_hit = _first_match(_SEND_RE, lines)
        if read_hit and send_hit:
            where = rel(path, root)
            findings.append(Finding(
                "exfiltration", "Exfiltration", "ai-exfiltration-compound", "CRITICAL",
                f"Skill/rule file both reads a credential and transmits off-box: {where}",
                f"{where} reads sensitive material ({where}:{read_hit[0]}: "
                f"{read_hit[1]}) AND sends data to an external destination "
                f"({where}:{send_hit[0]}: {send_hit[1]}) — the credential-"
                "exfiltration pattern in a file the agent trusts.",
                "Remove the read+transmit pair from the instruction/skill file; "
                "agents should never be told to read secrets and POST them out.",
                where, read_hit[0],
            ))
    return findings
