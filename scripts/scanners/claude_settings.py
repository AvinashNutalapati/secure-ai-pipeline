"""Claude Code permission/blast-radius scanner.

Inspects .claude/settings.json and .claude/settings.local.json for permissions
that let the agent reach outside the project workspace: home-directory or
filesystem-root reads, wildcard Bash, destructive commands, and
permission-bypass modes.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .base import Finding, rel, skip

CLAUDE_SETTINGS_NAMES = {"settings.json", "settings.local.json"}

# Read/Edit globs that escape the workspace.
ESCAPING_READ = re.compile(
    r"(?:Read|Edit|Write)\(\s*"
    r"(?:/+(?:Users|home|etc|var|root|opt)\b"   # /Users, //home, /etc, …
    r"|~"                                          # home tilde
    r"|/*\*\*)",                                  # /**, ** filesystem wildcard
    re.IGNORECASE,
)
DESTRUCTIVE_BASH = re.compile(r"(?i)Bash\(\s*(rm\s+-rf|sudo|curl[^)]*\|\s*sh|:\(\)\s*\{)")
WILDCARD_BASH = re.compile(r"(?i)Bash\(\s*\*\s*\)|Bash\(\s*\)")
BROAD_NET = re.compile(r"(?i)(WebFetch|WebSearch)\(\s*\*?\s*\)")


def _is_claude_settings(path: Path) -> bool:
    return path.name in CLAUDE_SETTINGS_NAMES and ".claude" in path.parts


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for p in root.rglob("*"):
        if not p.is_file() or skip(p) or not _is_claude_settings(p):
            continue
        where = rel(p, root)
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
        except (json.JSONDecodeError, OSError):
            continue

        perms = data.get("permissions", {}) if isinstance(data, dict) else {}
        allow = perms.get("allow", []) if isinstance(perms, dict) else []
        default_mode = (data.get("defaultMode") or perms.get("defaultMode") or "")

        if str(default_mode).lower() in ("bypasspermissions", "acceptedits"):
            findings.append(Finding(
                "claude", "Claude permissions", "claude-bypass-mode", "HIGH",
                f"Claude defaultMode is '{default_mode}'",
                f"{where} sets defaultMode='{default_mode}', which removes the "
                "human approval step for agent actions.",
                "Use 'default' (prompt) mode; reserve auto-accept for sandboxes.",
                where,
            ))

        for rule in allow if isinstance(allow, list) else []:
            r = str(rule)
            if ESCAPING_READ.search(r):
                sev = "CRITICAL" if re.search(r"(/Users|/home|~|//?\*\*)", r) else "HIGH"
                findings.append(Finding(
                    "claude", "Claude permissions", "claude-broad-read", sev,
                    "Claude can read outside the workspace",
                    f"Permission `{r}` in {where} grants access beyond the project "
                    "directory. Indirect prompt injection could turn this into "
                    "data exfiltration of anything the agent can read.",
                    "Scope file access to the project, e.g. Read(./**); deny "
                    "Read(//Users/**) and other home/root paths.",
                    where,
                ))
            elif DESTRUCTIVE_BASH.search(r):
                findings.append(Finding(
                    "claude", "Claude permissions", "claude-destructive-bash", "HIGH",
                    "Claude is pre-authorized for a destructive command",
                    f"Permission `{r}` in {where} pre-approves a dangerous shell "
                    "command without prompting.",
                    "Remove blanket approval for rm -rf/sudo/pipe-to-shell.",
                    where,
                ))
            elif WILDCARD_BASH.search(r):
                findings.append(Finding(
                    "claude", "Claude permissions", "claude-wildcard-bash", "HIGH",
                    "Claude has wildcard shell access",
                    f"Permission `{r}` in {where} approves arbitrary shell commands.",
                    "Allow only specific commands, e.g. Bash(npm test*).",
                    where,
                ))
            elif BROAD_NET.search(r):
                findings.append(Finding(
                    "claude", "Claude permissions", "claude-broad-network", "MEDIUM",
                    "Claude has unrestricted network fetch",
                    f"Permission `{r}` in {where} allows fetching arbitrary URLs, "
                    "an exfiltration channel under prompt injection.",
                    "Restrict WebFetch to specific, trusted domains.",
                    where,
                ))
    return findings
