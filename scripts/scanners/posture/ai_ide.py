"""AI IDE rules / instructions scanner.

AI assistants treat repo "rules" files as trusted local instructions, which makes
them a context-poisoning and rules-backdoor surface. This inventories those files
and flags directives that weaken safety (auto-run, disable confirmation,
fetch-and-execute, exfiltration-shaped instructions).
"""

from __future__ import annotations

import re
from pathlib import Path

from ..base import Finding, rel, skip

# (glob, tool label)
RULE_SOURCES = [
    (".cursorrules", "Cursor"),
    ("**/.cursor/rules/*", "Cursor"),
    ("**/.cursor/rules/**/*.mdc", "Cursor"),
    (".clinerules", "Cline"),
    ("**/.clinerules/*", "Cline"),
    (".windsurfrules", "Windsurf"),
    ("**/.windsurf/rules/*", "Windsurf"),
    ("**/.github/copilot-instructions.md", "Copilot"),
    ("**/AGENTS.md", "Agent"),
]

RISKY_DIRECTIVES = [
    (re.compile(r"(?i)\b(yolo|auto[\s-]?run|auto[\s-]?execute|run automatically)\b"),
     "auto-execution", "HIGH",
     "Rule encourages running commands automatically without approval."),
    (re.compile(r"(?i)(without (asking|confirmation|approval)|do(n'?t| not) ask|skip (the )?confirmation|no confirmation)"),
     "disable-approval", "HIGH",
     "Rule tells the agent to skip human confirmation."),
    (re.compile(r"(?i)(curl|wget)\b[^\n]*\|\s*(bash|sh)\b"),
     "fetch-execute", "HIGH",
     "Rule contains a fetch-and-execute (curl|bash) instruction."),
    (re.compile(r"(?i)\b(rm\s+-rf|sudo\s+rm|disable .*(security|safety|guardrail))"),
     "destructive", "HIGH",
     "Rule references destructive or safety-disabling actions."),
    (re.compile(r"(?i)(ignore (all )?(previous|prior) instructions|disregard (the )?(system|above))"),
     "prompt-injection", "CRITICAL",
     "Rule text contains prompt-injection-style override language."),
    # Word-boundaried: "send keyboard shortcuts" / "environment details" must
    # NOT match — only sending of secrets/tokens/keys/credentials/.env does.
    (re.compile(r"(?i)(?:exfiltrat"
                r"|send\s.*\b(?:secrets?|tokens?|api[_ -]?keys?|credentials?"
                r"|passwords?|environment\s+variables?)\b"
                r"|send\s.*\s\.env\b"
                r"|POST\s.*https?://)"),
     "exfiltration", "CRITICAL",
     "Rule text resembles an exfiltration instruction."),
]


def _collect(root: Path) -> list[tuple[Path, str]]:
    out: list[tuple[Path, str]] = []
    for pattern, label in RULE_SOURCES:
        # Exact top-level dotfiles vs glob patterns
        if pattern.startswith("**") or "/" in pattern or "*" in pattern.split("/")[-1]:
            it = root.glob(pattern)
        else:
            it = [root / pattern]
        for p in it:
            if p.is_file() and not skip(p):
                out.append((p, label))
    # de-dupe
    seen, uniq = set(), []
    for p, label in sorted(out, key=lambda t: str(t[0])):
        if p not in seen:
            seen.add(p)
            uniq.append((p, label))
    return uniq


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path, label in _collect(root):
        where = rel(path, root)
        findings.append(Finding(
            "ai_ide", "AI IDE rules", "ai-ide-rules-present", "INFO",
            f"{label} rules file present: {where}",
            f"{label} treats {where} as trusted instructions. Anyone who can edit "
            "it (or a PR author) can steer the agent.",
            "Review rules files in PRs as security-sensitive; keep them minimal.",
            where,
        ))
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lines = text.splitlines()
        for pattern, rule_id, severity, detail in RISKY_DIRECTIVES:
            for i, line in enumerate(lines, 1):
                if pattern.search(line):
                    findings.append(Finding(
                        "ai_ide", "AI IDE rules", f"ai-ide-{rule_id}", severity,
                        f"{label} rule has a risky directive ({rule_id})",
                        f"{detail} In {where}:{i}: {line.strip()[:120]}",
                        "Remove the directive; never let rules files disable "
                        "approvals or fetch-and-execute.",
                        where, i,
                    ))
                    break  # one finding per rule per file
    return findings
