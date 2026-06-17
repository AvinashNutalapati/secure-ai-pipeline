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
    ("**/CLAUDE.md", "Claude"),
    ("**/GEMINI.md", "Gemini"),
    ("**/SKILL.md", "Skill"),
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
    # Encoding-obfuscation: a payload that's decoded/run hides intent from review.
    # The verb and the base64 blob must be CLOSE (<=40 chars, either order), so an
    # unrelated long token elsewhere on a line that merely mentions "run" doesn't
    # false-positive.
    (re.compile(r"(?i)(?:"
                r"(?:decode|exec|eval|atob|fromCharCode|unescape|base64_?decode)\b[^\n]{0,40}[A-Za-z0-9+/]{40,}={0,2}"
                r"|[A-Za-z0-9+/]{40,}={0,2}[^\n]{0,40}\b(?:decode|exec|eval|atob|fromCharCode|unescape|base64_?decode)\b"
                r")"),
     "encoded-payload", "HIGH",
     "Rule has a long base64-looking blob next to a decode/exec verb - an "
     "obfuscated payload."),
    (re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}"),
     "hex-encoded", "MEDIUM",
     "Rule contains a long hex-escaped (\\xNN) byte string - likely an obfuscated "
     "payload."),
    (re.compile(r"(?i)\br[o0]t[\s_(-]{0,3}(?:13|47|\d{1,2})\b"),
     "rot-encoded", "MEDIUM",
     "Rule references ROT-n encoding - used to obfuscate instructions from review."),
]

# Zalgo / stacked combining marks (U+0300-U+036F) are a visual-obfuscation trick;
# built via chr() so this source stays plain ASCII. TWO in a row never occurs in
# natural text (a single accent is fine: cafe-acute, naive-diaeresis).
_ZALGO = re.compile("[" + re.escape(chr(0x0300)) + "-" + re.escape(chr(0x036F)) + "]{2,}")


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
        for i, line in enumerate(lines, 1):
            if _ZALGO.search(line):
                findings.append(Finding(
                    "ai_ide", "AI IDE rules", "ai-ide-obfuscation-zalgo", "MEDIUM",
                    f"{label} rule has stacked combining marks (Zalgo obfuscation)",
                    f"Zalgo/stacked combining-mark text in {where}:{i} hides the "
                    "line's real content from a human reviewer.",
                    "Remove the combining marks; retype the line in plain text.",
                    where, i,
                ))
                break
    return findings
