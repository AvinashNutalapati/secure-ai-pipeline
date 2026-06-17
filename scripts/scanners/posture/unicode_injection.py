"""Invisible-Unicode instruction-injection scanner.

AI assistants read rules/skill/MCP/config files as trusted instructions - and a
model reads codepoints a human reviewer can't see. Attackers smuggle directives
into these files using Unicode Tag characters, zero-width joiners, bidi overrides,
and soft hyphens: the file looks benign in review but carries hidden commands to
the model (the "Rules File Backdoor" / "Hidden Unicode Instruction Injection"
class - Pillar Security; CSA research).

This flags any approval-sensitive text file that contains those invisible
codepoints. Visible-but-risky directives are ai_ide's job; this is the orthogonal
invisible-payload check, so the two never double-report the same line.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..base import Finding, rel, skip

# The file set a coding agent treats as trusted instructions or wiring. Kept
# self-contained so this scanner owns its surface and can add files - CLAUDE.md /
# SKILL.md / *.mdc / git config - that ai_ide and mcp_config don't watch.
WATCHED_NAMES = {
    ".cursorrules", ".clinerules", ".windsurfrules",
    "CLAUDE.md", "AGENTS.md", "SKILL.md", "GEMINI.md",
    "copilot-instructions.md", "mcp.json", ".mcp.json",
    "claude_desktop_config.json", ".gitattributes", ".gitconfig",
}
WATCHED_GLOBS = (
    "**/.cursor/rules/**/*", "**/.clinerules/*", "**/.windsurf/rules/*",
    "**/.github/copilot-instructions.md", "**/.vscode/mcp.json",
    "**/.cursor/mcp.json", "**/*.mdc", "**/SKILL.md", "**/AGENTS.md",
)
_MAX_BYTES = 1_000_000  # never read a giant/binary blob into memory

# Character classes are built from integer codepoints via chr() so this SOURCE
# contains only visible ASCII (no invisible chars to review around). The compiled
# patterns match the real codepoints at runtime.
_TAG_CPS = (range(0xE0000, 0xE0080),)                       # Unicode Tags block
_BIDI_CPS = (range(0x202A, 0x202F), range(0x2066, 0x206A))  # LRE..RLO / LRI..PDI
_ZERO_WIDTH_CPS = (
    0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD,         # ZW*, WJ, BOM, soft-hyphen
    0x2061, 0x2062, 0x2063, 0x2064,                          # invisible math operators
    0x061C, 0x180E,                                          # Arabic letter mark, Mongolian vowel sep
    0x115F, 0x1160, 0x3164, 0xFFA0,                          # Hangul fillers (render blank)
    range(0xFE00, 0xFE10),                                   # variation selectors VS1-16
    range(0xE0100, 0xE01F0),                                 # variation selectors supplement
)


def _class(*specs) -> "re.Pattern":
    """Compile a character class from individual codepoints and/or ranges."""
    chars = []
    for spec in specs:
        if isinstance(spec, range):
            chars.append(re.escape(chr(spec.start)) + "-" + re.escape(chr(spec.stop - 1)))
        else:
            chars.append(re.escape(chr(spec)))
    return re.compile("[" + "".join(chars) + "]")


_CLASSES = [
    (_class(*_TAG_CPS), "ai-unicode-tag", "CRITICAL",
     "Unicode Tag characters (U+E0000-E007F) - an invisible instruction-injection "
     "channel with no legitimate use in a rules/config file."),
    (_class(*_BIDI_CPS), "ai-unicode-bidi", "HIGH",
     "Bidirectional-override characters (U+202A-202E / U+2066-2069) can reorder "
     "how text is read vs. how a model parses it (the Trojan Source attack)."),
    (_class(*_ZERO_WIDTH_CPS), "ai-unicode-zerowidth", "HIGH",
     "Zero-width / soft-hyphen characters that are invisible in review but read by "
     "the model - used to hide directives inside otherwise-benign text."),
]


def has_hidden_unicode(text: str):
    """(rule_id, severity, what, lineno, codepoints) for the first hidden-codepoint
    class found in ``text``, or None. Shared with the MCP poisoning scanner so a
    tool description and a rules file are checked the same way."""
    for pattern, rule_id, severity, what in _CLASSES:
        for i, line in enumerate(text.splitlines(), 1):
            if pattern.search(line):
                # Report the codepoints, since the chars themselves are invisible.
                hits = sorted({"U+%04X" % ord(c) for c in line if pattern.match(c)})
                return rule_id, severity, what, i, ", ".join(hits[:6])
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
            text = path.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeDecodeError):
            continue  # unreadable or not UTF-8 text -> nothing to flag
        where = rel(path, root)
        hit = has_hidden_unicode(text)
        if hit:
            rule_id, severity, what, line, codepoints = hit
            findings.append(Finding(
                "unicode_injection", "Hidden Unicode", rule_id, severity,
                f"Hidden Unicode in an agent-instruction file: {where}",
                f"{what} Found {codepoints} at {where}:{line}. A reviewer can't see "
                "these characters, but the AI model reads them.",
                "Remove the invisible characters; retype the line in plain visible "
                "text and review the file's true contents.",
                where, line,
            ))
    return findings
