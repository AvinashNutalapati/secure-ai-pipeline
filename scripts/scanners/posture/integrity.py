"""Config-integrity baseline — rug-pull / TOCTOU / Cuckoo-attack drift detection.

Approval-sensitive files (AI rules, MCP configs, CI workflows) are trusted once and
then re-read every session. The "Cuckoo Attack" / MCP rug-pull pattern ships a
benign file, gets it approved, then mutates it later. This scanner pins a SHA-256
of each such file in a committed baseline and flags any later change that wasn't
re-reviewed.

It is **read-only**: the scan never writes. Generate/refresh the baseline with
``python scripts/integrity_baseline.py`` and commit it, so CI and PR diffs can
detect drift. Without a baseline the scanner emits a single INFO pointing at it.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..base import Finding, rel, skip

# Where the committed baseline lives. (Generated repos gitignore fix-prompt output
# under this dir; the baseline must be force-added — the helper prints how.)
BASELINE_REL = ".secure-ai-pipeline/integrity-baseline.json"

# Files an agent treats as standing instructions / wiring — the rug-pull surface.
WATCHED_NAMES = {
    ".cursorrules", ".clinerules", ".windsurfrules",
    "CLAUDE.md", "AGENTS.md", "SKILL.md", "GEMINI.md",
    "copilot-instructions.md", "mcp.json", ".mcp.json",
    "claude_desktop_config.json", "settings.json", "settings.local.json",
}
WATCHED_GLOBS = (
    "**/.cursor/rules/**/*", "**/.clinerules/*", "**/.windsurf/rules/*",
    "**/.github/copilot-instructions.md", "**/.vscode/mcp.json",
    "**/.cursor/mcp.json", "**/*.mdc", "**/SKILL.md", "**/AGENTS.md",
    "**/.github/workflows/*.yml", "**/.github/workflows/*.yaml",
)


def watched_files(root: Path) -> list[Path]:
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


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def compute_hashes(root: Path) -> dict:
    """{relpath: sha256} for every watched file — used by the scan and the helper."""
    out = {}
    for p in watched_files(root):
        digest = _sha256(p)
        if digest:
            out[rel(p, root)] = digest
    return out


def _load_baseline(root: Path):
    bp = root / BASELINE_REL
    if not bp.is_file():
        return None
    try:
        data = json.loads(bp.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    files = data.get("files") if isinstance(data, dict) else None
    return files if isinstance(files, dict) else None


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    baseline = _load_baseline(root)
    current = compute_hashes(root)

    if baseline is None:
        if current:  # only nudge if there's actually something worth pinning
            findings.append(Finding(
                "integrity", "Config integrity", "integrity-no-baseline", "INFO",
                "No config-integrity baseline — drift detection is off",
                f"{len(current)} approval-sensitive file(s) (AI rules, MCP configs, "
                "workflows) are unpinned, so a later rug-pull/TOCTOU mutation would "
                "go unnoticed.",
                "Run `python scripts/integrity_baseline.py` and commit "
                f"{BASELINE_REL} to detect unreviewed changes.",
                BASELINE_REL,
            ))
        return findings

    for path, digest in sorted(current.items()):
        if path not in baseline:
            findings.append(Finding(
                "integrity", "Config integrity", "integrity-new-file", "HIGH",
                f"New approval-sensitive file since the baseline: {path}",
                f"{path} did not exist when the integrity baseline was approved. New "
                "rules/MCP/workflow files steer the agent and need review.",
                "Review the file, then refresh the baseline "
                "(`python scripts/integrity_baseline.py`).",
                path,
            ))
        elif baseline[path] != digest:
            findings.append(Finding(
                "integrity", "Config integrity", "integrity-drift", "CRITICAL",
                f"Approval-sensitive file changed without re-approval: {path}",
                f"{path} differs from the committed baseline hash — the rug-pull / "
                "Cuckoo-attack pattern (approve a benign file, mutate it later).",
                "Review the change. If intended, refresh the baseline "
                "(`python scripts/integrity_baseline.py`); if not, revert it.",
                path,
            ))
    return findings
