"""User-defined posture rules (the `custom_posture_rules` policy hook).

secure-ai-pipeline:rule-source — excluded from the built-in scan (the docstring
shows example pattern strings).


The built-in posture scanners are opinionated; orgs need their own rules-file /
config / code checks too. This scanner lets a repo add regex rules in its
`secure-ai-pipeline.yml` policy — single-source by definition, no code change:

    custom_posture_rules:
      - id: no-internal-host
        pattern: "internal\\.corp\\.example\\.com"
        severity: HIGH
        files: ["**/*.md", "**/*.cursorrules"]      # optional; default = rules/config files
        message: "Internal hostname leaked into an agent-instruction file."
        fix: "Remove the internal hostname."

Note: a list-of-maps policy value needs a real YAML parser (PyYAML installed) or a
JSON policy file — the built-in flat-YAML subset can't represent it.

stdlib only.
"""

from __future__ import annotations

import re
from pathlib import Path

import policy as policy_mod
from ..base import Finding, rel, skip

_DEFAULT_FILES = (
    "**/*.cursorrules", "**/.clinerules/*", "**/.windsurfrules", "**/*.mdc",
    "**/CLAUDE.md", "**/AGENTS.md", "**/SKILL.md", "**/copilot-instructions.md",
    "**/mcp.json", "**/.mcp.json",
)
_VALID_SEV = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_MAX_BYTES = 1_000_000


def _files(root: Path, globs) -> list:
    out = []
    for g in globs:
        for p in root.glob(g):
            if p.is_file() and not skip(p):
                out.append(p)
    # exact dotfile names (no slash, no wildcard) via rglob by basename
    seen, uniq = set(), []
    for p in sorted(out):
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def scan(root: Path) -> list[Finding]:
    pol = policy_mod.load_policy(root)
    rules = pol.get("custom_posture_rules") or []
    if not isinstance(rules, list):
        return []
    findings: list[Finding] = []
    for raw in rules:
        if not isinstance(raw, dict) or not raw.get("pattern") or not raw.get("id"):
            continue
        try:
            pat = re.compile(str(raw["pattern"]))
        except re.error:
            continue  # a bad user regex must never crash the scan
        sev = str(raw.get("severity", "MEDIUM")).upper()
        if sev not in _VALID_SEV:
            sev = "MEDIUM"
        globs = raw.get("files") or _DEFAULT_FILES
        if isinstance(globs, str):
            globs = [globs]
        rid = str(raw["id"])
        msg = str(raw.get("message", f"Custom posture rule '{rid}' matched."))
        fix = str(raw.get("fix", "Review and remediate per your policy."))
        for path in _files(root, globs):
            try:
                if path.stat().st_size > _MAX_BYTES:
                    continue
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            where = rel(path, root)
            for i, line in enumerate(lines, 1):
                if pat.search(line):
                    findings.append(Finding(
                        "custom", "Custom policy", f"custom-{rid}", sev,
                        f"{msg} ({where}:{i})",
                        f"Custom rule '{rid}' matched in {where}:{i}: {line.strip()[:120]}",
                        fix, where, i,
                    ))
                    break  # one finding per rule per file
    return findings
