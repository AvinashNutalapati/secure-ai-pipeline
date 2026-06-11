"""GitHub Actions supply-chain scanner.

Flags the CI/CD risks amplified by AI-fast adoption: third-party actions pinned
by mutable tag instead of full commit SHA (the tj-actions/changed-files lesson),
`pull_request_target` (which runs with secrets on untrusted PRs), and untrusted
`github.event.*` interpolation in `run:` steps (script injection).

Line/regex based — no YAML dependency.
"""

from __future__ import annotations

import re
from pathlib import Path

from .base import Finding, rel, skip

USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?([^'\"\s#]+)['\"]?")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
PR_TARGET_RE = re.compile(r"pull_request_target")
EVENT_INTERP_RE = re.compile(r"\$\{\{\s*github\.event\.[^}]*\}\}")
RUN_RE = re.compile(r"^\s*(?:-\s*)?run:\s|^\s*run:\s*\|")


def _workflow_files(root: Path) -> list[Path]:
    out = []
    wf_dir = root / ".github" / "workflows"
    if wf_dir.is_dir():
        for p in sorted(wf_dir.rglob("*")):
            if p.is_file() and p.suffix in (".yml", ".yaml") and not skip(p):
                out.append(p)
    return out


def _is_pinned(ref: str) -> bool:
    """A 'uses' ref is pinned only if @<40-hex-sha>. Docker/local refs are exempt."""
    if ref.startswith("./") or ref.startswith("docker://"):
        return True
    if "@" not in ref:
        return False
    return bool(SHA_RE.match(ref.rsplit("@", 1)[1]))


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for wf in _workflow_files(root):
        where = rel(wf, root)
        try:
            lines = wf.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        # pull_request_target
        for i, line in enumerate(lines, 1):
            if PR_TARGET_RE.search(line) and not line.strip().startswith("#"):
                findings.append(Finding(
                    "github_actions", "CI/CD", "gha-pull-request-target", "CRITICAL",
                    "Workflow uses pull_request_target",
                    f"{where}:{i} triggers on pull_request_target, which runs with "
                    "repository secrets in the context of untrusted PR code.",
                    "Prefer pull_request; if you must use pull_request_target, never "
                    "check out or execute PR head code, and gate on labels.",
                    where, i,
                ))
                break

        # Script injection via github.event.* — flagged only INSIDE run: blocks.
        # Track the block by indentation so `env:`/`with:` lines after a run
        # step (the recommended remediation!) are never false-positived.
        in_run = False
        run_indent = 0
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if RUN_RE.search(line):
                in_run = True
                run_indent = line.find("run:")
            elif in_run:
                indent = len(line) - len(line.lstrip(" "))
                if indent <= run_indent:
                    in_run = False  # dedent past `run:` ends the shell block
            if in_run and EVENT_INTERP_RE.search(line):
                findings.append(Finding(
                    "github_actions", "CI/CD", "gha-script-injection", "HIGH",
                    "Untrusted github.event interpolation in run step",
                    f"{where}:{i} interpolates ${{{{ github.event.* }}}} directly "
                    "into a shell step — an attacker-controlled value can inject "
                    "commands.",
                    "Pass the value via an env: var and reference \"$VAR\" in the "
                    "script instead of interpolating directly.",
                    where, i,
                ))

        # unpinned actions
        for i, line in enumerate(lines, 1):
            m = USES_RE.match(line)
            if not m:
                continue
            ref = m.group(1)
            if _is_pinned(ref):
                continue
            owner = ref.split("/")[0] if "/" in ref else ref
            first_party = owner in ("actions", "github")
            sev = "MEDIUM" if first_party else "HIGH"
            findings.append(Finding(
                "github_actions", "CI/CD", "gha-unpinned-action", sev,
                f"Action not pinned by SHA: {ref}",
                f"{where}:{i} uses `{ref}` pinned by a mutable tag/branch. A "
                "compromised tag (e.g. tj-actions/changed-files, 2025) silently "
                "runs attacker code with your CI secrets.",
                "Pin to a full 40-char commit SHA, e.g. "
                "uses: owner/action@<sha>  # vX.Y.Z",
                where, i,
            ))
    return findings
