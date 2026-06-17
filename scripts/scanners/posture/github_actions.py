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

from ..base import Finding, rel, skip

USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?([^'\"\s#]+)['\"]?")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
PR_TARGET_RE = re.compile(r"pull_request_target")
EVENT_INTERP_RE = re.compile(r"\$\{\{\s*github\.event\.[^}]*\}\}")
RUN_RE = re.compile(r"^\s*(?:-\s*)?run:\s|^\s*run:\s*\|")
SECRET_USE_RE = re.compile(r"\$\{\{\s*secrets\.")
SECRETS_INHERIT_RE = re.compile(r"secrets:\s*inherit\b")
# Checking out the PR HEAD ref under pull_request_target = running untrusted code
# with secrets — the classic "pwn request".
CHECKOUT_PR_REF_RE = re.compile(
    r"ref:\s*\$\{\{[^}]*(?:github\.event\.pull_request\.head|github\.head_ref)")


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


# Our own action is referenced by its @v3 major tag in the quickstart we ship.
# Don't flag a user for invoking the scanner the exact way our README recommends:
# @v3 lets them auto-receive security fixes, and we control the tag. (A fork under
# a different owner with the same repo name is NOT exempt — full owner/repo match.)
_OWN_ACTION = "avinashnutalapati/secure-ai-pipeline"


def _is_own_action(ref: str) -> bool:
    return ref.split("@", 1)[0].lower() == _OWN_ACTION


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for wf in _workflow_files(root):
        where = rel(wf, root)
        try:
            lines = wf.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        # pull_request_target
        uses_prt = False
        for i, line in enumerate(lines, 1):
            if PR_TARGET_RE.search(line) and not line.strip().startswith("#"):
                uses_prt = True
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

        # pull_request_target + checkout of the PR head ref = the "pwn request".
        if uses_prt:
            for i, line in enumerate(lines, 1):
                if CHECKOUT_PR_REF_RE.search(line) and not line.strip().startswith("#"):
                    findings.append(Finding(
                        "github_actions", "CI/CD", "gha-prtarget-untrusted-checkout", "CRITICAL",
                        "pull_request_target checks out the untrusted PR head",
                        f"{where}:{i} checks out the PR's head ref while running under "
                        "pull_request_target — attacker-controlled code then executes "
                        "with your repository secrets.",
                        "Don't check out PR head code in pull_request_target; if you "
                        "must, run it in an isolated job with no secrets.",
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
            if _is_pinned(ref) or _is_own_action(ref):
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
            # Worse: this unpinned THIRD-PARTY action is also handed secrets.
            if not first_party and _step_passes_secret(lines, i):
                findings.append(Finding(
                    "github_actions", "CI/CD", "gha-secret-to-untrusted-action", "HIGH",
                    f"Secrets passed to an unpinned third-party action: {ref}",
                    f"{where}:{i} passes repository secrets to `{ref}`, which is "
                    "pinned by a mutable tag — a hijacked tag exfiltrates them.",
                    "Pin the action to a full commit SHA before giving it secrets, "
                    "and pass only the narrowest scoped token it needs.",
                    where, i,
                ))
    return findings


def _step_passes_secret(lines: list, uses_lineno: int) -> bool:
    """True if the step starting at the given 1-based `uses:` line passes a
    ${{ secrets.* }} value or `secrets: inherit`. Bounds the scan to the step's
    own body by indentation (stops at the next `- ` step or any dedent)."""
    uses_indent = len(lines[uses_lineno - 1]) - len(lines[uses_lineno - 1].lstrip(" "))
    for j in range(uses_lineno, len(lines)):  # lines after the uses: line
        nxt = lines[j]
        if not nxt.strip():
            continue
        nind = len(nxt) - len(nxt.lstrip(" "))
        if nxt.lstrip().startswith("- ") or nind < uses_indent:
            break  # next step / dedent out of this step's body
        if SECRET_USE_RE.search(nxt) or SECRETS_INHERIT_RE.search(nxt):
            return True
    return False
