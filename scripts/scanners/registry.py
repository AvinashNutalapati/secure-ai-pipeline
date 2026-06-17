"""
The scanner registry — the ONE place that knows every tool the pipeline can run.

Every channel (the GitHub Action, the MCP server, `npx scan`, the local runner)
reads scanners from here, so adding a tool is a drop-in: create one adapter file
under ``scripts/scanners/<scan_type>/<tool>.py`` that calls ``register(...)`` at
import time, and the orchestrator picks it up automatically — no per-channel edits.

Two kinds of scanner feed the registry:
  - built-in   pure-Python detectors already under scanners/ (slopsquatting,
               ai-insecure-defaults, blast radius). These are orchestrated as
               per-type fallbacks by scan_all.py.
  - external   an OSS binary we shell out to (gitleaks, trivy, bandit, checkov,
               …). Each is a ``ToolAdapter`` whose ``run(ctx)`` returns a list of
               normalised finding dicts, or ``None`` when the tool isn't installed
               (so a missing scanner degrades gracefully instead of failing).

Normalised finding dict (one shape across every tool):
    {"severity": str, "title": str, "detail": str,
     "file": str, "line": int, "fix": str, "tool": str}

stdlib only.
"""

from __future__ import annotations

import fnmatch
import functools
import importlib
import json
import pkgutil
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

import external_tools as _ext  # the shared adapter toolkit (helpers + core 5)

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


# ─────────────────────────────────────────────────────────────────────────────
# Scan-type taxonomy — the single source for type ordering + the AI fix-prompt
# instruction (shared by scan_all's fix prompts and the Action job summary).
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ScanType:
    key: str
    label: str          # human label (renderers may upper-case for compact views)
    intro: str          # the "Task:" line of the AI fix prompt for this type


SCAN_TYPES: list[ScanType] = [
    ScanType("secrets", "Secrets",
             "remove every hardcoded secret, replace it with an environment "
             "variable or secrets-manager lookup, and note that the exposed value must be rotated"),
    ScanType("packages", "Dependency Trust (supply chain)",
             "remove or correct each hallucinated / non-existent / malicious package: verify "
             "the real name on PyPI/npm before installing, and DELETE anything flagged malicious"),
    ScanType("sca", "Dependencies (SCA / CVEs)",
             "upgrade each vulnerable dependency to the fixed version shown (or replace the "
             "package if no fix exists)"),
    ScanType("sast", "Static Analysis (SAST)",
             "fix each insecure code pattern using the secure idiom the rule describes "
             "(parameterised queries, verify=True, no shell=True, no eval on input, no hardcoded creds)"),
    ScanType("iac", "Infrastructure as Code (IaC)",
             "fix each infrastructure misconfiguration: least-privilege IAM, no public exposure, "
             "encryption at rest/in transit, and drop insecure defaults in Terraform/K8s/Docker"),
    ScanType("ci_cd", "CI/CD & GitHub Actions",
             "harden the CI/CD config: pin actions to commit SHAs, set least-privilege "
             "permissions, avoid pull_request_target with untrusted checkout, and never expose secrets to PRs"),
    ScanType("ai_posture", "AI Workflow Blast Radius",
             "harden the AI workflow: pin actions to commit SHAs, remove pull_request_target where "
             "possible, scope agent/Claude permissions, and stop passing long-lived secrets to MCP servers"),
    ScanType("dast", "Dynamic Analysis (DAST)",
             "fix each runtime/HTTP issue at the server: add the missing security headers, "
             "secure cookies, and input handling identified by the DAST scan"),
]

SCAN_TYPE_KEYS = [t.key for t in SCAN_TYPES]
_BY_KEY = {t.key: t for t in SCAN_TYPES}


def label_for(key: str) -> str:
    t = _BY_KEY.get(key)
    return t.label if t else key


def intro_for(key: str) -> str:
    t = _BY_KEY.get(key)
    return t.intro if t else "fix the security findings below"


def order_index(key: str) -> int:
    return SCAN_TYPE_KEYS.index(key) if key in SCAN_TYPE_KEYS else len(SCAN_TYPE_KEYS)


# ─────────────────────────────────────────────────────────────────────────────
# Tool adapters
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScanContext:
    """Everything an adapter might need to run, passed to every ``run(ctx)``."""
    root: Path
    offline: bool = False
    dast_url: str = ""
    semgrep_ruleset: Optional[Path] = None
    zap_rules: Optional[Path] = None
    policy: Optional[dict] = None   # the repo's secure-ai-pipeline.yml (for ai_posture)


@dataclass
class ToolAdapter:
    name: str                                   # "trivy", "bandit", …
    scan_type: str                              # one of SCAN_TYPE_KEYS
    run: Callable[[ScanContext], Optional[list]]  # ctx → finding dicts | None
    binary: str = ""                            # executable checked on PATH
    install: str = ""                           # human install hint (shown when missing)
    ci_install: str = ""                        # shell snippet to install it in CI (optional)
    available_fn: Optional[Callable[[], bool]] = None  # override binary check
    heavy: bool = False                         # slow/expensive — only with deep-scan
    timeout: Optional[int] = None               # per-tool wall-clock cap (s); None = global default

    def available(self) -> bool:
        if self.available_fn is not None:
            try:
                return bool(self.available_fn())
            except Exception:
                return False
        if self.binary:
            return shutil.which(self.binary) is not None
        return True


_ADAPTERS: dict[str, ToolAdapter] = {}
_DISCOVERED = False


def register(adapter: ToolAdapter) -> ToolAdapter:
    """Add an adapter. Idempotent by name (re-import / double-discover safe)."""
    if adapter.scan_type not in SCAN_TYPE_KEYS:
        raise ValueError(f"{adapter.name}: unknown scan_type {adapter.scan_type!r}")
    _ADAPTERS[adapter.name] = adapter
    return adapter


def finding(severity: str, title: str, detail: str = "", file: str = "",
            line: int = 0, fix: str = "", tool: str = "", *,
            vuln_id: str = "", rule_key: str = "", cwe_id: str = "",
            signature: str = "", confidence: str = "", reachable: str = "",
            sources=None) -> dict:
    """Build a normalised finding dict — the one shape every adapter emits.

    The first eight fields are the long-standing shape. The trailing keyword-only
    fields are the *identity* substrate that lets consolidation.py collapse the
    same issue reported by several tools into one finding (see that module):
      - ``vuln_id``    CVE / GHSA / OSV / MAL advisory id (SCA, packages)
      - ``rule_key``   the tool's native rule id (SAST/IaC/CI)
      - ``cwe_id``     canonical CWE (e.g. "89") — the cross-tool SAST key
      - ``signature``  secondary identity: sha256(secret value) for secrets,
                       normalised package name for SCA
      - ``confidence`` e.g. "verified" (TruffleHog live-verify, OSV MAL-)
      - ``reachable``  "", "true", or "false" (dependency reachability triage)
      - ``sources``    tool names that confirmed this finding (filled on merge)
    All default empty, so every existing adapter and test keeps working unchanged.
    """
    return {"severity": _ext._norm_sev(severity), "title": title, "detail": detail,
            "file": file, "line": int(line or 0), "fix": fix, "tool": tool,
            "vuln_id": vuln_id, "rule_key": rule_key, "cwe_id": cwe_id,
            "signature": signature, "confidence": confidence,
            "reachable": reachable, "sources": list(sources or [])}


@functools.lru_cache(maxsize=8)
def _basename_index(root_str: str) -> frozenset:
    """Every non-vendored file basename under root, walked ONCE and cached, so the
    N adapters that gate on has_files() share one traversal instead of N. Cleared
    per scan (clear_file_index) so it can't go stale across runs in a long-lived
    process (the MCP server)."""
    from scanners.base import skip
    root = Path(root_str)
    return frozenset(p.name for p in root.rglob("*") if p.is_file() and not skip(p))


def clear_file_index() -> None:
    """Drop the cached file index — call at the start of each scan."""
    _basename_index.cache_clear()


def run_json(ctx, argv: list, parse, *, gate=None, cwd=None):
    """The standard adapter body for a tool that prints JSON on stdout: optionally
    gate on the repo containing the right files, run ``argv`` (non-zero exit is
    fine — tools exit non-zero when they find issues), json.loads the stdout, and
    hand it to ``parse``. Returns [] when the gate fails or the output isn't
    parseable. The CALLER checks ``_which(binary)`` first (so a test that patches
    the adapter's _which can still simulate the tool being absent → None)."""
    if gate and not has_files(ctx.root, *gate):
        return []
    proc = _ext._run(argv, cwd=cwd)
    if proc is None:
        return []
    try:
        data = json.loads(proc.stdout or "{}")
    except (json.JSONDecodeError, ValueError):
        return []
    return parse(data)


def has_files(root, *patterns: str) -> bool:
    """True if any file matching a basename glob exists under root (skipping vendor
    dirs). Lets an adapter cheaply skip itself when the repo has nothing to scan.
    Patterns are basename globs (`*.py`, `requirements*.txt`, `Gemfile`); a pattern
    containing `/` falls back to a direct rglob."""
    root = Path(root)
    simple = [p for p in patterns if "/" not in p]
    if simple:
        names = _basename_index(str(root))
        if any(fnmatch.fnmatch(n, pat) for pat in simple for n in names):
            return True
    if len(simple) != len(patterns):  # rare: a path-shaped pattern
        from scanners.base import skip
        for pat in patterns:
            if "/" in pat and any(p.is_file() and not skip(p) for p in root.rglob(pat)):
                return True
    return False


def discover() -> None:
    """Import every adapter module under scanners/ so they self-register.

    This is what makes the registry a true drop-in: a new file under
    scripts/scanners/<type>/ that calls register() at import is live everywhere
    after this runs. A broken adapter is skipped, never fatal.
    """
    global _DISCOVERED
    if _DISCOVERED:
        return
    _DISCOVERED = True  # set first so a re-entrant import can't loop
    import scanners
    for info in pkgutil.walk_packages(scanners.__path__, prefix="scanners."):
        if info.name == __name__:
            continue
        try:
            importlib.import_module(info.name)
        except Exception:
            # A scanner with a missing optional dep or a typo must not take the
            # whole registry down — it just won't be available.
            continue


def all_adapters() -> list[ToolAdapter]:
    discover()
    return sorted(_ADAPTERS.values(), key=lambda a: (order_index(a.scan_type), a.name))


def adapters_for(scan_type: str) -> list[ToolAdapter]:
    return [a for a in all_adapters() if a.scan_type == scan_type]


def available_adapters(scan_type: str, include_heavy: bool = True) -> list[ToolAdapter]:
    return [a for a in adapters_for(scan_type)
            if a.available() and (include_heavy or not a.heavy)]


def detect() -> dict:
    """{tool_name: bool installed} for every registered external adapter."""
    return {a.name: a.available() for a in all_adapters()}


def roles() -> dict:
    """{tool_name: scan_type} — for the preflight 'which engines' display."""
    return {a.name: a.scan_type for a in all_adapters()}


def install_hint(name: str) -> str:
    a = _ADAPTERS.get(name)
    return a.install if a else ""


# ─────────────────────────────────────────────────────────────────────────────
# The core five (gitleaks/semgrep/trivy/osv/zap) live in external_tools.py and
# are registered here so they share the one orchestration path with everything
# else. New tools get their own file under scanners/<type>/.
# ─────────────────────────────────────────────────────────────────────────────

register(ToolAdapter(
    name="gitleaks", scan_type="secrets", binary="gitleaks",
    run=lambda ctx: _ext.run_gitleaks(ctx.root),
    install=_ext.INSTALL_HINTS["gitleaks"]))

register(ToolAdapter(
    name="semgrep", scan_type="sast", binary="semgrep",
    run=lambda ctx: _ext.run_semgrep(ctx.root, extra_config=ctx.semgrep_ruleset),
    install=_ext.INSTALL_HINTS["semgrep"], ci_install="pip install semgrep",
    timeout=900))  # rule compile + scan on a big monorepo can exceed the default

register(ToolAdapter(
    name="trivy", scan_type="sca", binary="trivy",
    run=lambda ctx: _ext.run_trivy(ctx.root),
    install=_ext.INSTALL_HINTS["trivy"],
    ci_install="curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/"
               "install.sh | sh -s -- -b /usr/local/bin",
    timeout=900))  # first run builds/updates the vuln DB

register(ToolAdapter(
    name="osv-scanner", scan_type="sca", binary="osv-scanner",
    run=lambda ctx: _ext.run_osv(ctx.root),
    install=_ext.INSTALL_HINTS["osv-scanner"]))

register(ToolAdapter(
    name="zap", scan_type="dast",
    available_fn=lambda: bool(_ext._which("zap-baseline.py") or _ext._which("docker")),
    run=lambda ctx: _ext.run_zap(ctx.dast_url, rules_file=ctx.zap_rules) if ctx.dast_url else None,
    install=_ext.INSTALL_HINTS["docker"]))
