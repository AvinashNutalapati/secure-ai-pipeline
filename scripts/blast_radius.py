#!/usr/bin/env python3
"""
AI Agent Blast Radius Score.

Aggregates the AI-posture scanners (AI IDE rules, Claude permissions, MCP configs,
GitHub Actions) — and, unless --offline, the anti-slopsquatting package guard —
into one 0–100 score. 100 means minimal blast radius; lower means an attacker who
gets a foothold (via prompt injection, a poisoned issue, a malicious MCP server,
or a compromised action) can reach further.

Usage:
    python blast_radius.py [ROOT] [--json OUT] [--offline] [--fail-on LEVEL]

ROOT defaults to $GITHUB_WORKSPACE or cwd. --fail-on {critical,high,medium} makes
the process exit 1 when a finding at or above that severity exists (for CI). By
default it is report-only (exit 0).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from scanners import SEVERITIES  # noqa: E402
from scanners.posture import ai_ide, claude_settings, github_actions, mcp_config  # noqa: E402
from scanners.secrets import config_secrets, prompt_privacy  # noqa: E402
from scanners.base import Finding, grade_of, score_from_counts  # noqa: E402
import policy as policy_mod  # noqa: E402

OFFLINE_SCANNERS = {
    "ai_ide": ai_ide.scan,
    "claude": claude_settings.scan,
    "mcp": mcp_config.scan,
    "github_actions": github_actions.scan,
    "prompt_privacy": prompt_privacy.scan,
    "secrets": config_secrets.scan,
}

_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # CRITICAL=0 .. INFO=4


def run_scanners(root: Path, include=None) -> list[Finding]:
    findings: list[Finding] = []
    for name, fn in OFFLINE_SCANNERS.items():
        if include and name not in include:
            continue
        try:
            findings.extend(fn(root))
        except Exception as exc:  # a scanner crash must not sink the whole run
            findings.append(Finding(
                name, name.upper(), f"{name}-scanner-error", "LOW",
                f"{name} scanner error", str(exc),
                "Report this as a bug.", "",
            ))
    return findings


def package_findings(root: Path) -> list[Finding]:
    """Convert the (network) anti-slopsquatting guard into Findings."""
    import check_packages
    result = check_packages.scan(root)
    out: list[Finding] = []
    for b in result["blocked"]:
        out.append(Finding(
            "packages", "Dependency trust", "pkg-hallucinated", "CRITICAL",
            f"Hallucinated/non-existent package: {b['package']}",
            f"'{b['package']}' (imported in {b['file']}) does not exist on "
            f"{b['registry']} — a slopsquatting foothold.",
            "Remove or correct the import; verify the real package name.",
            b["file"],
        ))
    for w in result["warnings"]:
        out.append(Finding(
            # INFO so a flaky/offline network ("couldn't check") never deducts
            # from the score — only genuinely missing packages (CRITICAL) do.
            "packages", "Dependency trust", "pkg-registry-warning", "INFO",
            f"Could not verify package: {w['package']}",
            f"{w['registry']} was unreachable while checking '{w['package']}'.",
            "Re-run when the registry is reachable.",
            w["file"],
        ))
    return out


def score_of(findings: list[Finding]) -> int:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return score_from_counts(counts)


def assess(root: Path, *, offline: bool = False, include=None) -> dict:
    findings = run_scanners(root, include=include)
    if not offline:
        try:
            findings.extend(package_findings(root))
        except Exception as exc:
            # The flagship gate must never fail silently: surface the crash as
            # a HIGH finding so the score drops and fail_on [high] gates.
            findings.append(Finding(
                "packages", "Dependency trust", "packages-scanner-error", "HIGH",
                "Anti-slopsquatting guard failed to run",
                f"check_packages crashed ({exc.__class__.__name__}: {exc}). "
                "Hallucinated-package coverage is MISSING from this report.",
                "Re-run with --offline to skip network checks, or report this as a bug.",
                "",
            ))
    findings.sort(key=lambda f: (_SEV_RANK.get(f.severity, 99), f.category, f.file))

    by_sev = {s: 0 for s in SEVERITIES}
    by_cat: dict[str, dict] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        cat = by_cat.setdefault(f.category, {s: 0 for s in SEVERITIES})
        cat[f.severity] += 1

    sc = score_of(findings)
    return {
        "score": sc,
        "grade": grade_of(sc),
        "counts": by_sev,
        "by_category": by_cat,
        "findings": [f.to_dict() for f in findings],
    }


# ── text rendering ──────────────────────────────────────────────────────────
_C = {"CRITICAL": "\033[91m\033[1m", "HIGH": "\033[91m", "MEDIUM": "\033[93m",
      "LOW": "\033[2m", "INFO": "\033[2m", "_": "\033[0m", "B": "\033[1m"}


def render(report: dict, color: bool = True) -> str:
    def c(k, s):
        return f"{_C[k]}{s}{_C['_']}" if color else s
    out = []
    sc, gr = report["score"], report["grade"]
    out.append("")
    out.append(c("B", f"  AI Agent Blast Radius Score: {sc}/100  (grade {gr})"))
    out.append(c("LOW", "  100 = minimal blast radius. Higher is safer."))
    counts = report["counts"]
    summary = "  ".join(f"{counts[s]} {s.lower()}" for s in SEVERITIES if counts[s])
    out.append("  " + (summary or "no findings"))
    out.append("")
    for f in report["findings"]:
        if f["severity"] == "INFO":
            continue
        loc = f"{f['file']}:{f['line']}" if f.get("line") else f.get("file", "")
        out.append(f"  {c(f['severity'], '● ' + f['severity'])}  {f['title']}")
        out.append(c("LOW", f"      {loc}"))
        out.append(f"      {f['detail']}")
        out.append(c("LOW", f"      fix: {f['fix']}"))
        out.append("")
    return "\n".join(out)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="AI Agent Blast Radius Score.")
    parser.add_argument("root", nargs="?",
                        default=os.environ.get("GITHUB_WORKSPACE", os.getcwd()))
    parser.add_argument("--json", metavar="OUT", help="Write the full report as JSON.")
    parser.add_argument("--html", metavar="OUT", help="Write an HTML report.")
    parser.add_argument("--offline", action="store_true",
                        help="Skip network package checks.")
    parser.add_argument("--fail-on", type=str.lower,
                        choices=["critical", "high", "medium"],
                        help="Exit 1 if a finding at/above this severity exists "
                             "(overrides the policy file's fail_on). Case-insensitive.")
    parser.add_argument("--policy", metavar="FILE", help="Path to a policy file.")
    parser.add_argument("--no-policy", action="store_true",
                        help="Ignore any secure-ai-pipeline.{yml,yaml,json}.")
    parser.add_argument("--exclude", metavar="GLOBS", default="",
                        help="Comma-separated path globs to drop (e.g. 'vendor/**,fixtures/**').")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    report = assess(root, offline=args.offline)
    cli_excludes = [g.strip() for g in args.exclude.split(",") if g.strip()]
    if args.no_policy:
        if cli_excludes:
            report = policy_mod.apply(report, {"fail_on": [], "exclude": cli_excludes})
    else:
        pol = policy_mod.load_policy(root, args.policy)
        if cli_excludes:
            pol["exclude"] = list(pol.get("exclude", [])) + cli_excludes
        report = policy_mod.apply(report, pol)

    print(render(report, color=not args.no_color))
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2), encoding="utf-8")
    if args.html:
        import report as report_mod
        Path(args.html).write_text(report_mod.render_html(report), encoding="utf-8")
        print(f"  HTML report written to {args.html}")

    # CLI --fail-on wins; otherwise honor the policy gate.
    if args.fail_on:
        threshold = _SEV_RANK[args.fail_on.upper()]
        worst = min((_SEV_RANK[f["severity"]] for f in report["findings"]), default=99)
        if worst <= threshold:
            print(f"  ⛔ blast-radius gate: finding at/above {args.fail_on.upper()}.")
            return 1
    elif report.get("policy", {}).get("gate_failed"):
        by = ", ".join(report["policy"]["triggered_by"])
        print(f"  ⛔ policy gate failed (fail_on: {by}).")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
