#!/usr/bin/env python3
"""
Local Pipeline Runner
=====================
Runs all four security gates against a target Python file + requirements.txt.
Implements the same detection logic as the real CI tools (Gitleaks, check_packages,
Semgrep custom rules, Trivy SCA) — no network or external binaries required.

Usage:
    python scripts/run_pipeline.py path/to/app.py [path/to/requirements.txt]
"""

import ast
import re
import sys
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Literal, Optional

# Make sibling modules importable regardless of the invocation directory, then
# share the stdlib allowlist with the authoritative network guard — one source
# of truth instead of a second, drifting copy.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_packages import PYTHON_STDLIB  # noqa: E402
# Rule data lives once, per scan type, under scanners/<type>/ — this runner just
# applies it. Edit those files to improve a check everywhere it's used.
from scanners.sast.ai_insecure_defaults import SAST_REGEX_RULES  # noqa: E402
from scanners.sca.known_cves import KNOWN_CVES  # noqa: E402
from scanners.secrets.code_secrets import (  # noqa: E402
    SECRET_PATTERNS, is_placeholder as _is_placeholder,
)

# ─────────────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────────────

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
Action   = Literal["BLOCK", "WARN", "INFO"]

@dataclass
class Finding:
    stage: str
    tool: str
    rule_id: str
    severity: Severity
    action: Action
    message: str
    file: str
    line: int = 0
    snippet: str = ""

# ─────────────────────────────────────────────────────────────────────────────
# Shared utilities
# ─────────────────────────────────────────────────────────────────────────────

# Inline suppression: a line carrying one of these markers is skipped by the
# secret and SAST line scanners (same convention as Semgrep's `nosemgrep` and
# Bandit's `nosec`). Lets users silence a confirmed-safe match in place.
_SUPPRESS_RE = re.compile(r"\bnosemgrep\b|\bnosec\b|sap-ignore", re.IGNORECASE)

# Offline fast-path of known-real PyPI packages. Deliberately NOT exhaustive:
# names outside this list WARN (never block) and point to the network guard
# (check_packages.py), which gives the authoritative verdict.
KNOWN_PYPI = {
    "flask","flask_cors","requests","django","fastapi","sqlalchemy","celery",
    "redis","boto3","pandas","numpy","scipy","matplotlib","pillow","pytest",
    "click","pydantic","httpx","aiohttp","uvicorn","gunicorn","cryptography",
    "paramiko","bcrypt","passlib","jwt","stripe","sendgrid","twilio",
    "psycopg2","pymongo","elasticsearch","kafka","pika","grpc","protobuf",
    "tensorflow","torch","sklearn","transformers","openai","anthropic",
    "langchain","llama_index","chromadb","pinecone","weaviate","qdrant",
    "alembic","marshmallow","cerberus","wtforms","jinja2","mako","yaml",
    "toml","dotenv","colorama","rich","typer","loguru","structlog",
    "werkzeug","itsdangerous","markupsafe","six","certifi","urllib3",
    "chardet","idna","charset_normalizer","attrs","cattrs","pydantic_v2",
}

# ─────────────────────────────────────────────────────────────────────────────
# STAGE 0a — Package existence check (anti-slopsquatting)
# ─────────────────────────────────────────────────────────────────────────────

def stage0_packages(src: Path) -> list[Finding]:
    findings = []
    try:
        tree = ast.parse(src.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError as e:
        return [Finding("Stage 0","check_packages","parse-error","HIGH","BLOCK",
                        str(e), str(src))]
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imports.add((a.name.split(".")[0], node.lineno))
        elif isinstance(node, ast.ImportFrom):
            # Relative imports (`from .utils import x`) resolve locally —
            # never a registry package.
            if node.level and node.level > 0:
                continue
            if node.module:
                imports.add((node.module.split(".")[0], node.lineno))

    lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
    for pkg, lineno in sorted(imports, key=lambda x: x[1]):
        if pkg in PYTHON_STDLIB:
            continue
        norm = pkg.lower().replace("-","_")
        if norm not in KNOWN_PYPI:
            snippet = lines[lineno-1].strip() if lineno <= len(lines) else ""
            # Offline heuristic: an unknown name is UNVERIFIED, not proven
            # hallucinated — warn and defer the hard verdict to the network
            # guard so real packages are never blocked locally.
            findings.append(Finding(
                stage="Stage 0", tool="check_packages",
                rule_id="unverified-package",
                severity="MEDIUM", action="WARN",
                message=(f"'{pkg}' is not in the offline known-package list. "
                         "Verify it exists before installing: "
                         "`python scripts/check_packages.py .` (network check)."),
                file=str(src), line=lineno, snippet=snippet
            ))
    return findings

# ─────────────────────────────────────────────────────────────────────────────
# STAGE 0b — Secret / credential detection (Gitleaks logic)
# ─────────────────────────────────────────────────────────────────────────────

# SECRET_PATTERNS + the placeholder logic now live in
# scanners/secrets/code_secrets.py (imported at the top).

def stage0_secrets(src: Path) -> list[Finding]:
    findings = []
    lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
    for i, line in enumerate(lines, 1):
        if _SUPPRESS_RE.search(line):
            continue
        for rule_id, pat, desc in SECRET_PATTERNS:
            m = pat.search(line)
            if m:
                # Check the captured VALUE (last group) against whole-value
                # placeholder shapes only.
                value = m.group(m.lastindex) if m.lastindex else m.group(0)
                if _is_placeholder(value):
                    continue
                findings.append(Finding(
                    stage="Stage 0", tool="Gitleaks",
                    rule_id=rule_id,
                    severity="CRITICAL", action="BLOCK",
                    message=f"{desc}: `{line.strip()}`",
                    file=str(src), line=i, snippet=line.strip()
                ))
    return findings

# ─────────────────────────────────────────────────────────────────────────────
# STAGE 1a — SAST (Semgrep custom rules reimplemented as AST + regex)
# ─────────────────────────────────────────────────────────────────────────────

# SAST_REGEX_RULES now lives in scanners/sast/ai_insecure_defaults.py (imported above).

def stage1_sast(src: Path) -> list[Finding]:
    findings = []
    lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
    for i, line in enumerate(lines, 1):
        if _SUPPRESS_RE.search(line):
            continue
        for rule_id, sev, action, pat, msg in SAST_REGEX_RULES:
            if pat.search(line):
                findings.append(Finding(
                    stage="Stage 1", tool="Semgrep",
                    rule_id=rule_id,
                    severity=sev, action=action,
                    message=msg,
                    file=str(src), line=i, snippet=line.strip()
                ))
    return findings

# ─────────────────────────────────────────────────────────────────────────────
# STAGE 1b — SCA (Trivy: known CVEs for pinned dependency versions)
# ─────────────────────────────────────────────────────────────────────────────

# KNOWN_CVES now lives in scanners/sca/known_cves.py (imported above).

def parse_requirements(req: Optional[Path]) -> list[tuple[str,str]]:
    """Returns list of (pkg_name_normalised, version) from requirements.txt.
    Returns [] if no requirements file was given."""
    result = []
    if not req or not req.is_file():
        return result
    for line in req.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r'^([A-Za-z0-9_\-.]+)==([^\s#]+)', line)
        if m:
            result.append((m.group(1).lower().replace("-","_"), m.group(2)))
    return result

def stage1_sca(req: Optional[Path]) -> list[Finding]:
    findings = []
    if req is not None and not req.is_file():
        # A path was given but doesn't exist — say so instead of silently
        # printing a green PASS (a typo'd path must not skip the CVE gate).
        return [Finding(
            stage="Stage 1", tool="Trivy",
            rule_id="requirements-not-found",
            severity="MEDIUM", action="WARN",
            message=f"Requirements file '{req}' not found — SCA was SKIPPED. Fix the path to scan dependencies.",
            file=str(req)
        )]
    pinned = parse_requirements(req)
    known_cve_pkgs = {k[0] for k in KNOWN_CVES}
    for pkg, ver in pinned:
        for cve_data in KNOWN_CVES.get((pkg, ver), []):
            sev = cve_data["severity"]
            action = "BLOCK" if sev in ("CRITICAL","HIGH") else "WARN"
            findings.append(Finding(
                stage="Stage 1", tool="Trivy",
                rule_id=cve_data["id"],
                severity=sev, action=action,
                message=f"{pkg}=={ver} → {cve_data['id']}: {cve_data['desc']} (fix: >={cve_data['fixed']})",
                file=str(req), snippet=f"{pkg}=={ver}"
            ))
        # Same offline-heuristic stance as stage0: unknown → verify, not block.
        if pkg not in KNOWN_PYPI and pkg not in known_cve_pkgs:
            findings.append(Finding(
                stage="Stage 1", tool="Trivy",
                rule_id="unknown-package-in-requirements",
                severity="MEDIUM", action="WARN",
                message=(f"'{pkg}' is not in the offline known-package list — verify it on PyPI "
                         "(`python scripts/check_packages.py .`) before installing."),
                file=str(req), snippet=f"{pkg}=={ver}"
            ))
    return findings

# ─────────────────────────────────────────────────────────────────────────────
# Output helpers
# ─────────────────────────────────────────────────────────────────────────────

ANSI = {
    "CRITICAL": "\033[91m\033[1m",  # bold red
    "HIGH":     "\033[91m",          # red
    "MEDIUM":   "\033[93m",          # yellow
    "LOW":      "\033[96m",          # cyan
    "INFO":     "\033[97m",          # white
    "BLOCK":    "\033[91m\033[1m",
    "WARN":     "\033[93m",
    "PASS":     "\033[92m\033[1m",
    "RESET":    "\033[0m",
    "DIM":      "\033[2m",
    "BOLD":     "\033[1m",
}

def c(color: str, text: str) -> str:
    return f"{ANSI[color]}{text}{ANSI['RESET']}"

def print_banner(text: str):
    line = "─" * 70
    print(f"\n{c('BOLD', line)}")
    print(f"  {c('BOLD', text)}")
    print(c('BOLD', line))

def _safe(stage: str, tool: str, fn, *args) -> list[Finding]:
    """Run one gate; a crash becomes a visible finding instead of killing the
    rest of the pipeline (and losing every other gate's findings)."""
    try:
        return fn(*args)
    except Exception as exc:
        return [Finding(
            stage=stage, tool=tool, rule_id=f"{tool.lower()}-runner-error",
            severity="HIGH", action="WARN",
            message=(f"{tool} gate crashed ({exc.__class__.__name__}: {exc}) — "
                     "findings from this gate are incomplete."),
            file="",
        )]


def _print_findings(findings: list[Finding], pass_msg: str, *, by_line: bool = True) -> None:
    for f in findings:
        icon = c('CRITICAL', '● BLOCK') if f.action == "BLOCK" else c('WARN', '▲ WARN ')
        where = f"line {f.line}" if by_line else f.snippet
        print(f"    {icon}  [{f.rule_id}]  {where}")
        if by_line and f.snippet:
            print(f"           {c('DIM', f.snippet)}")
        print(f"           {f.message}\n")
    if not findings:
        print(f"    {c('PASS','✓ PASS')}  {pass_msg}\n")


def run_all(py_file: str, req_file: str) -> list[Finding]:
    src = Path(py_file)
    req = Path(req_file) if req_file else None

    all_findings: list[Finding] = []

    print_banner("🔒  SECURE AI PIPELINE — LOCAL RUNNER")
    print(f"  Target : {c('BOLD', py_file)}")
    print(f"  Deps   : {c('BOLD', req_file or '(none — SCA will be skipped)')}\n")

    # ── Stage 0 ───────────────────────────────────────────────────────────────
    print_banner("STAGE 0  |  Secrets & Package Validation")

    print(f"\n  {c('BOLD','[check_packages]')} Anti-slopsquatting scan …")
    pkg_findings = _safe("Stage 0", "check_packages", stage0_packages, src)
    _print_findings(pkg_findings, "All imports are stdlib or known-real packages")
    all_findings.extend(pkg_findings)

    print(f"  {c('BOLD','[Gitleaks]')} Secret detection scan …")
    sec_findings = _safe("Stage 0", "Gitleaks", stage0_secrets, src)
    _print_findings(sec_findings, "No secrets detected")
    all_findings.extend(sec_findings)

    stage0_blocked = [f for f in all_findings if f.stage == "Stage 0" and f.action == "BLOCK"]
    if stage0_blocked:
        print(f"  {c('CRITICAL','⛔  Stage 0 FAILED')} — {len(stage0_blocked)} blocking finding(s). Stage 1 will NOT run in CI.")
        print(f"  {c('DIM','(Running Stage 1 here anyway to show all findings)')} \n")
    else:
        print(f"  {c('PASS','✓ Stage 0 PASSED')} — proceeding to Stage 1\n")

    # ── Stage 1 ───────────────────────────────────────────────────────────────
    print_banner("STAGE 1  |  SAST + SCA")

    print(f"\n  {c('BOLD','[Semgrep]')} Static analysis (AI insecure-defaults ruleset) …")
    sast_findings = _safe("Stage 1", "Semgrep", stage1_sast, src)
    _print_findings(sast_findings, "No SAST findings")
    all_findings.extend(sast_findings)

    print(f"  {c('BOLD','[Trivy]')} SCA — dependency CVE scan …")
    sca_findings = _safe("Stage 1", "Trivy", stage1_sca, req)
    sca_pass = ("No known CVEs in dependencies" if req
                else "No requirements file provided — SCA skipped")
    _print_findings(sca_findings, sca_pass, by_line=False)
    all_findings.extend(sca_findings)

    # ── Stage 2 ───────────────────────────────────────────────────────────────
    print_banner("STAGE 2  |  DAST (ZAP Baseline)")
    print(f"\n  {c('DIM','Skipped — STAGING_URL not set. DAST runs against a live deploy.')}")
    print(f"  {c('DIM','Set the STAGING_URL repo variable to enable ZAP scanning.')}\n")

    # ── Summary ───────────────────────────────────────────────────────────────
    print_banner("PIPELINE SUMMARY")
    blocks = [f for f in all_findings if f.action == "BLOCK"]
    warns  = [f for f in all_findings if f.action == "WARN"]

    stage_results = {}
    for f in all_findings:
        stage_results.setdefault(f.stage, {"BLOCK": 0, "WARN": 0})
        stage_results[f.stage][f.action] = stage_results[f.stage].get(f.action, 0) + 1

    for stage, counts in sorted(stage_results.items()):
        b = counts.get("BLOCK", 0)
        w = counts.get("WARN", 0)
        status = c('CRITICAL','FAILED') if b else c('WARN','WARNING') if w else c('PASS','PASSED')
        print(f"  {stage:<12}  {status}   {b} block(s)  {w} warn(s)")

    print(f"\n  Total   :  {c('CRITICAL', str(len(blocks)))} blocking  |  {c('WARN', str(len(warns)))} warnings\n")

    if blocks:
        print(c('CRITICAL', f"  ⛔  BUILD BLOCKED — fix the {len(blocks)} issue(s) above before this can merge.\n"))
    else:
        print(c('PASS', "  ✅  No blocking findings — safe to proceed.\n"))

    # Machine-readable JSON output
    output = [
        {"stage": f.stage, "tool": f.tool, "rule": f.rule_id,
         "severity": f.severity, "action": f.action,
         "file": f.file, "line": f.line, "message": f.message,
         "snippet": f.snippet}
        for f in all_findings
    ]
    out_path = Path(__file__).parent.parent / "pipeline-results.json"
    out_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"  {c('DIM', f'Full results written to {out_path}')}\n")

    return all_findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: run_pipeline.py <code_file> [requirements_file]", file=sys.stderr)
        sys.exit(2)
    py_file = sys.argv[1]
    req_file = sys.argv[2] if len(sys.argv) > 2 else ""
    findings = run_all(py_file, req_file)
    has_blocks = any(f.action == "BLOCK" for f in findings)
    sys.exit(1 if has_blocks else 0)
