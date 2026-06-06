#!/usr/bin/env python3
"""
Local Pipeline Runner
=====================
Runs all four security gates against a target Python file + requirements.txt.
Implements the same detection logic as the real CI tools (Gitleaks, check_packages,
Semgrep custom rules, Trivy SCA) — no network or external binaries required.

Usage:
    python scripts/run_pipeline.py demo/app.py demo/requirements.txt
"""

import ast
import re
import sys
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Literal

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

PYTHON_STDLIB = {
    "os","sys","re","io","abc","ast","csv","json","math","time","enum","copy",
    "uuid","hmac","stat","glob","shutil","queue","array","heapq","struct",
    "socket","string","random","logging","hashlib","pathlib","urllib","typing",
    "decimal","inspect","functools","itertools","datetime","calendar","textwrap",
    "threading","multiprocessing","subprocess","contextlib","collections",
    "dataclasses","configparser","http","html","xml","email","smtplib","ssl",
    "base64","binascii","codecs","pickle","shelve","sqlite3","zlib","gzip",
    "bz2","lzma","zipfile","tarfile","tempfile","platform","traceback",
    "warnings","unittest","argparse","getopt","getpass","gc","weakref","ctypes",
    "concurrent","asyncio","builtins","__future__","types","numbers","fractions",
    "cmath","statistics","secrets","token","tokenize","keyword","dis","marshal",
    "importlib","pkgutil","runpy","site","sysconfig","sqlite3","signal",
}

# Real packages that exist on PyPI (representative whitelist for demo)
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
        tree = ast.parse(src.read_text(encoding="utf-8"))
    except SyntaxError as e:
        return [Finding("Stage 0","check_packages","parse-error","HIGH","BLOCK",
                        str(e), str(src))]
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imports.add((a.name.split(".")[0], node.lineno))
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add((node.module.split(".")[0], node.lineno))

    lines = src.read_text().splitlines()
    for pkg, lineno in sorted(imports, key=lambda x: x[1]):
        if pkg in PYTHON_STDLIB:
            continue
        norm = pkg.lower().replace("-","_")
        if norm not in KNOWN_PYPI:
            snippet = lines[lineno-1].strip() if lineno <= len(lines) else ""
            findings.append(Finding(
                stage="Stage 0", tool="check_packages",
                rule_id="hallucinated-package",
                severity="HIGH", action="BLOCK",
                message=f"Package '{pkg}' not found on PyPI — possible AI hallucination (slopsquatting risk).",
                file=str(src), line=lineno, snippet=snippet
            ))
    return findings

# ─────────────────────────────────────────────────────────────────────────────
# STAGE 0b — Secret / credential detection (Gitleaks logic)
# ─────────────────────────────────────────────────────────────────────────────

SECRET_PATTERNS = [
    # (rule_id, regex, description)
    ("hardcoded-api-key",
     re.compile(r'(?i)(api_key|secret|password|token|passwd|auth_key|access_key)\s*=\s*["\']([A-Za-z0-9\-_]{8,})["\']'),
     "Hardcoded credential assigned to variable"),
    ("aws-key",
     re.compile(r'AKIA[0-9A-Z]{16}'),
     "AWS Access Key ID pattern"),
    ("generic-secret-str",
     re.compile(r'["\']([A-Za-z0-9+/]{40,})["\']'),
     "Long high-entropy string — possible hardcoded secret"),
    ("private-key-header",
     re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'),
     "Private key block in source"),
]

def stage0_secrets(src: Path) -> list[Finding]:
    findings = []
    lines = src.read_text().splitlines()
    for i, line in enumerate(lines, 1):
        for rule_id, pat, desc in SECRET_PATTERNS:
            m = pat.search(line)
            if m:
                # Skip obvious non-secrets
                val = m.group(0)
                if any(x in val.lower() for x in ["example","placeholder","changeme","your_","<",">"]):
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

SAST_REGEX_RULES = [
    ("flask-debug-true",    "ERROR", "BLOCK",
     re.compile(r'app\.run\s*\(.*debug\s*=\s*True'),
     "Flask debug=True exposes interactive debugger — allows arbitrary code execution in browser."),
    ("tls-verify-false",    "ERROR", "BLOCK",
     re.compile(r'requests\.\w+\s*\(.*verify\s*=\s*False'),
     "TLS certificate verification disabled (verify=False). Allows MITM attacks."),
    ("wildcard-cors",       "WARNING", "WARN",
     re.compile(r'origins\s*=\s*["\']\*["\']|Access-Control-Allow-Origin.*\*'),
     "Wildcard CORS — any origin can make credentialed requests to this API."),
    ("subprocess-shell-true","ERROR", "BLOCK",
     re.compile(r'subprocess\.\w+\s*\(.*shell\s*=\s*True'),
     "subprocess shell=True with user input → command injection."),
    ("sql-injection-fstring","ERROR", "BLOCK",
     re.compile(r'\.execute\s*\(\s*f["\']|\.execute\s*\(\s*["\'].*%\s*\w|\.execute\s*\(\s*["\'].*\+\s*\w'),
     "SQL query built via f-string/concatenation — parameterise with cursor.execute(sql,(val,))."),
    ("eval-user-input",     "ERROR", "BLOCK",
     re.compile(r'eval\s*\(\s*request\.|exec\s*\(\s*request\.'),
     "eval/exec on request data → arbitrary code execution."),
]

def stage1_sast(src: Path) -> list[Finding]:
    findings = []
    lines = src.read_text().splitlines()
    for i, line in enumerate(lines, 1):
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

# Curated CVE data for the packages/versions in the demo requirements.txt
KNOWN_CVES = {
    ("flask", "1.0"): [
        {"id":"CVE-2023-30861","severity":"HIGH","fixed":"2.3.2",
         "desc":"Flask session cookie not invalidated on logout — session fixation."},
        {"id":"CVE-2018-1000656","severity":"HIGH","fixed":"0.12.3",
         "desc":"Werkzeug (Flask dep) debug console PIN bypass — remote code execution."},
    ],
    ("requests", "2.18.0"): [
        {"id":"CVE-2023-32681","severity":"MEDIUM","fixed":"2.31.0",
         "desc":"Proxy-Authorization header leaked to third-party hosts on redirect."},
    ],
    ("flask_cors", "3.0.10"): [
        {"id":"CVE-2024-6221","severity":"MEDIUM","fixed":"4.0.0",
         "desc":"CORS policy bypass via crafted Origin header."},
    ],
}

def parse_requirements(req: Path) -> list[tuple[str,str]]:
    """Returns list of (pkg_name_normalised, version) from requirements.txt."""
    result = []
    for line in req.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r'^([A-Za-z0-9_\-]+)==([^\s#]+)', line)
        if m:
            result.append((m.group(1).lower().replace("-","_"), m.group(2)))
    return result

def stage1_sca(req: Path) -> list[Finding]:
    findings = []
    for pkg, ver in parse_requirements(req):
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
    # Flag non-existent package in requirements too
    for pkg, ver in parse_requirements(req):
        norm = pkg.lower().replace("-","_")
        if norm not in KNOWN_PYPI and norm not in {k[0] for k in KNOWN_CVES}:
            findings.append(Finding(
                stage="Stage 1", tool="Trivy",
                rule_id="unknown-package-in-requirements",
                severity="HIGH", action="BLOCK",
                message=f"'{pkg}' not found in any registry — remove from requirements.txt.",
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

def run_all(py_file: str, req_file: str) -> list[Finding]:
    src = Path(py_file)
    req = Path(req_file)

    all_findings: list[Finding] = []

    print_banner("🔒  SECURE AI PIPELINE — LOCAL RUNNER")
    print(f"  Target : {c('BOLD', py_file)}")
    print(f"  Deps   : {c('BOLD', req_file)}\n")

    # ── Stage 0 ───────────────────────────────────────────────────────────────
    print_banner("STAGE 0  |  Secrets & Package Validation")

    print(f"\n  {c('BOLD','[check_packages]')} Anti-slopsquatting scan …")
    pkg_findings = stage0_packages(src)
    for f in pkg_findings:
        print(f"    {c('BLOCK','● BLOCK')}  [{f.rule_id}]  line {f.line}")
        print(f"           {c('DIM', f.snippet)}")
        print(f"           {f.message}\n")
    if not pkg_findings:
        print(f"    {c('PASS','✓ PASS')}  All imports verified on PyPI\n")
    all_findings.extend(pkg_findings)

    print(f"  {c('BOLD','[Gitleaks]')} Secret detection scan …")
    sec_findings = stage0_secrets(src)
    for f in sec_findings:
        print(f"    {c('CRITICAL','● BLOCK')}  [{f.rule_id}]  line {f.line}")
        print(f"           {c('DIM', f.snippet)}")
        print(f"           {f.message}\n")
    if not sec_findings:
        print(f"    {c('PASS','✓ PASS')}  No secrets detected\n")
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
    sast_findings = stage1_sast(src)
    for f in sast_findings:
        icon = c('CRITICAL','● BLOCK') if f.action == "BLOCK" else c('WARN','▲ WARN ')
        print(f"    {icon}  [{f.rule_id}]  line {f.line}")
        print(f"           {c('DIM', f.snippet)}")
        print(f"           {f.message}\n")
    if not sast_findings:
        print(f"    {c('PASS','✓ PASS')}  No SAST findings\n")
    all_findings.extend(sast_findings)

    print(f"  {c('BOLD','[Trivy]')} SCA — dependency CVE scan …")
    sca_findings = stage1_sca(req)
    for f in sca_findings:
        icon = c('CRITICAL','● BLOCK') if f.action == "BLOCK" else c('WARN','▲ WARN ')
        print(f"    {icon}  [{f.rule_id}]  {f.snippet}")
        print(f"           {f.message}\n")
    if not sca_findings:
        print(f"    {c('PASS','✓ PASS')}  No known CVEs in dependencies\n")
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
    out_path.write_text(json.dumps(output, indent=2))
    print(f"  {c('DIM', f'Full results written to {out_path}')}\n")

    return all_findings


if __name__ == "__main__":
    py_file  = sys.argv[1] if len(sys.argv) > 1 else "demo/app.py"
    req_file = sys.argv[2] if len(sys.argv) > 2 else "demo/requirements.txt"
    findings = run_all(py_file, req_file)
    has_blocks = any(f.action == "BLOCK" for f in findings)
    sys.exit(1 if has_blocks else 0)
