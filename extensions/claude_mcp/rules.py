"""
Shared rule engine for the Secure AI Pipeline MCP server.

This mirrors the detection logic in ``scripts/run_pipeline.py`` so the MCP tools
return the same findings the CI pipeline would. Pure stdlib — no third-party
imports here, so it is trivially unit-testable and importable anywhere.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# SAST rules (mirror of run_pipeline.SAST_REGEX_RULES + a remediation hint)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SastRule:
    rule_id: str
    severity: str          # ERROR | WARNING
    action: str            # BLOCK | WARN
    pattern: "re.Pattern[str]"
    message: str
    fix: str


SAST_RULES: list[SastRule] = [
    SastRule(
        "flask-debug-true", "ERROR", "BLOCK",
        re.compile(r"app\.run\s*\(.*debug\s*=\s*True"),
        "Flask debug=True exposes the interactive debugger — arbitrary code execution.",
        'debug=os.getenv("FLASK_DEBUG", "false") == "true"',
    ),
    SastRule(
        "tls-verify-false", "ERROR", "BLOCK",
        re.compile(r"requests\.\w+\s*\(.*verify\s*=\s*False"),
        "TLS certificate verification disabled (verify=False) — allows MITM attacks.",
        "Remove verify=False (the default is verify=True).",
    ),
    SastRule(
        "wildcard-cors", "WARNING", "WARN",
        re.compile(r'origins\s*=\s*["\']\*["\']|Access-Control-Allow-Origin.*\*'),
        "Wildcard CORS — any origin can make credentialed requests to this API.",
        'Restrict to explicit origins, e.g. origins=["https://yourapp.example.com"].',
    ),
    SastRule(
        "subprocess-shell-true", "ERROR", "BLOCK",
        re.compile(r"subprocess\.\w+\s*\(.*shell\s*=\s*True"),
        "subprocess shell=True with user input → command injection.",
        'Pass an argument list and drop shell=True: subprocess.run(["ping", "-c", "1", host]).',
    ),
    SastRule(
        "sql-injection-fstring", "ERROR", "BLOCK",
        re.compile(r'\.execute\s*\(\s*f["\']|\.execute\s*\(\s*["\'].*%\s*\w|\.execute\s*\(\s*["\'].*\+\s*\w'),
        "SQL query built via f-string/concatenation → SQL injection.",
        'Use parameters: cursor.execute("SELECT * FROM t WHERE x=?", (val,)).',
    ),
    SastRule(
        "eval-user-input", "ERROR", "BLOCK",
        re.compile(r"eval\s*\(\s*request\.|exec\s*\(\s*request\."),
        "eval/exec on request data → arbitrary code execution.",
        "Remove eval/exec or replace with a safe parser.",
    ),
    SastRule(
        "hardcoded-api-key", "ERROR", "BLOCK",
        re.compile(
            r'(?i)(api_key|secret|password|token|passwd|auth_key|access_key)\s*=\s*["\']([A-Za-z0-9\-_]{8,})["\']'
        ),
        "Hardcoded credential in source.",
        'Load from the environment: os.environ["API_KEY"].',
    ),
]

_PLACEHOLDER_TOKENS = ("example", "placeholder", "changeme", "your_", "<", ">")


@dataclass
class SastFinding:
    rule: str
    line: int
    severity: str
    message: str
    fix: str

    def to_dict(self) -> dict:
        return asdict(self)


def sast_scan(code: str, language: str = "python") -> list[SastFinding]:
    """Run the regex SAST rules against a code string. ``language`` is accepted
    for API symmetry; the rules are Python-oriented but harmless on JS."""
    findings: list[SastFinding] = []
    for i, line in enumerate(code.splitlines(), 1):
        for rule in SAST_RULES:
            if not rule.pattern.search(line):
                continue
            if rule.rule_id == "hardcoded-api-key":
                low = line.lower()
                if any(tok in low for tok in _PLACEHOLDER_TOKENS):
                    continue
            findings.append(
                SastFinding(rule.rule_id, i, rule.severity, rule.message, rule.fix)
            )
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# SCA — known CVEs for pinned versions (mirror of run_pipeline.KNOWN_CVES)
# ─────────────────────────────────────────────────────────────────────────────

KNOWN_CVES: dict[tuple[str, str], list[dict]] = {
    ("flask", "1.0"): [
        {"id": "CVE-2023-30861", "severity": "HIGH", "fixed": "2.3.2",
         "desc": "Flask session cookie not invalidated on logout — session fixation."},
        {"id": "CVE-2018-1000656", "severity": "HIGH", "fixed": "0.12.3",
         "desc": "Werkzeug debug console PIN bypass — remote code execution."},
    ],
    ("requests", "2.18.0"): [
        {"id": "CVE-2023-32681", "severity": "MEDIUM", "fixed": "2.31.0",
         "desc": "Proxy-Authorization header leaked to third-party hosts on redirect."},
    ],
    ("flask_cors", "3.0.10"): [
        {"id": "CVE-2024-6221", "severity": "MEDIUM", "fixed": "4.0.0",
         "desc": "CORS policy bypass via crafted Origin header."},
    ],
}


@dataclass
class ScaFinding:
    package: str
    version: str
    cve: str
    severity: str
    fix_version: str

    def to_dict(self) -> dict:
        return asdict(self)


def parse_requirements(requirements: str) -> list[tuple[str, str]]:
    """Parse raw requirements.txt content into (normalised_name, version) pairs,
    skipping comments and blank lines."""
    result: list[tuple[str, str]] = []
    for line in requirements.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_\-.]+)==([^\s#]+)", line)
        if m:
            result.append((m.group(1).lower().replace("-", "_"), m.group(2)))
    return result


def sca_scan(requirements: str) -> list[ScaFinding]:
    findings: list[ScaFinding] = []
    for pkg, ver in parse_requirements(requirements):
        for cve in KNOWN_CVES.get((pkg, ver), []):
            findings.append(
                ScaFinding(pkg, ver, cve["id"], cve["severity"], cve["fixed"])
            )
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Severity → blocking decision (mirror of the gating policy table)
# ─────────────────────────────────────────────────────────────────────────────

def is_blocking_sast(f: SastFinding) -> bool:
    return f.severity == "ERROR"


def is_blocking_sca(f: ScaFinding) -> bool:
    return f.severity in ("CRITICAL", "HIGH")


def summarise(
    sast: list[SastFinding],
    sca: list[ScaFinding],
    package_warnings: Optional[list[str]] = None,
) -> tuple[bool, str]:
    """Return (blocked, human_readable_summary)."""
    package_warnings = package_warnings or []
    blocking = (
        [f for f in sast if is_blocking_sast(f)]
        + [f for f in sca if is_blocking_sca(f)]  # type: ignore[list-item]
    )
    blocked = bool(blocking) or bool(package_warnings)
    parts: list[str] = []
    if package_warnings:
        parts.append(f"{len(package_warnings)} non-existent package(s)")
    n_sast_block = sum(1 for f in sast if is_blocking_sast(f))
    n_sast_warn = len(sast) - n_sast_block
    if n_sast_block:
        parts.append(f"{n_sast_block} blocking code issue(s)")
    if n_sast_warn:
        parts.append(f"{n_sast_warn} code warning(s)")
    if sca:
        parts.append(f"{len(sca)} dependency CVE(s)")

    if not parts:
        return False, "No security findings — safe to proceed."
    verb = "BLOCKED" if blocked else "OK with warnings"
    return blocked, f"{verb}: " + ", ".join(parts) + "."
