"""
Shared rule engine for the Secure AI Pipeline MCP + REST servers.

The SAST rules and CVE data come from ``_rules_data.py`` — a bundled, in-package
copy that ``scripts/gen_rules.py`` regenerates from the ONE canonical source
(scripts/scanners/sast/ai_insecure_defaults.py + scanners/sca/known_cves.py). So
the MCP tools never drift from the rest of the product AND the server works when
the wheel is pip-installed, with no dependency on the scripts/ tree.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Optional

from ._rules_data import RULES as _CANON_SAST, KNOWN_CVES

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


def _compile(rule: dict):
    """Use the rule's Python regex. hardcoded-api-key has none (the pipeline
    treats it as a secret), so fall back to its VS Code trigger for snippet scans."""
    if rule.get("py"):
        return re.compile(rule["py"])
    js = rule.get("js") or {}
    if js.get("trigger"):
        return re.compile(js["trigger"],
                          re.IGNORECASE if "i" in (js.get("flags") or "") else 0)
    return None


# Built once from the canonical catalog (scanners.sast.ai_insecure_defaults) —
# edit a rule there and every channel, including this server, picks it up.
SAST_RULES: list[SastRule] = []
for _r in _CANON_SAST:
    _pat = _compile(_r)
    if _pat is None:
        continue
    SAST_RULES.append(SastRule(
        _r["id"], _r["severity"], "BLOCK" if _r["severity"] == "ERROR" else "WARN",
        _pat, _r["message"], _r["fix"]))

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
# SCA — KNOWN_CVES is imported from scanners.sca.known_cves above (the one source).
# ─────────────────────────────────────────────────────────────────────────────


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
    packages_missing: Optional[list[str]] = None,
    *,
    packages_unverified: int = 0,
) -> tuple[bool, str]:
    """Return (blocked, human_readable_summary).

    Only packages CONFIRMED missing on a registry block; unverified ones
    (offline / no registry checker) are reported as warnings.
    """
    packages_missing = packages_missing or []
    blocking = (
        [f for f in sast if is_blocking_sast(f)]
        + [f for f in sca if is_blocking_sca(f)]  # type: ignore[list-item]
    )
    blocked = bool(blocking) or bool(packages_missing)
    parts: list[str] = []
    if packages_missing:
        parts.append(f"{len(packages_missing)} non-existent package(s)")
    if packages_unverified:
        parts.append(f"{packages_unverified} unverified package(s)")
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


# ─────────────────────────────────────────────────────────────────────────────
# full_scan — the one orchestration both servers expose (REST + stdio MCP)
# ─────────────────────────────────────────────────────────────────────────────

# Offline fast-path of common real packages; anything else is verified against
# the live registry when a checker is supplied, and reported as "unverified"
# (warning, never blocking) when it isn't.
_COMMON_REAL_PACKAGES = {
    "flask", "flask_cors", "requests", "django", "fastapi", "sqlalchemy",
    "pydantic", "uvicorn", "gunicorn", "numpy", "pandas", "pytest", "click",
    "httpx", "aiohttp", "boto3", "redis", "celery", "jinja2", "werkzeug",
}


def full_scan(
    code: str = "",
    requirements: str = "",
    language: str = "python",
    check_registry=None,
) -> dict:
    """Run package, SAST and SCA checks together with one blocking decision.

    ``check_registry`` is an optional callable ``(package, registry) -> dict``
    (see registry.check_package). With it, unknown pinned deps get an
    authoritative live-registry verdict: confirmed-missing blocks, unreachable
    warns. Without it, unknown deps warn as "unverified" — a 20-name allowlist
    is not grounds to declare a real package non-existent.
    """
    sast_findings = sast_scan(code, language)
    sca_findings = sca_scan(requirements)

    known = {k[0] for k in KNOWN_CVES} | _COMMON_REAL_PACKAGES
    missing: list[str] = []
    unverified: list[dict] = []
    for pkg, _ver in parse_requirements(requirements):
        if pkg in known:
            continue
        if check_registry is not None:
            try:
                res = check_registry(pkg, "pypi")
            except Exception as exc:  # a checker crash must not kill the scan
                res = {"exists": None, "warning": f"registry check failed: {exc}"}
            if res.get("exists") is True:
                continue
            if res.get("exists") is False:
                missing.append(pkg)
            else:
                unverified.append({
                    "package": pkg,
                    "warning": res.get("warning") or "registry unreachable — could not verify",
                })
        else:
            unverified.append({
                "package": pkg,
                "warning": "not in the offline known-package list — verify with check_package",
            })

    blocked, summary = summarise(
        sast_findings, sca_findings, missing, packages_unverified=len(unverified)
    )
    return {
        "findings": {
            "sast": [f.to_dict() for f in sast_findings],
            "sca": [f.to_dict() for f in sca_findings],
            "packages": (
                [{"package": p, "warning": "not found on the registry — slopsquatting risk"}
                 for p in missing]
                + unverified
            ),
        },
        "blocked": blocked,
        "summary": summary,
    }
