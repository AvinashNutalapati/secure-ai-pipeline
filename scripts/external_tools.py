#!/usr/bin/env python3
"""
Adapters for the open-source security scanners the pipeline shells out to.

Each tool is optional. ``run_*`` returns a list of normalised finding dicts
when the tool is installed and produced output, or ``None`` when the tool is
absent (so the orchestrator can fall back to its built-in Python scanners). A
crash in any adapter degrades to ``None`` — a missing or broken scanner must
never take down the whole scan.

All scanners here are open source:
  - gitleaks      secrets            https://github.com/gitleaks/gitleaks
  - semgrep       SAST (SARIF)       https://github.com/semgrep/semgrep
  - trivy         SCA + vulns        https://github.com/aquasecurity/trivy
  - osv-scanner   malicious + vulns  https://github.com/google/osv-scanner
  - zap           DAST               https://github.com/zaproxy/zaproxy

Socket.dev is intentionally NOT hard-wired: it is a paid/closed service that
needs an account and API key, which conflicts with the OSS-only goal. OSV-Scanner
reads the OSV `MAL-` malicious-package advisories — the open equivalent of
Socket's core malicious-dependency feature. See socket_hint() for the opt-in path.

Normalised finding dict:
    {"severity": str, "title": str, "detail": str,
     "file": str, "line": int, "fix": str, "tool": str}

stdlib only.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Per-tool install hint shown when a tool is missing.
INSTALL_HINTS = {
    "gitleaks": "brew install gitleaks   (or: https://github.com/gitleaks/gitleaks/releases)",
    "semgrep": "pipx install semgrep   (or: brew install semgrep)",
    "trivy": "brew install trivy   (or: https://trivy.dev/latest/getting-started/installation/)",
    "osv-scanner": "brew install osv-scanner   (or: go install github.com/google/osv-scanner/cmd/osv-scanner@latest)",
    "docker": "https://docs.docker.com/get-docker/   (needed for the ZAP DAST scan)",
}

# Tool name -> the scan type(s) it feeds, for the preflight summary.
TOOL_ROLES = {
    "gitleaks": "secrets",
    "semgrep": "sast",
    "trivy": "sca",
    "osv-scanner": "sca / malicious packages",
    "docker": "dast (ZAP)",
}


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


def detect() -> dict:
    """Return {tool_name: path_or_None} for every scanner we know about."""
    return {name: _which(name) for name in TOOL_ROLES}


def _norm_sev(value: str, default: str = "MEDIUM") -> str:
    v = (value or "").strip().upper()
    if v in SEVERITIES:
        return v
    # Common aliases across tools.
    return {
        "ERROR": "HIGH", "WARNING": "MEDIUM", "WARN": "MEDIUM", "NOTE": "LOW",
        "INFORMATION": "INFO", "INFORMATIONAL": "INFO", "UNKNOWN": "LOW",
        "MODERATE": "MEDIUM", "IMPORTANT": "HIGH", "NEGLIGIBLE": "LOW",
    }.get(v, default)


def _default_timeout() -> int:
    """Per-tool wall-clock cap. Bounded so one slow/hung scanner can't stall the
    whole job, but generous (10 min) so a legitimately slow scan on a large repo
    (Trivy/Semgrep DB build, big monorepo) isn't cut off and its findings dropped.
    Tools run in parallel, so this is a per-tool cap, not the total. Override with
    SAP_TOOL_TIMEOUT (seconds)."""
    try:
        return int(os.environ.get("SAP_TOOL_TIMEOUT", "600"))
    except ValueError:
        return 600


def _run(cmd: list, timeout: Optional[int] = None, cwd=None) -> Optional[subprocess.CompletedProcess]:
    """Run a tool, returning the completed process or None on any failure
    (including a timeout — a tool that overruns its budget is skipped, not fatal).
    Tools legitimately exit non-zero when they find issues, so the caller inspects
    output rather than the return code. ``cwd`` runs the tool from a directory
    (needed by tools that take package globs like gosec's ./...)."""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout if timeout is not None else _default_timeout(),
            check=False, cwd=str(cwd) if cwd else None,
        )
    except (OSError, subprocess.SubprocessError):
        return None


# ── gitleaks (secrets) ───────────────────────────────────────────────────────

def parse_gitleaks(data) -> list:
    """gitleaks --report-format json → a JSON array of finding objects."""
    out = []
    for f in data or []:
        rule = f.get("RuleID") or f.get("Description") or "secret"
        desc = f.get("Description") or rule
        out.append({
            "severity": "CRITICAL",  # a committed live secret is always blocking
            "title": f"Secret detected: {desc}",
            "detail": f"Rule '{rule}' matched. Rotate this credential immediately; "
                      "a leaked secret is valid until revoked.",
            "file": f.get("File", ""),
            "line": int(f.get("StartLine") or 0),
            "fix": "Remove the secret, load it from the environment / a secrets "
                   "manager, and rotate the exposed value.",
            "tool": "gitleaks",
        })
    return out


def run_gitleaks(root: Path) -> Optional[list]:
    if not _which("gitleaks"):
        return None
    with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as tf:
        report = tf.name
    try:
        # --no-git scans the working tree (predictable locally); the full
        # git-history scan is the CI job. --exit-code 0 so "found secrets" is
        # not treated as a tool failure.
        _run(["gitleaks", "detect", "--source", str(root), "--no-git",
              "--report-format", "json", "--report-path", report,
              "--exit-code", "0", "--no-banner"])
        try:
            data = json.loads(Path(report).read_text(encoding="utf-8") or "[]")
        except (json.JSONDecodeError, OSError):
            return []
        return parse_gitleaks(data)
    finally:
        try:
            os.unlink(report)
        except OSError:
            pass


# ── semgrep (SAST, SARIF) ────────────────────────────────────────────────────

def parse_sarif(data, tool: str = "semgrep") -> list:
    """Parse a SARIF document into normalised SAST findings."""
    out = []
    for run in (data or {}).get("runs", []):
        rules = {r.get("id"): r
                 for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            rule_id = res.get("ruleId", "")
            rule = rules.get(rule_id, {})
            level = res.get("level") or \
                rule.get("defaultConfiguration", {}).get("level", "warning")
            # Prefer an explicit numeric security-severity (CVSS) in rule
            # metadata; otherwise fall back to the SARIF level.
            cvss = rule.get("properties", {}).get("security-severity")
            sev = _cvss_band(cvss) if cvss not in (None, "") else _norm_sev(level)
            msg = (res.get("message", {}).get("text", "") or rule_id).strip()
            loc = (res.get("locations") or [{}])[0].get(
                "physicalLocation", {})
            uri = loc.get("artifactLocation", {}).get("uri", "")
            line = loc.get("region", {}).get("startLine", 0)
            fix = ""
            help_txt = rule.get("help", {}).get("text") or \
                rule.get("fullDescription", {}).get("text", "")
            out.append({
                "severity": sev,
                "title": msg.split("\n")[0][:120] or rule_id,
                "detail": msg + (f"\n[{rule_id}]" if rule_id else ""),
                "file": uri,
                "line": int(line or 0),
                "fix": help_txt[:300],
                "tool": tool,
            })
    return out


def _cvss_band(score) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "MEDIUM"
    return ("CRITICAL" if s >= 9 else "HIGH" if s >= 7 else
            "MEDIUM" if s >= 4 else "LOW")


def run_semgrep(root: Path, extra_config: Optional[Path] = None) -> Optional[list]:
    if not _which("semgrep"):
        return None
    configs = ["--config", "p/security-audit",
               "--config", "p/python", "--config", "p/javascript"]
    if extra_config and Path(extra_config).exists():
        configs += ["--config", str(extra_config)]
    with tempfile.NamedTemporaryFile("r", suffix=".sarif", delete=False) as tf:
        out_file = tf.name
    try:
        proc = _run(["semgrep", "scan", *configs, "--sarif",
                     "--output", out_file, "--quiet", "--metrics=off", str(root)])
        if proc is None:
            return []
        try:
            data = json.loads(Path(out_file).read_text(encoding="utf-8") or "{}")
        except (json.JSONDecodeError, OSError):
            return []
        return parse_sarif(data, tool="semgrep")
    finally:
        try:
            os.unlink(out_file)
        except OSError:
            pass


# ── trivy (SCA + vulnerabilities) ────────────────────────────────────────────

def parse_trivy(data) -> list:
    out = []
    for result in (data or {}).get("Results", []) or []:
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities", []) or []:
            pkg = v.get("PkgName", "")
            installed = v.get("InstalledVersion", "")
            fixed = v.get("FixedVersion", "")
            vid = v.get("VulnerabilityID", "")
            out.append({
                "severity": _norm_sev(v.get("Severity", "MEDIUM")),
                "title": f"{pkg} {installed} — {vid}",
                "detail": (v.get("Title") or v.get("Description", ""))[:400] +
                          f"\nPackage: {pkg}@{installed}  ({target})",
                "file": target,
                "line": 0,
                "fix": (f"Upgrade {pkg} to >= {fixed}." if fixed
                        else "No fixed version published yet — assess exposure / pin away."),
                "tool": "trivy",
            })
    return out


def run_trivy(root: Path) -> Optional[list]:
    if not _which("trivy"):
        return None
    proc = _run(["trivy", "fs", "--quiet", "--format", "json",
                 "--scanners", "vuln", str(root)])
    if proc is None:
        return []
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return []
    return parse_trivy(data)


# ── osv-scanner (malicious packages + vulnerabilities) ───────────────────────

def parse_osv(data) -> list:
    out = []
    for result in (data or {}).get("results", []) or []:
        source = result.get("source", {}).get("path", "")
        for pkg in result.get("packages", []) or []:
            info = pkg.get("package", {})
            name = info.get("name", "")
            version = info.get("version", "")
            for vuln in pkg.get("vulnerabilities", []) or []:
                vid = vuln.get("id", "")
                malicious = vid.startswith("MAL-") or "malicious" in \
                    (vuln.get("summary", "").lower())
                sev = "CRITICAL" if malicious else _osv_severity(vuln)
                label = "MALICIOUS PACKAGE" if malicious else "Vulnerable dependency"
                out.append({
                    "severity": sev,
                    "title": f"{label}: {name} {version} — {vid}",
                    "detail": (vuln.get("summary") or vid)[:400] +
                              f"\nPackage: {name}@{version}  ({source})",
                    "file": source,
                    "line": 0,
                    "fix": ("Remove this dependency NOW and audit anything it ran — "
                            "it is flagged as malicious." if malicious else
                            "Upgrade to a patched version; see the OSV advisory."),
                    "tool": "osv-scanner",
                })
    return out


def _osv_severity(vuln) -> str:
    db = vuln.get("database_specific", {})
    if isinstance(db, dict) and db.get("severity"):
        return _norm_sev(str(db["severity"]))
    for s in vuln.get("severity", []) or []:
        if s.get("type", "").startswith("CVSS"):
            return _cvss_band(_cvss_base(s.get("score", "")))
    return "MEDIUM"


def _cvss_base(vector) -> float:
    # OSV CVSS scores are vectors, not numbers; without a parser we can't derive
    # the base score, so treat as medium-ish unless it's clearly a number.
    try:
        return float(vector)
    except (TypeError, ValueError):
        return 5.0


def run_osv(root: Path) -> Optional[list]:
    if not _which("osv-scanner"):
        return None
    proc = _run(["osv-scanner", "--format", "json", "-r", str(root)])
    if proc is None:
        return []
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return []
    return parse_osv(data)


# ── ZAP (DAST) ───────────────────────────────────────────────────────────────

def parse_zap(data) -> list:
    out = []
    risk_to_sev = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
    for site in (data or {}).get("site", []) or []:
        host = site.get("@name", "")
        for alert in site.get("alerts", []) or []:
            riskcode = str(alert.get("riskcode", "1"))
            instances = alert.get("instances", []) or []
            uri = instances[0].get("uri", host) if instances else host
            out.append({
                "severity": risk_to_sev.get(riskcode, "LOW"),
                "title": alert.get("alert", "DAST finding"),
                "detail": _strip_html(alert.get("desc", ""))[:400] +
                          f"\nInstances: {len(instances)}  ({host})",
                "file": uri,
                "line": 0,
                "fix": _strip_html(alert.get("solution", ""))[:300],
                "tool": "zap",
            })
    return out


def _strip_html(text: str) -> str:
    import re
    return re.sub(r"<[^>]+>", "", text or "").strip()


def run_zap(url: str, rules_file: Optional[Path] = None) -> Optional[list]:
    """Run the ZAP baseline scan against a live URL.

    Prefers a local zap-baseline.py; otherwise uses the official Docker image.
    Returns None when neither ZAP nor Docker is available.
    """
    local = _which("zap-baseline.py")
    have_docker = _which("docker")
    if not local and not have_docker:
        return None
    with tempfile.TemporaryDirectory() as workdir:
        report = "zap.json"
        report_path = Path(workdir) / report
        if local:
            cmd = ["zap-baseline.py", "-t", url, "-J", str(report_path), "-I"]
            if rules_file and Path(rules_file).exists():
                cmd += ["-c", str(rules_file)]
        else:
            # The ZAP container only sees the mounted workdir, so the report
            # path is relative to /zap/wrk inside the container.
            cmd = ["docker", "run", "--rm", "-v", f"{workdir}:/zap/wrk/:rw",
                   "ghcr.io/zaproxy/zaproxy:stable",
                   "zap-baseline.py", "-t", url, "-J", report, "-I"]
        _run(cmd, timeout=900)
        try:
            data = json.loads(report_path.read_text(encoding="utf-8") or "{}")
        except (json.JSONDecodeError, OSError):
            return []
        return parse_zap(data)


# ── Socket.dev (optional, opt-in) ────────────────────────────────────────────

def socket_hint() -> Optional[str]:
    """Socket is closed-source and needs an API key; we don't run it by default.
    Returns an opt-in hint when a key is configured but the CLI is missing."""
    if os.getenv("SOCKET_SECURITY_API_KEY") or os.getenv("SOCKET_API_KEY"):
        if not _which("socket"):
            return ("SOCKET_*_API_KEY is set but the `socket` CLI isn't installed: "
                    "`npm i -g @socketsecurity/cli`. (OSV-Scanner already covers "
                    "malicious packages with no account.)")
    return None
