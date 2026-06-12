"""GuardDog adapter — packages (malicious / suspicious). https://github.com/DataDog/guarddog

Datadog's malicious-package detector: it analyses each dependency's CODE and
metadata (Semgrep/heuristic rules) for attacker behaviour — exfiltration,
base64'd exec, install-time shells, typosquats. The OSS complement to our
anti-slopsquatting check: slopsquatting catches names that don't exist, GuardDog
catches names that exist but misbehave.
Registered into the scanner registry; returns None when the binary is absent.

stdlib only.
"""

from __future__ import annotations

import json
from typing import Optional

from external_tools import _run, _which
from scanners.registry import ScanContext, ToolAdapter, finding, register

_INSTALL = "pip install guarddog"

# Rule-name fragments that indicate ACTIVE malice (→ CRITICAL) vs merely
# suspicious patterns worth a human look (→ HIGH).
_CRITICAL_HINTS = ("exec", "exfiltrat", "code-execution", "download", "cmd-overwrite",
                   "silent-process", "steganography", "shady-links", "obfuscation", "bash")


def _severity_for(rule: str) -> str:
    r = (rule or "").lower()
    return "CRITICAL" if any(h in r for h in _CRITICAL_HINTS) else "HIGH"


def parse(data) -> list:
    """`guarddog <ecosystem> verify <manifest> --output-format json` → a list of
    per-package results: {package, version, issues, results: {rule: [matches]}}.
    `scan` of a single package returns one such dict."""
    if isinstance(data, dict):
        data = [data]
    out = []
    for entry in data or []:
        if not isinstance(entry, dict) or not entry.get("issues"):
            continue
        pkg = entry.get("package", "")
        version = entry.get("version", "")
        path = entry.get("path") or ""
        for rule, matches in (entry.get("results") or {}).items():
            if not matches:
                continue
            first = ""
            if isinstance(matches, list) and matches and isinstance(matches[0], dict):
                first = matches[0].get("message") or matches[0].get("code") or ""
            out.append(finding(
                _severity_for(rule),
                f"Suspicious package {pkg} {version} — {rule}",
                f"GuardDog rule '{rule}' matched in {pkg}@{version}"
                + (f": {first}" if first else "") + ". This package may be malicious.",
                str(path), 0,
                "Do NOT install this package. Verify the real package on the registry; "
                "if confirmed malicious, remove it and audit anything it executed.",
                "guarddog"))
    return out


def run(ctx: ScanContext) -> Optional[list]:
    if not _which("guarddog"):
        return None
    out: list = []
    from scanners.base import skip
    targets = []
    for req in sorted(ctx.root.rglob("requirements*.txt")):
        if not skip(req):
            targets.append(("pypi", req))
    for pkg_json in sorted(ctx.root.rglob("package.json")):
        if not skip(pkg_json):
            targets.append(("npm", pkg_json))
    for ecosystem, manifest in targets:
        proc = _run(["guarddog", ecosystem, "verify", str(manifest),
                     "--output-format", "json"])
        if proc is None:
            continue
        try:
            data = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError:
            continue
        out += parse(data)
    return out


register(ToolAdapter(name="guarddog", scan_type="packages", binary="guarddog",
                     run=run, install=_INSTALL, ci_install="pip install guarddog",
                     heavy=True))  # downloads + scans every dependency — opt-in via deep-scan
