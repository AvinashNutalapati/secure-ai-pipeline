"""
Secure AI Pipeline — MCP server.

A FastAPI app exposing the pipeline's security checks as tool endpoints that
Claude Code can call mid-session. Run it with:

    uvicorn extensions.claude_mcp.server:app --port 8765

or via the installed console script:

    sap-mcp
"""

from __future__ import annotations

from typing import Literal, Optional

import requests
from fastapi import FastAPI
from pydantic import BaseModel, Field

from . import rules

app = FastAPI(
    title="Secure AI Pipeline MCP Server",
    description="Security scanner for AI-generated code.",
    version="1.0.0",
)

PYPI_URL = "https://pypi.org/pypi/{pkg}/json"
NPM_URL = "https://registry.npmjs.org/{pkg}"


# ── check_package ────────────────────────────────────────────────────────────

class CheckPackageRequest(BaseModel):
    package: str = Field(..., description="Package name to verify.")
    registry: Literal["pypi", "npm"] = "pypi"


class CheckPackageResponse(BaseModel):
    exists: bool
    latest_version: Optional[str] = None
    warning: Optional[str] = None


@app.post("/check_package", response_model=CheckPackageResponse)
def check_package(req: CheckPackageRequest) -> CheckPackageResponse:
    """Verify a package exists on PyPI or npm before importing it."""
    name = req.package.strip()
    try:
        if req.registry == "pypi":
            resp = requests.get(PYPI_URL.format(pkg=name), timeout=10)
            if resp.status_code == 200:
                version = resp.json().get("info", {}).get("version")
                return CheckPackageResponse(exists=True, latest_version=version)
        else:
            encoded = name.replace("/", "%2F")
            resp = requests.get(NPM_URL.format(pkg=encoded), timeout=10)
            if resp.status_code == 200:
                version = resp.json().get("dist-tags", {}).get("latest")
                return CheckPackageResponse(exists=True, latest_version=version)
    except requests.RequestException as exc:
        return CheckPackageResponse(
            exists=False, warning=f"Could not reach {req.registry}: {exc}"
        )

    return CheckPackageResponse(
        exists=False,
        warning=(
            f"'{name}' was not found on {req.registry}. This is a slopsquatting risk — "
            "AI models invent plausible package names that attackers pre-register. "
            "Do not install it without confirming the correct name."
        ),
    )


# ── sast_scan ────────────────────────────────────────────────────────────────

class SastRequest(BaseModel):
    code: str
    language: Literal["python", "javascript"] = "python"


class SastResponse(BaseModel):
    findings: list[dict]


@app.post("/sast_scan", response_model=SastResponse)
def sast_scan(req: SastRequest) -> SastResponse:
    """Scan a code snippet for insecure patterns (injection, hardcoded secrets, etc.)."""
    findings = rules.sast_scan(req.code, req.language)
    return SastResponse(findings=[f.to_dict() for f in findings])


# ── sca_scan ─────────────────────────────────────────────────────────────────

class ScaRequest(BaseModel):
    requirements: str


class ScaResponse(BaseModel):
    vulnerabilities: list[dict]


@app.post("/sca_scan", response_model=ScaResponse)
def sca_scan(req: ScaRequest) -> ScaResponse:
    """Check dependency versions for known CVEs."""
    findings = rules.sca_scan(req.requirements)
    return ScaResponse(vulnerabilities=[f.to_dict() for f in findings])


# ── full_scan ────────────────────────────────────────────────────────────────

class FullScanRequest(BaseModel):
    code: str = ""
    requirements: str = ""
    language: Literal["python", "javascript"] = "python"


class FullScanResponse(BaseModel):
    findings: dict
    blocked: bool
    summary: str


@app.post("/full_scan", response_model=FullScanResponse)
def full_scan(req: FullScanRequest) -> FullScanResponse:
    """Run package, SAST and SCA checks together and report a blocking decision."""
    sast_findings = rules.sast_scan(req.code, req.language)
    sca_findings = rules.sca_scan(req.requirements)

    # Any pinned dep we don't recognise as real and don't have CVE data for is a
    # slopsquatting candidate — flag it without a network call here.
    package_warnings: list[str] = []
    known = {k[0] for k in rules.KNOWN_CVES}
    for pkg, _ver in rules.parse_requirements(req.requirements):
        if pkg not in known and pkg not in _COMMON_REAL_PACKAGES:
            package_warnings.append(pkg)

    blocked, summary = rules.summarise(sast_findings, sca_findings, package_warnings)
    return FullScanResponse(
        findings={
            "sast": [f.to_dict() for f in sast_findings],
            "sca": [f.to_dict() for f in sca_findings],
            "packages": [
                {"package": p, "warning": "not found in known registries"}
                for p in package_warnings
            ],
        },
        blocked=blocked,
        summary=summary,
    )


# A small allow-list so full_scan doesn't false-positive common real packages
# when offline. check_package does the authoritative network lookup.
_COMMON_REAL_PACKAGES = {
    "flask", "flask_cors", "requests", "django", "fastapi", "sqlalchemy",
    "pydantic", "uvicorn", "gunicorn", "numpy", "pandas", "pytest", "click",
    "httpx", "aiohttp", "boto3", "redis", "celery", "jinja2", "werkzeug",
}


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "secure-ai-pipeline-mcp"}


def main() -> None:
    """Console-script entry point (``sap-mcp``)."""
    import uvicorn

    uvicorn.run("extensions.claude_mcp.server:app", host="127.0.0.1", port=8765)


if __name__ == "__main__":
    main()
