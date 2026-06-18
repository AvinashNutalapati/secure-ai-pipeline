"""
Secure AI Pipeline — REST server (backend for the OpenAI GPT Action).

A FastAPI app exposing the pipeline's security checks as HTTP endpoints. The
Claude Code integration is the stdio MCP server in ``mcp_server.py``. Run this
one with:

    uvicorn extensions.claude_mcp.server:app --port 8765

or via the installed console script:

    sap-rest
"""

from __future__ import annotations

import os
from typing import Literal, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from . import rules
from .registry import check_package as _check_package

app = FastAPI(
    title="Secure AI Pipeline API",
    description="Security scanner for AI-generated code.",
    version="3.3.1",
)

# Optional API-key auth. Set SAP_API_KEY in the deployment environment to require
# an `X-API-Key` header on every scan endpoint. Unset → open (local/demo only).
API_KEY = os.getenv("SAP_API_KEY")


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key.")


_AUTH = [Depends(require_api_key)]


# ── check_package ────────────────────────────────────────────────────────────

class CheckPackageRequest(BaseModel):
    package: str = Field(..., description="Package name to verify.")
    registry: Literal["pypi", "npm"] = "pypi"


class CheckPackageResponse(BaseModel):
    # Tri-state: true = exists, false = confirmed missing (slopsquatting risk),
    # null = registry unreachable, could not verify (NOT a missing verdict).
    exists: Optional[bool]
    latest_version: Optional[str] = None
    warning: Optional[str] = None


@app.post("/check_package", response_model=CheckPackageResponse, dependencies=_AUTH)
def check_package(req: CheckPackageRequest) -> CheckPackageResponse:
    """Verify a package exists on PyPI or npm before importing it."""
    return CheckPackageResponse(**_check_package(req.package, req.registry))


# ── sast_scan ────────────────────────────────────────────────────────────────

class SastRequest(BaseModel):
    code: str
    language: Literal["python", "javascript"] = "python"


class SastResponse(BaseModel):
    findings: list[dict]


@app.post("/sast_scan", response_model=SastResponse, dependencies=_AUTH)
def sast_scan(req: SastRequest) -> SastResponse:
    """Scan a code snippet for insecure patterns (injection, hardcoded secrets, etc.)."""
    findings = rules.sast_scan(req.code, req.language)
    return SastResponse(findings=[f.to_dict() for f in findings])


# ── sca_scan ─────────────────────────────────────────────────────────────────

class ScaRequest(BaseModel):
    requirements: str


class ScaResponse(BaseModel):
    vulnerabilities: list[dict]


@app.post("/sca_scan", response_model=ScaResponse, dependencies=_AUTH)
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


@app.post("/full_scan", response_model=FullScanResponse, dependencies=_AUTH)
def full_scan(req: FullScanRequest) -> FullScanResponse:
    """Run package, SAST and SCA checks together and report a blocking decision.

    The orchestration lives in rules.full_scan (shared with the stdio MCP
    server); unknown pinned deps get a live-registry verdict so real packages
    are never falsely reported as non-existent.
    """
    return FullScanResponse(
        **rules.full_scan(req.code, req.requirements, req.language,
                          check_registry=_check_package)
    )


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "secure-ai-pipeline-mcp"}


def main() -> None:
    """Console-script entry point (``sap-rest``)."""
    import uvicorn

    host = os.getenv("SAP_HOST", "127.0.0.1")
    port = int(os.getenv("PORT", os.getenv("SAP_PORT", "8765")))
    uvicorn.run("extensions.claude_mcp.server:app", host=host, port=port)


if __name__ == "__main__":
    main()
