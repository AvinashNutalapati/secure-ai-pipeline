"""
Secure AI Pipeline — stdio MCP server for Claude Code.

Unlike ``server.py`` (a FastAPI REST app used as the OpenAI GPT Action backend),
this is a real Model Context Protocol server: it speaks JSON-RPC over stdio via
the official ``mcp`` SDK (FastMCP), which is what ``claude mcp add`` expects.

Connect it with:

    claude mcp add secure-ai-pipeline -- python -m extensions.claude_mcp.mcp_server

Run from the repo root so the ``extensions.claude_mcp`` package resolves.
"""

from __future__ import annotations

from typing import Literal

from mcp.server.fastmcp import FastMCP

from . import rules
from .registry import check_package as _check_package

mcp = FastMCP("secure-ai-pipeline")

# A small allow-list so full_scan doesn't false-positive common real packages
# offline. check_package does the authoritative network lookup.
_COMMON_REAL_PACKAGES = {
    "flask", "flask_cors", "requests", "django", "fastapi", "sqlalchemy",
    "pydantic", "uvicorn", "gunicorn", "numpy", "pandas", "pytest", "click",
    "httpx", "aiohttp", "boto3", "redis", "celery", "jinja2", "werkzeug",
}


@mcp.tool()
def check_package(package: str, registry: Literal["pypi", "npm"] = "pypi") -> dict:
    """Verify a package exists on PyPI or npm before importing it (anti-slopsquatting)."""
    return _check_package(package, registry)


@mcp.tool()
def sast_scan(code: str, language: Literal["python", "javascript"] = "python") -> dict:
    """Scan a code snippet for insecure patterns (injection, hardcoded secrets, insecure defaults)."""
    findings = rules.sast_scan(code, language)
    return {"findings": [f.to_dict() for f in findings]}


@mcp.tool()
def sca_scan(requirements: str) -> dict:
    """Check pinned dependency versions (requirements.txt content) for known CVEs."""
    findings = rules.sca_scan(requirements)
    return {"vulnerabilities": [f.to_dict() for f in findings]}


@mcp.tool()
def full_scan(
    code: str = "",
    requirements: str = "",
    language: Literal["python", "javascript"] = "python",
) -> dict:
    """Run package, SAST and SCA checks together and report a blocking decision."""
    sast_findings = rules.sast_scan(code, language)
    sca_findings = rules.sca_scan(requirements)

    known = {k[0] for k in rules.KNOWN_CVES}
    package_warnings = [
        pkg
        for pkg, _ver in rules.parse_requirements(requirements)
        if pkg not in known and pkg not in _COMMON_REAL_PACKAGES
    ]

    blocked, summary = rules.summarise(sast_findings, sca_findings, package_warnings)
    return {
        "findings": {
            "sast": [f.to_dict() for f in sast_findings],
            "sca": [f.to_dict() for f in sca_findings],
            "packages": [
                {"package": p, "warning": "not found in known registries"}
                for p in package_warnings
            ],
        },
        "blocked": blocked,
        "summary": summary,
    }


def main() -> None:
    """Console-script entry point — runs the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
