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

import sys
from pathlib import Path
from typing import Literal

from mcp.server.fastmcp import FastMCP

from . import rules
from .registry import check_package as _check_package

mcp = FastMCP("secure-ai-pipeline")


@mcp.tool()
def check_package(package: str, registry: Literal["pypi", "npm"] = "pypi") -> dict:
    """Verify a package exists on PyPI or npm before importing it (anti-slopsquatting).

    `exists` is tri-state: true / false (confirmed missing — do not install) /
    null (registry unreachable — could not verify, NOT a missing verdict).
    """
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
    """Run package, SAST and SCA checks together and report a blocking decision.

    Shared engine with the REST server (rules.full_scan): unknown pinned deps
    get a live-registry verdict; unreachable registries warn, never block.
    """
    return rules.full_scan(code, requirements, language,
                           check_registry=_check_package)


@mcp.tool()
def scan_repo(path: str, deep: bool = False) -> dict:
    """Run the FULL multi-tool security scan on a directory — every installed OSS
    scanner (secrets, supply-chain/slopsquatting, SCA, SAST, IaC, CI/CD),
    consolidated per type — the same registry-driven engine the GitHub Action uses.

    `path` is the absolute path to the project to scan (the MCP client controls the
    server's working directory, so pass it explicitly). `deep` also runs the
    heaviest tools (e.g. GuardDog). Whatever scanners are on PATH run automatically.

    This needs the full pipeline: it works from the secure-ai-pipeline repo or a
    project where `npx secure-ai-pipeline init` has dropped it in. On a bare
    pip-install it returns a hint — use the standalone snippet tools instead
    (sast_scan / sca_scan / check_package), which always work.
    """
    target = Path(path).expanduser().resolve()
    if not target.is_dir():
        return {"available": True, "error": f"Not a directory: {path}"}

    # The full scan needs scripts/ (the pipeline). Look for it next to this package
    # (repo / dev install) and inside the scanned project (npx-init'd); add the
    # first that exists, then import. Absent in a bare pip-install → degrade.
    for candidate in (Path(__file__).resolve().parents[2] / "scripts", target / "scripts"):
        if candidate.is_dir() and str(candidate) not in sys.path:
            sys.path.insert(0, str(candidate))
    try:
        import scan_all
    except ImportError:
        return {
            "available": False,
            "message": ("Full-repo scanning needs the secure-ai-pipeline tooling, which "
                        "isn't present here. Run `npx secure-ai-pipeline init` in the "
                        "project (then `npx secure-ai-pipeline scan`), or use the snippet "
                        "tools (sast_scan, sca_scan, check_package) which work standalone."),
        }

    result = scan_all.orchestrate(target, offline=False, only=[], deep=deep)
    return {
        "root": result["root"],
        "layers": {t: {"engine": lyr.engine, "note": lyr.note,
                       "findings": [f.to_dict() for f in lyr.findings]}
                   for t, lyr in result["layers"].items()},
    }


def main() -> None:
    """Console-script entry point — runs the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
