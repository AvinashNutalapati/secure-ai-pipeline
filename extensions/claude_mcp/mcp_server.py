"""
Secure AI Pipeline — stdio MCP server for AI coding assistants.

A real Model Context Protocol server (JSON-RPC over stdio via the official ``mcp``
SDK / FastMCP) — what ``claude mcp add``, the Codex CLI, and Cursor/Windsurf expect.
It lets the assistant verify packages and scan code MID-conversation, before it
installs a dependency or hands you generated code.

Install + connect:

    pipx install git+https://github.com/AvinashNutalapati/secure-ai-pipeline.git
    claude mcp add secure-ai-pipeline -- sap-mcp        # Claude Code
    # Codex:  ~/.codex/config.toml → [mcp_servers.secure-ai-pipeline] command = "sap-mcp"
    # Cursor: { "mcpServers": { "secure-ai-pipeline": { "command": "sap-mcp" } } }

Every tool returns a ``verdict`` ("block" | "warn" | "ok") and a one-line
``summary`` so the assistant can act on it directly.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Literal

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from . import rules
from .registry import check_package as _check_package

mcp = FastMCP("secure-ai-pipeline")

# Hints so MCP clients can auto-approve these — they only READ (never modify your
# repo). The network ones also set openWorldHint (they reach PyPI / npm).
_READS_NET = ToolAnnotations(readOnlyHint=True, openWorldHint=True)
_READS_LOCAL = ToolAnnotations(readOnlyHint=True, openWorldHint=False)

_BLOCK_SEVERITIES = {"CRITICAL", "HIGH", "ERROR"}


def _wrap(verdict: str, summary: str, **data) -> dict:
    """Every tool leads with a verdict + one-line summary the assistant can act on."""
    return {"verdict": verdict, "summary": summary, **data}


@mcp.tool(annotations=_READS_NET)
def check_package(package: str, registry: Literal["pypi", "npm"] = "pypi") -> dict:
    """Verify a package exists on PyPI or npm BEFORE importing or installing it.

    Call this whenever you're about to recommend a dependency — AI models invent
    plausible names that attackers pre-register (slopsquatting), so the next
    install silently runs malware. verdict "block" means it was NOT found: do not
    install it. verdict "warn" means the registry was unreachable (not a verdict).
    """
    res = _check_package(package, registry)
    exists = res.get("exists")
    if exists is True:
        latest = f" (latest {res['latest_version']})" if res.get("latest_version") else ""
        return _wrap("ok", f"'{package}' exists on {registry}{latest}.", **res)
    if exists is False:
        return _wrap("block", f"'{package}' was NOT found on {registry} — likely a "
                     "hallucinated / slopsquatting name. Do not install it.", **res)
    return _wrap("warn", res.get("warning") or f"Could not verify '{package}'.", **res)


@mcp.tool(annotations=_READS_NET)
def verify_install(command: str) -> dict:
    """Check every package in an install command BEFORE you run it.

    Paste the exact command you're about to run or suggest — `pip install …`,
    `npm install …`, `pnpm/yarn add …`, `uv add …`. Each package name is checked
    against its registry. verdict "block" means at least one name doesn't exist
    (do NOT run the command — it's the slopsquatting trap). Use this before you
    ever suggest installing dependencies.
    """
    pkgs = rules.parse_install_command(command)
    if not pkgs:
        return _wrap("ok", "No installable package names found in the command.", packages=[])
    results, missing, unverified = [], [], []
    for name, reg in pkgs:
        res = _check_package(name, reg)
        results.append({"package": name, "registry": reg, **res})
        if res.get("exists") is False:
            missing.append(name)
        elif res.get("exists") is None:
            unverified.append(name)
    if missing:
        return _wrap("block", f"{len(missing)} package(s) NOT found — likely hallucinated: "
                     f"{', '.join(missing)}. Do NOT run this command.", packages=results)
    if unverified:
        return _wrap("warn", f"Could not verify {len(unverified)} package(s) "
                     f"({', '.join(unverified)}) — registry unreachable.", packages=results)
    return _wrap("ok", f"All {len(pkgs)} package(s) exist on their registry.", packages=results)


@mcp.tool(annotations=_READS_LOCAL)
def sast_scan(code: str, language: Literal["python", "javascript"] = "python") -> dict:
    """Scan a code snippet for insecure patterns before you present or commit it.

    Catches SQL injection (f-string/concat), eval/exec on request data, subprocess
    shell=True, requests verify=False, Flask debug=True, wildcard CORS, and
    hardcoded credentials. Run this on any code you generate; fix every "block"
    finding before showing it to the user.
    """
    findings = rules.sast_scan(code, language)
    if not findings:
        return _wrap("ok", "No insecure patterns found.", findings=[])
    blocking = [f for f in findings if rules.is_blocking_sast(f)]
    ids = ", ".join(sorted({f.rule for f in findings}))
    return _wrap("block" if blocking else "warn", f"{len(findings)} insecure pattern(s): {ids}.",
                 findings=[f.to_dict() for f in findings])


@mcp.tool(annotations=_READS_LOCAL)
def sca_scan(requirements: str) -> dict:
    """Check pinned dependency versions (requirements.txt content) for known CVEs.

    Run this when you add or pin Python dependencies. verdict "block" means a
    Critical/High CVE in a pinned version — upgrade to the fixed release shown.
    """
    findings = rules.sca_scan(requirements)
    if not findings:
        return _wrap("ok", "No known CVEs in the pinned versions.", vulnerabilities=[])
    blocking = [f for f in findings if rules.is_blocking_sca(f)]
    cves = ", ".join(f.cve for f in findings)
    return _wrap("block" if blocking else "warn", f"{len(findings)} known CVE(s): {cves}.",
                 vulnerabilities=[f.to_dict() for f in findings])


@mcp.tool(annotations=_READS_NET)
def full_scan(
    code: str = "",
    requirements: str = "",
    language: Literal["python", "javascript"] = "python",
) -> dict:
    """Run package, SAST and SCA checks together with one blocking decision.

    The combined gate: pass generated code + any requirements.txt content. Unknown
    pinned deps get a live-registry verdict (confirmed-missing blocks, unreachable
    warns). verdict "block" means a hallucinated/missing package, a blocking code
    issue, or a Critical/High CVE — fix it before proceeding.
    """
    out = rules.full_scan(code, requirements, language, check_registry=_check_package)
    f = out.get("findings", {})
    has_findings = any(f.get(k) for k in ("sast", "sca", "packages"))
    out["verdict"] = "block" if out.get("blocked") else ("warn" if has_findings else "ok")
    return out


@mcp.tool(annotations=_READS_NET)
def scan_repo(path: str, deep: bool = False) -> dict:
    """Run the FULL multi-tool security scan on a project directory — every installed
    OSS scanner (secrets, supply-chain/slopsquatting, SCA, SAST, IaC, CI/CD),
    consolidated per type — the same registry-driven engine the GitHub Action uses.

    `path` is the absolute path to the project (the MCP client controls the server's
    working directory, so pass it explicitly). `deep` also runs the heaviest tools
    (e.g. GuardDog). verdict "block" = a Critical/High finding somewhere.

    Needs the full pipeline: works from the secure-ai-pipeline repo or a project where
    `npx secure-ai-pipeline init` dropped it in. On a bare pip-install it returns a
    hint — use the snippet tools (sast_scan / sca_scan / check_package), which always work.
    """
    target = Path(path).expanduser().resolve()
    if not target.is_dir():
        return _wrap("warn", f"Not a directory: {path}", available=True)

    # The full scan needs scripts/ (the pipeline). Look for it next to this package
    # (repo / dev install) and inside the scanned project (npx-init'd); add the first
    # that exists, then import. Absent in a bare pip-install → degrade gracefully.
    for candidate in (Path(__file__).resolve().parents[2] / "scripts", target / "scripts"):
        if candidate.is_dir() and str(candidate) not in sys.path:
            sys.path.insert(0, str(candidate))
    try:
        import scan_all
    except ImportError:
        return _wrap("warn",
                     "Full-repo scanning needs the secure-ai-pipeline tooling, which isn't "
                     "present here. Run `npx secure-ai-pipeline init` in the project (then "
                     "`npx secure-ai-pipeline scan`), or use the snippet tools (sast_scan, "
                     "sca_scan, check_package) which work standalone.", available=False)

    result = scan_all.orchestrate(target, offline=False, only=[], deep=deep)
    layers = {t: {"engine": lyr.engine, "note": lyr.note,
                  "findings": [f.to_dict() for f in lyr.findings]}
              for t, lyr in result["layers"].items()}
    sevs = {f["severity"] for lyr in layers.values() for f in lyr["findings"]}
    total = sum(len(lyr["findings"]) for lyr in layers.values())
    types = sum(1 for lyr in layers.values() if lyr["findings"])
    verdict = "block" if sevs & _BLOCK_SEVERITIES else ("warn" if total else "ok")
    summary = (f"{total} finding(s) across {types} scan type(s)." if total
               else "Clean — no findings.")
    return _wrap(verdict, summary, root=result["root"], layers=layers)


@mcp.tool(annotations=_READS_LOCAL)
def list_posture_checks(category: str = "") -> dict:
    """List the AI-workflow posture checks this pipeline runs, grouped by category.

    These are the checks `scan_repo` applies beyond classic SAST/SCA: invisible-
    Unicode injection, MCP tool-poisoning & cross-server attack-paths, rug-pull/
    TOCTOU config drift, agent over-permission, GitHub Actions risks, and
    dependency-trust (slopsquatting / typosquat / known-malicious). Use it to
    explain what the scanner inspects, or to look up a rule's id, severity, and
    meaning. Pass `category` (e.g. "MCP", "CI/CD", "Hidden Unicode") to filter.
    Read-only and offline — it just reports the bundled catalog.
    """
    cat = rules.posture_catalog(category)
    scope = f" matching '{category}'" if category else ""
    summary = (f"{cat['count']} posture check(s){scope} across "
               f"{len(cat['categories'])} categor{'y' if len(cat['categories']) == 1 else 'ies'}.")
    return _wrap("ok", summary, **cat)


@mcp.prompt(title="Secure review")
def secure_review() -> str:
    """A checklist that makes the assistant verify packages + scan code before finalizing."""
    return (
        "You have the secure-ai-pipeline tools. Before you give me code or suggest "
        "installing anything, use them, and only proceed when nothing comes back 'block':\n\n"
        "1. New dependency? Call `verify_install` on the exact install command (or "
        "`check_package` per name). NEVER install a package that returns 'block' — it's "
        "likely hallucinated / slopsquatting.\n"
        "2. Generated code? Call `sast_scan` on it and fix every 'block' finding before "
        "showing it to me.\n"
        "3. Pinned versions? Call `sca_scan` on the requirements.\n\n"
        "For each check you run, tell me the verdict (block / warn / ok)."
    )


def _version() -> str:
    from importlib.metadata import PackageNotFoundError, version
    try:
        return version("secure-ai-pipeline")
    except PackageNotFoundError:
        return "dev"


def _selftest() -> int:
    """Verify the server is healthy WITHOUT an MCP client: the bundled rules load,
    a known-bad snippet is caught, and the registries are reachable. Exit 0 if the
    core (rules + snippet scan) works; network checks are informational only."""
    n_rules, n_cves = len(rules.SAST_RULES), len(rules.KNOWN_CVES)
    core_ok = bool(n_rules) and bool(rules.sast_scan("eval(request.data)"))
    print(f"secure-ai-pipeline MCP server  v{_version()}")
    print(f"  {'PASS' if n_rules else 'FAIL'}  rules loaded ({n_rules} SAST rules, "
          f"{n_cves} CVE entries)")
    print(f"  {'PASS' if core_ok else 'FAIL'}  snippet scan works (catches eval-on-request)")
    for reg, sample in (("pypi", "requests"), ("npm", "react")):
        res = _check_package(sample, reg)
        ok = res.get("exists") is not None
        print(f"  {'PASS' if ok else 'skip'}  {reg} reachable "
              f"(check_package('{sample}') -> exists={res.get('exists')})")
    print()
    if core_ok:
        print("Healthy. Add it to your assistant:")
        print("  Claude Code:  claude mcp add secure-ai-pipeline -- sap-mcp")
        print('  Codex:        ~/.codex/config.toml -> '
              '[mcp_servers.secure-ai-pipeline] command = "sap-mcp"')
        return 0
    print("FAILED — the bundled rules did not load. Reinstall the package.")
    return 1


def main(argv=None) -> int:
    """Console-script entry point (`sap-mcp`). With no args it serves the MCP
    protocol over stdio (what `claude mcp add` launches); the flags are for a human
    verifying the install, never used by an MCP client."""
    import argparse
    p = argparse.ArgumentParser(
        prog="sap-mcp",
        description="Secure AI Pipeline MCP server (stdio JSON-RPC). Run with no "
                    "arguments to serve; use the flags to verify the install.")
    p.add_argument("--version", action="store_true", help="Print the version and exit.")
    p.add_argument("--selftest", action="store_true",
                   help="Check rules load + registry reachability, then exit.")
    args = p.parse_args(argv)
    if args.version:
        print(_version())
        return 0
    if args.selftest:
        return _selftest()
    mcp.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
