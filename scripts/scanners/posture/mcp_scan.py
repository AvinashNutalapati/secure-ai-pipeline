"""MCP-Scan adapter — AI posture (MCP security). https://github.com/invariantlabs-ai/mcp-scan

Invariant Labs' scanner for MCP setups: tool poisoning, rug-pulls, and prompt
injection hidden in tool descriptions. Deepens our built-in MCP-config posture
check on the `ai_posture` type. Runs only when the repo ships an MCP config.

No auto-install (and note: mcp-scan may send tool descriptions to its analysis
service — review its data handling before relying on it), so this activates only
when a `mcp-scan` binary is on PATH. The JSON schema below is BEST-EFFORT (the
tool is young); a shape we don't recognise degrades to no findings, never a crash.

stdlib only.
"""

from __future__ import annotations

import json
from typing import Optional

from external_tools import _run, _which
from scanners.registry import ScanContext, ToolAdapter, finding, has_files, register

_INSTALL = "pipx install mcp-scan  (review its data handling; https://github.com/invariantlabs-ai/mcp-scan)"

_MCP_CONFIGS = ("mcp.json", ".mcp.json", "claude_desktop_config.json")


def _issues(node, server="") -> list:
    """Walk a (schema-uncertain) mcp-scan JSON tree, yielding (server, tool, msg,
    severity) for anything that looks like a flagged tool/issue."""
    found = []
    if isinstance(node, dict):
        # An issue-like dict: has a message and isn't a passing verdict.
        msg = node.get("message") or node.get("description") or node.get("label")
        status = str(node.get("status") or node.get("verdict") or "").lower()
        if msg and status not in ("ok", "pass", "passed", "verified", "safe", "clean"):
            found.append((server or node.get("server", ""), node.get("tool") or node.get("name", ""),
                          str(msg), node.get("severity") or node.get("risk") or "HIGH"))
        srv = node.get("server") or node.get("name") or server
        for key in ("issues", "findings", "results", "tools", "servers", "scan_results"):
            if key in node:
                found += _issues(node[key], srv)
    elif isinstance(node, list):
        for item in node:
            found += _issues(item, server)
    return found


def parse(data) -> list:
    out = []
    for server, tool, msg, sev in _issues(data):
        head = f"MCP tool '{tool}': {msg}" if tool else f"MCP: {msg}"
        out.append(finding(
            sev, head[:120], (f"server: {server}\n" if server else "") + msg, "", 0,
            "Treat MCP tool descriptions as untrusted input; remove or scope the flagged server/tool.",
            "mcp-scan"))
    return out


def run(ctx: ScanContext) -> Optional[list]:
    if not _which("mcp-scan"):
        return None
    if not has_files(ctx.root, *_MCP_CONFIGS):
        return []
    from scanners.base import skip
    out = []
    for name in _MCP_CONFIGS:
        for cfg in sorted(ctx.root.rglob(name)):
            if skip(cfg):
                continue
            proc = _run(["mcp-scan", "scan", str(cfg), "--json"])
            if proc is None:
                continue
            try:
                data = json.loads(proc.stdout or "{}")
            except json.JSONDecodeError:
                continue
            out += parse(data)
    return out


register(ToolAdapter(name="mcp-scan", scan_type="ai_posture", binary="mcp-scan",
                     run=run, install=_INSTALL))
