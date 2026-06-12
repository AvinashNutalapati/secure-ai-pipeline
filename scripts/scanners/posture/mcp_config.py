"""MCP configuration risk scanner.

Inspects Model Context Protocol config files for blast-radius risks: secrets
handed to servers, arbitrary shell/`curl|bash` startup commands, broad filesystem
mounts, and unauthenticated remote servers. Anthropic's MCP guidance is explicit
that connectors increase blast radius when they can reach secrets or external
systems.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..base import Finding, rel, skip

# Config files used by the major MCP hosts.
MCP_FILENAMES = {
    "mcp.json",
    ".mcp.json",
    "claude_desktop_config.json",
}
# Also: .vscode/mcp.json, .cursor/mcp.json (matched via globs below).
MCP_GLOBS = ("**/.vscode/mcp.json", "**/.cursor/mcp.json")

SECRET_ENV_PATTERN = re.compile(
    r"(?i)(TOKEN|SECRET|API_?KEY|ACCESS_?KEY|PASSWORD|PRIVATE_?KEY|"
    r"AWS_|GITHUB_TOKEN|OPENAI_|ANTHROPIC_|SLACK_|STRIPE_)"
)
SHELL_COMMANDS = {"bash", "sh", "zsh", "/bin/bash", "/bin/sh"}
PIPE_TO_SHELL = re.compile(r"(curl|wget)\b.*\|\s*(bash|sh)\b")
BROAD_FS_PATHS = ("/", "/Users", "/home", "~", "$HOME", "/etc", "/var")


def _iter_servers(data: dict):
    """Yield (name, server_dict) across the known MCP config shapes."""
    for key in ("mcpServers", "servers", "mcp"):
        block = data.get(key)
        if isinstance(block, dict):
            for name, server in block.items():
                if isinstance(server, dict):
                    yield name, server
    # top-level dict of servers (some configs)
    if not any(k in data for k in ("mcpServers", "servers", "mcp")):
        for name, server in data.items():
            if isinstance(server, dict) and ("command" in server or "url" in server):
                yield name, server


def _collect_config_files(root: Path) -> list[Path]:
    out = []
    for p in root.rglob("*"):
        if p.is_file() and p.name in MCP_FILENAMES and not skip(p):
            out.append(p)
    for g in MCP_GLOBS:
        for p in root.glob(g):
            if p.is_file() and not skip(p):
                out.append(p)
    seen, uniq = set(), []
    for p in sorted(out):
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for cfg in _collect_config_files(root):
        where = rel(cfg, root)
        try:
            data = json.loads(cfg.read_text(encoding="utf-8", errors="ignore"))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(data, dict):
            continue

        servers = list(_iter_servers(data))
        for name, server in servers:
            findings.append(Finding(
                "mcp", "MCP", "mcp-server-inventory", "INFO",
                f"MCP server configured: {name}",
                f"Server '{name}' is configured in {where}. MCP servers are "
                "privileged code — treat them like production integrations.",
                "Keep MCP servers on an allowlist and review their scopes.",
                where,
            ))

            # 1. Secrets handed to the server via env.
            env = server.get("env") or {}
            if isinstance(env, dict):
                leaked = [k for k in env if SECRET_ENV_PATTERN.search(str(k))
                          or SECRET_ENV_PATTERN.search(str(env.get(k, "")))]
                if leaked:
                    findings.append(Finding(
                        "mcp", "MCP", "mcp-secret-env", "CRITICAL",
                        f"MCP server '{name}' receives secrets via env",
                        f"Env keys {leaked} look like long-lived credentials passed "
                        f"to MCP server '{name}'. A compromised or malicious server "
                        "can exfiltrate them.",
                        "Use short-lived/OAuth tokens scoped to the server, or a "
                        "secrets broker. Never pass GITHUB_TOKEN/AWS keys directly.",
                        where,
                    ))

            # 2. Shell / pipe-to-shell startup command.
            command = str(server.get("command", "")).strip()
            args = server.get("args") or []
            argstr = " ".join(str(a) for a in args) if isinstance(args, list) else str(args)
            full_cmd = f"{command} {argstr}".strip()
            base_cmd = Path(command).name if command else ""
            if base_cmd in SHELL_COMMANDS or PIPE_TO_SHELL.search(full_cmd):
                findings.append(Finding(
                    "mcp", "MCP", "mcp-shell-exec", "HIGH",
                    f"MCP server '{name}' launches via a shell",
                    f"Server '{name}' runs `{full_cmd}`. Shell/`curl|bash` startup "
                    "commands are an RCE and supply-chain risk.",
                    "Run a pinned binary or vetted package directly; avoid shell "
                    "wrappers and remote-fetch-then-execute.",
                    where,
                ))

            # 3. Broad filesystem mounts (e.g. filesystem server rooted at $HOME).
            for a in (args if isinstance(args, list) else []):
                a = str(a)
                if a in BROAD_FS_PATHS or a.rstrip("/") in BROAD_FS_PATHS:
                    findings.append(Finding(
                        "mcp", "MCP", "mcp-broad-fs", "HIGH",
                        f"MCP server '{name}' mounts a broad filesystem path",
                        f"Server '{name}' is given '{a}', granting access well "
                        "beyond the project workspace.",
                        "Scope filesystem servers to the project directory only.",
                        where,
                    ))
                    break

            # 4. Unauthenticated remote server.
            url = server.get("url") or server.get("serverUrl")
            if url:
                headers = server.get("headers") or {}
                has_auth = isinstance(headers, dict) and any(
                    "authorization" in str(k).lower() or "api-key" in str(k).lower()
                    for k in headers
                )
                sev = "MEDIUM" if str(url).startswith("https") else "HIGH"
                if not has_auth:
                    findings.append(Finding(
                        "mcp", "MCP", "mcp-remote-unauth", sev,
                        f"Remote MCP server '{name}' has no auth header",
                        f"Server '{name}' points at {url} with no Authorization/"
                        "API-key header. Remote tool output is untrusted input to "
                        "your agent.",
                        "Require OAuth or an API key; prefer allowlisted, "
                        "authenticated endpoints.",
                        where,
                    ))
    return findings
