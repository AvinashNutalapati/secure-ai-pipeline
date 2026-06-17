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
from .unicode_injection import has_hidden_unicode

# Instruction-injection language that has no business in a tool name/description/
# parameter — the core of an MCP "tool poisoning" attack (the model reads tool
# metadata as trusted instructions). Invariant Labs' mcp-scan keys on this class.
INJECTION_PHRASES = re.compile(
    r"(?i)("
    # Unambiguous instruction-override / concealment language.
    r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions"
    r"|disregard\s+(?:the\s+)?(?:system|above|previous)"
    r"|do\s+not\s+(?:tell|inform|mention|reveal|warn|notify)\s+(?:the\s+)?user"
    r"|without\s+(?:telling|informing|notifying)\s+(?:the\s+)?user"
    r"|exfiltrat"
    r"|silently\s+(?:run|execute|send|read|forward)"
    # "before responding, <do a tool action>" — sequencing an action ahead of the
    # real request is the tool-poisoning shape (not a bare "before responding").
    r"|before\s+(?:responding|answering|using\s+any\s+other\s+tool)\b[^.\n]{0,60}\b(?:read|send|fetch|call|run|include|append)\b"
    # An action verb aimed at a SENSITIVE target — this is what separates a real
    # poisoning payload from benign docs like "always return JSON". (ai_ide.py uses
    # the same target-required approach to avoid false positives.)
    r"|(?:send|forward|read|leak|include|append|return|post)\b[^.\n]{0,40}\b(?:secret|token|api[_ -]?key|credential|password|\.env\b|environment\s+variable|ssh|private\s+key|system\s+prompt|\.aws|\.npmrc)\b"
    r")"
)

# Heuristic capability keywords for cross-server attack-path analysis. ("http"/
# "url" are deliberately NOT here — they match localhost dev servers; a remote URL
# is detected separately, excluding localhost, in _capabilities.)
_FS_HINTS = ("filesystem", "server-filesystem", "/files", "fs-server", "files-server")
_NET_HINTS = ("fetch", "curl", "wget", "brave", "search", "puppeteer",
              "playwright", "browser", "axios", "requests", "webhook", "slack",
              "discord", "telegram", "email", "smtp")
_SHELL_HINTS = ("shell", "bash", "terminal", "command-runner", "run-command", "exec")
_LOCALHOST_RE = re.compile(r"(?i)localhost|127\.0\.0\.1|\[::1\]|::1|0\.0\.0\.0")

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


def _walk_strings(obj, path="$"):
    """Yield (json-path, string) for every string value in a nested config."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_strings(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_strings(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        yield path, obj


def _iter_input_schemas(obj):
    """Yield every tool input-schema dict found anywhere in the config."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ("inputSchema", "input_schema") and isinstance(v, dict):
                yield v
            else:
                yield from _iter_input_schemas(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_input_schemas(v)


def _capabilities(name: str, server: dict) -> set:
    """Best-effort capability tags for a server, for cross-server path analysis."""
    args = server.get("args") or []
    url = str(server.get("url") or server.get("serverUrl") or "")
    # The URL is judged separately (remote vs localhost); everything else feeds the
    # keyword heuristics so a localhost dev server isn't treated as outbound network.
    blob = " ".join([name, str(server.get("command", "")),
                     " ".join(str(a) for a in args if not isinstance(a, dict))]).lower()
    tags = set()
    if any(h in blob for h in _FS_HINTS) or any(
            str(a).rstrip("/") in BROAD_FS_PATHS for a in args):
        tags.add("filesystem")
    remote_url = bool(url) and not _LOCALHOST_RE.search(url)
    if remote_url or any(h in blob for h in _NET_HINTS):
        tags.add("network")
    base_cmd = Path(str(server.get("command", ""))).name
    if base_cmd in SHELL_COMMANDS or PIPE_TO_SHELL.search(blob) \
            or any(h in blob for h in _SHELL_HINTS):
        tags.add("shell")
    return tags


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
                        f"Remote MCP server '{name}' points at {url} with no auth header",
                        f"Server '{name}' points at {url} with no Authorization/"
                        "API-key header. Remote tool output is untrusted input to "
                        "your agent.",
                        "Require OAuth or an API key; prefer allowlisted, "
                        "authenticated endpoints.",
                        where,
                    ))

        # 5. Tool poisoning — instruction-injection language in any config string
        #    (tool names/descriptions/params/enums live here in manifests). One
        #    finding per file is enough signal.
        poison = next(((jp, s) for jp, s in _walk_strings(data)
                       if INJECTION_PHRASES.search(s)), None)
        if poison:
            jp, s = poison
            findings.append(Finding(
                "mcp", "MCP", "mcp-tool-poisoning", "HIGH",
                f"MCP config contains tool-poisoning language ({where})",
                f"A string at {jp} reads like an instruction-injection payload: "
                f"\"{s.strip()[:120]}\". A poisoned tool description hijacks the agent "
                "the moment the tool list is loaded.",
                "Treat tool metadata as untrusted; remove override/exfiltration "
                "language and pin tool definitions (hash) so they can't change silently.",
                where,
            ))

        # 6. Hidden Unicode in any config string (covert tool poisoning).
        uni = next(((jp, has_hidden_unicode(s)) for jp, s in _walk_strings(data)
                    if has_hidden_unicode(s)), None)
        if uni:
            jp, hit = uni
            findings.append(Finding(
                "mcp", "MCP", "mcp-tool-hidden-unicode", "CRITICAL",
                f"Hidden Unicode in an MCP config string ({where})",
                f"Invisible characters ({hit[4]}) in the string at {jp} — a covert "
                "tool-poisoning channel a reviewer can't see.",
                "Remove the invisible characters and review the tool definition's "
                "true text.",
                where,
            ))

        # 7. Permissive tool input schema → a poisoned tool can accept extra args.
        for schema in _iter_input_schemas(data):
            if schema.get("additionalProperties") is not False:
                findings.append(Finding(
                    "mcp", "MCP", "mcp-permissive-schema", "LOW",
                    f"MCP tool input schema is permissive ({where})",
                    "A tool inputSchema does not set additionalProperties:false, so a "
                    "poisoned or buggy tool can accept unexpected arguments.",
                    "Set additionalProperties:false on MCP tool input schemas.",
                    where,
                ))
                break  # one note per file

        # 8. Cross-server attack paths — capability combinations that turn a single
        #    prompt injection into read-local-then-exfiltrate or RCE.
        caps = {name: _capabilities(name, server) for name, server in servers}
        fs = sorted(n for n, t in caps.items() if "filesystem" in t)
        net = sorted(n for n, t in caps.items() if "network" in t)
        shell = sorted(n for n, t in caps.items() if "shell" in t)
        if fs and net:
            findings.append(Finding(
                "mcp", "MCP", "mcp-cross-server-exfil", "HIGH",
                f"MCP servers form a read-local + send-remote chain ({where})",
                f"Filesystem server(s) {fs} together with network server(s) {net} let "
                "a prompt-injected agent read local files and exfiltrate them.",
                "Avoid enabling broad-filesystem and outbound-network servers "
                "together; scope the filesystem server or split the trust domains.",
                where,
            ))
        if shell and net:
            findings.append(Finding(
                "mcp", "MCP", "mcp-cross-server-rce", "HIGH",
                f"MCP servers form a fetch + shell-exec chain ({where})",
                f"Shell/exec server(s) {shell} together with network server(s) {net} "
                "let untrusted fetched content drive command execution.",
                "Don't pair an outbound-network server with a shell/exec server; "
                "require human approval for shell tools.",
                where,
            ))
    return findings
