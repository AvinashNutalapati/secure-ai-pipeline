# MCP hardening

MCP is the new browser-extension problem — but with shell access. An MCP server can
read your files, run commands, and reach the network on the agent's behalf, so a
malicious or over-scoped server turns a prompt injection into code exfiltration or
RCE. `scan` flags the four highest-leverage MCP risks.

## What the MCP scanner flags

| Rule | Risk | Fix |
|---|---|---|
| `mcp-secret-env` | Long-lived creds (`GITHUB_TOKEN`, `AWS_*`, `*_API_KEY`) handed to a server | Use short-lived/OAuth tokens scoped to the server, or a secrets broker |
| `mcp-shell-exec` | Server starts via `bash`/`sh` or `curl\|bash` | Run a pinned binary or vetted package directly |
| `mcp-broad-fs` | Filesystem server mounted at `/`, `~`, `$HOME` | Scope to the project directory only |
| `mcp-remote-unauth` | Remote (`http`/`sse`) server with no `Authorization`/API-key header | Require OAuth or an API key; prefer `https` + allowlist |

Config files scanned: `mcp.json`, `.mcp.json`, `claude_desktop_config.json`,
`.vscode/mcp.json`, `.cursor/mcp.json`.

## Allowlist policy

Set an allowlist so any unreviewed server is flagged:

```yaml
# secure-ai-pipeline.yml
mcp:
  allowed_servers:
    - github-readonly
    - docs-search
```

## Hardening checklist

- [ ] Every server is on the allowlist and reviewed.
- [ ] No long-lived secrets in `env`; use OAuth / short-lived tokens.
- [ ] No shell or fetch-and-execute startup commands.
- [ ] Filesystem servers scoped to the workspace.
- [ ] Remote servers authenticated and over `https`.
- [ ] Treat all tool output as untrusted input to the agent.
