# Secure AI Pipeline — Claude MCP server

Exposes the pipeline's security checks as tools an AI assistant can call mid-session —
verify a package before importing it, scan a snippet before committing, or run a full
scan on code + dependencies.

This directory ships **two servers** that share the same rule engine (`rules.py`) and
registry check (`registry.py`):

| File | Protocol | Used by |
|------|----------|---------|
| `mcp_server.py` | **MCP over stdio** (JSON-RPC, via the `mcp` SDK) | **Claude Code** (`claude mcp add`) |
| `server.py` | **REST/HTTP** (FastAPI) | **OpenAI Custom GPT Action** (see `../openai-gpt/`) |

> `claude mcp add` speaks the Model Context Protocol over stdio, **not** plain HTTP — so
> Claude Code uses `mcp_server.py`, not the FastAPI app. Use `server.py` only for the
> REST/GPT-Action path.

## Tools

| Tool | Input | Output |
|------|-------|--------|
| `check_package` | `{ package, registry: "pypi"\|"npm" }` | `{ exists, latest_version, warning }` |
| `sast_scan` | `{ code, language }` | `{ findings: [{ rule, line, severity, message, fix }] }` |
| `sca_scan` | `{ requirements }` | `{ vulnerabilities: [{ package, version, cve, severity, fix_version }] }` |
| `full_scan` | `{ code, requirements, language }` | `{ findings, blocked, summary }` |

`exists` is **tri-state**: `true` (found), `false` (confirmed missing — a
slopsquatting risk, do not install), or `null` (registry unreachable — could not
verify; never treat as missing). `full_scan` only sets `blocked` for packages
*confirmed* missing; unreachable lookups surface as warnings.

## Install

```bash
cd extensions/claude_mcp
pip install -r requirements.txt
```

## Connect to Claude Code (MCP, stdio)

Run from the repo root so the `extensions.claude_mcp` package resolves:

```bash
claude mcp add secure-ai-pipeline -- python -m extensions.claude_mcp.mcp_server
```

Once connected, Claude Code can call `check_package`, `sast_scan`, `sca_scan`, and
`full_scan` directly. Ask it to "check that package exists before importing" or
"scan this file for security issues" and it will use these tools.

Verify the tools registered:

```bash
claude mcp list
```

## REST server (for the OpenAI GPT Action)

```bash
uvicorn extensions.claude_mcp.server:app --port 8765
# health check:
curl http://127.0.0.1:8765/health

curl -X POST http://127.0.0.1:8765/check_package \
  -H 'content-type: application/json' \
  -d '{"package": "flaskutils_ai", "registry": "pypi"}'
# → {"exists": false, "latest_version": null, "warning": "...slopsquatting risk..."}
```

The production deployment lives at **https://api.mirawyn.com** (Render, see
[`../openai-gpt/DEPLOY.md`](../openai-gpt/DEPLOY.md) and
[`docs/domain-setup.md`](../../docs/domain-setup.md));
`../openai-gpt/openapi.yaml` already points the Custom GPT there.
