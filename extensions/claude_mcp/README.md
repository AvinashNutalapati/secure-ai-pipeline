# Secure AI Pipeline — Claude MCP server

Exposes the pipeline's security checks as tools an AI assistant can call mid-session —
verify a package before importing it, scan a snippet before committing, or run a full
scan on code + dependencies.

This directory ships **two servers** that share the same rule engine (`rules.py`) and
registry check (`registry.py`):

| File | Protocol | Used by |
|------|----------|---------|
| `mcp_server.py` | **MCP over stdio** (JSON-RPC, via the `mcp` SDK) | **Claude Code · Codex CLI · Cursor / Windsurf / Cline** |
| `server.py` | **REST/HTTP** (FastAPI) | **OpenAI Custom GPT Action** (see `../openai-gpt/`) |

> Stdio MCP is what Claude Code, Codex, and Cursor speak — they use `mcp_server.py`.
> **ChatGPT** is the odd one out: it uses **GPT Actions (REST)**, so it talks to
> `server.py` + `../openai-gpt/openapi.yaml`, not the stdio MCP server.

## Tools

Every tool leads with a **`verdict`** (`"block"` | `"warn"` | `"ok"`) and a one-line
**`summary`** so the assistant can act without parsing the details. All tools are
read-only and annotated (`readOnlyHint`) so MCP clients can auto-approve them.

| Tool | Input | Output (beyond `verdict` + `summary`) |
|------|-------|--------|
| `check_package` | `{ package, registry: "pypi"\|"npm" }` | `{ exists, latest_version, warning }` |
| `verify_install` | `{ command }` | `{ packages: [...] }` — checks every package in a `pip/npm/yarn/pnpm/uv` install command |
| `sast_scan` | `{ code, language }` | `{ findings: [{ rule, line, severity, message, fix }] }` |
| `sca_scan` | `{ requirements }` | `{ vulnerabilities: [{ package, version, cve, severity, fix_version }] }` |
| `full_scan` | `{ code, requirements, language }` | `{ findings, blocked }` |
| `scan_repo` | `{ path, deep }` | `{ root, layers }` — full multi-tool scan (needs the pipeline) |

There's also a **`secure_review` prompt** that tells the assistant to verify new
deps + scan generated code before finalizing — turns "has tools" into "uses them."

`exists` is **tri-state**: `true` (found), `false` (confirmed missing — a
slopsquatting risk, do not install), or `null` (registry unreachable — could not
verify; never treat as missing). `full_scan` only sets `blocked` for packages
*confirmed* missing; unreachable lookups surface as warnings.

## Install

`pipx` gives you a self-contained `sap-mcp` command — no need to be inside this repo
(the rules ship bundled in the wheel as `_rules_data.py`):

```bash
pipx install git+https://github.com/AvinashNutalapati/secure-ai-pipeline.git
# (or `pipx install secure-ai-pipeline` once it's on PyPI)
```

## Connect (Claude Code · Codex · Cursor)

- **Claude Code** — `claude mcp add secure-ai-pipeline -- sap-mcp` (then `claude mcp list`)
- **Codex CLI** — add to `~/.codex/config.toml`:
  ```toml
  [mcp_servers.secure-ai-pipeline]
  command = "sap-mcp"
  ```
- **Cursor / Windsurf / Cline** — add to the MCP config:
  ```json
  { "mcpServers": { "secure-ai-pipeline": { "command": "sap-mcp" } } }
  ```

Ask the assistant to *"check that package exists before importing it"* or *"scan this
code for security issues"* and it will call these tools. The four snippet tools work
from any install; `scan_repo` runs the full multi-tool scan when the pipeline is present
(this repo, or a project where `npx secure-ai-pipeline init` dropped it in).

## REST server (for the OpenAI GPT Action)

```bash
pip install 'secure-ai-pipeline[rest]'          # adds fastapi + uvicorn
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
