# Secure AI Pipeline — Claude MCP server

A FastAPI server that exposes the pipeline's security checks as tools Claude Code can
call mid-session — verify a package before importing it, scan a snippet before committing,
or run a full scan on code + dependencies.

## Tools

| Tool | Input | Output |
|------|-------|--------|
| `check_package` | `{ package, registry: "pypi"\|"npm" }` | `{ exists, latest_version, warning }` |
| `sast_scan` | `{ code, language }` | `{ findings: [{ rule, line, severity, message, fix }] }` |
| `sca_scan` | `{ requirements }` | `{ vulnerabilities: [{ package, version, cve, severity, fix_version }] }` |
| `full_scan` | `{ code, requirements, language }` | `{ findings, blocked, summary }` |

## Install

```bash
cd extensions/claude_mcp
pip install -r requirements.txt
```

## Run

```bash
uvicorn extensions.claude_mcp.server:app --port 8765
```

(Run from the repo root so the `extensions.claude_mcp` package resolves.) Or, after
`pip install -e .` from the repo root, just run `sap-mcp`.

Health check: `curl http://127.0.0.1:8765/health`.

## Connect to Claude Code

```bash
claude mcp add secure-ai-pipeline -- uvicorn extensions.claude_mcp.server:app --port 8765
```

Once connected, Claude Code can call `check_package`, `sast_scan`, `sca_scan`, and
`full_scan` directly. Ask it to "check that package exists before importing" or
"scan this file for security issues" and it will use these tools.

## Try it

```bash
curl -X POST http://127.0.0.1:8765/check_package \
  -H 'content-type: application/json' \
  -d '{"package": "flaskutils_ai", "registry": "pypi"}'
# → {"exists": false, "latest_version": null, "warning": "...slopsquatting risk..."}
```
