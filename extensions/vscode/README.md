# Secure AI Pipeline — VS Code / Cursor extension

Security for AI-assisted development, in-editor. Flags insecure code as you save **and**
runs an **AI Agent Blast Radius checkup** across your MCP configs, Claude/Cursor
settings, and GitHub Actions. No CI wait, no network, no server, no Python — everything
runs locally and works in [Cursor](https://cursor.com) (VS Code-compatible).

## Code diagnostics (Python / JS / TS)

| Rule | Severity | Quick Fix |
|------|----------|-----------|
| `tls-verify-false` | Error | `verify=False` → `verify=True` |
| `flask-debug-true` | Error | `debug=True` → env-gated (also inserts `import os`) |
| `wildcard-cors` | Warning | `"*"` → explicit origin |
| `subprocess-shell-true` | Error | `shell=True` → `shell=False` |
| `sql-injection-fstring` | Error | — (use parameterised queries) |
| `hardcoded-api-key` | Error | → `os.environ[...]` (Python) / `process.env.*` (JS/TS) |

## AI-workflow diagnostics (new in 1.1)

Open or scan these and findings appear inline + in the Problems panel:

| File | Catches |
|------|---------|
| `mcp.json`, `.mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json` | secrets to servers, `bash`/`curl\|bash` startup, broad `/` mounts, unauth `http` remotes |
| `.claude/settings*.json` | home/root reads, wildcard `Bash(*)`, `rm -rf`, `bypassPermissions` |
| `.cursorrules`, `.clinerules`, `.windsurfrules`, `copilot-instructions.md` | auto-run, fetch-execute, prompt-injection overrides |
| `.github/workflows/*.yml` | unpinned actions, `pull_request_target`, `github.event` injection |

Run **“Secure AI Pipeline: AI Blast Radius Scan”** from the Command Palette for a
workspace-wide score (0–100).

## Features

- **Inline diagnostics** on save (code + AI-workflow config files), rule ID as the source.
- **Quick Fixes** (lightbulb) that apply the secure replacement — language-aware.
- **Status bar** item bottom-right: `$(shield) SAP: 3 issues` — click to open Problems.
- **Sidebar view** (shield icon): all findings across open files, grouped by rule.
- **AI Blast Radius Scan** command: workspace-wide posture score.

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `securePipeline.enable` | `true` | Toggle the extension on/off. |
| `securePipeline.severity` | `"warning"` | Minimum severity to show (`"error"` or `"warning"`). |
| `securePipeline.runOnType` | `false` | Run checks while typing, not just on save. |

## Develop / build

```bash
cd extensions/vscode
npm install
npm run compile        # tsc -p ./  → out/
```

Press `F5` in VS Code to launch an Extension Development Host, then open `demo/app.py`
to watch the rules fire.

## Publish

Bump `version` in `package.json` (the Marketplace rejects re-uploading the same
version), then package and upload:

```bash
npx @vscode/vsce package          # → secure-ai-pipeline-<version>.vsix
```

Upload the `.vsix` at <https://marketplace.visualstudio.com/manage/publishers/AvinashNutalapati1>
(or `vsce publish` if you have a Marketplace PAT).

Publisher / extension ID: `AvinashNutalapati1` / `AvinashNutalapati1.secure-ai-pipeline`.
