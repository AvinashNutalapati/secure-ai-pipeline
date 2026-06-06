# Secure AI Pipeline — VS Code / Cursor extension

Inline security diagnostics for AI-generated code. The same insecure-default patterns
the CI pipeline blocks are flagged the moment you save a file — no CI wait, no network,
no server, no Python. Everything runs locally in the extension process and works in
[Cursor](https://cursor.com) (VS Code-compatible).

## What it catches

| Rule | Severity | Quick Fix |
|------|----------|-----------|
| `tls-verify-false` | Error | `verify=False` → `verify=True` |
| `flask-debug-true` | Error | `debug=True` → env-gated |
| `wildcard-cors` | Warning | `"*"` → explicit origin |
| `subprocess-shell-true` | Error | `shell=True` → `shell=False` |
| `sql-injection-fstring` | Error | — (use parameterised queries) |
| `hardcoded-api-key` | Error | string literal → `os.environ[...]` |

## Features

- **Inline diagnostics** on save (Python and JS/TS) with the rule ID as the source.
- **Quick Fixes** (lightbulb) that apply the secure replacement in one click.
- **Status bar** item bottom-right: `$(shield) SAP: 3 issues` — click to open Problems.
- **Sidebar view** (shield icon in the Activity Bar): all findings across open files,
  grouped by rule. Click a finding to jump to the line.

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

```bash
npm install -g @vscode/vsce
vsce publish --pat <YOUR_MARKETPLACE_PAT>
```

Publisher ID and extension ID are `AvinashNutalapati` / `AvinashNutalapati.secure-ai-pipeline`.
