# Changelog

## 2.0.0

Aligns the extension with the project's v2 release (AI-assisted-development security).

### Added
- **AI-workflow diagnostics.** Inline findings now appear on the configs that
  shape AI-tool behavior, not just source code:
  - **MCP** (`mcp.json`, `.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json`,
    `claude_desktop_config.json`): secrets passed to servers, `bash`/`curl|bash`
    startup commands, broad `/`·`~`·`$HOME` filesystem mounts, unauthenticated
    `http://` remotes.
  - **Claude permissions** (`.claude/settings.json`, `settings.local.json`):
    reads outside the workspace (`Read(//Users/**)`), wildcard `Bash(*)`,
    destructive `rm -rf`, and `bypassPermissions` mode.
  - **AI IDE rules** (`.cursorrules`, `.clinerules`, `.windsurfrules`,
    `copilot-instructions.md`, `AGENTS.md`): auto-run / skip-confirmation,
    fetch-and-execute, and prompt-injection override text.
  - **GitHub Actions** (`.github/workflows/*.yml`): actions pinned by mutable
    tag instead of commit SHA, `pull_request_target`, and untrusted
    `${{ github.event.* }}` interpolation in `run:` steps.
- **New command** — *Secure AI Pipeline: AI Blast Radius Scan*: scans the whole
  workspace and reports a 0–100 blast-radius score.

### Fixed
- Quick fix for hardcoded secrets is now language-aware: `os.environ[...]` in
  Python, `process.env.*` in JS/TS (previously emitted Python in JS files).
- The debug-mode and secret quick fixes now insert `import os` when it's missing.

### Notes
- Everything still runs locally — no network, no server, no Python.

## 1.0.0
- Initial release: inline diagnostics + quick fixes for AI-generated insecure
  code (TLS verify, Flask debug, wildcard CORS, shell=True, SQL f-strings,
  hardcoded secrets); status bar and findings sidebar.
