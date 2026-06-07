# AI tool risk — rules, permissions, and CI

AI coding tools treat local config as **trusted instructions** and run with broad
authority. Three surfaces matter most, and `scan` checks all three.

## 1. AI IDE rules (`ai_ide`)

Rules files are loaded into the agent's context and trusted. Anyone who can edit them
— including a PR author — can steer the agent.

Scanned: `.cursorrules`, `.cursor/rules/*`, `.clinerules`, `.windsurfrules`,
`.windsurf/rules/*`, `.github/copilot-instructions.md`, `AGENTS.md`.

Flagged directives: auto-run/yolo, "without asking"/skip-confirmation,
`curl|bash` fetch-execute, destructive/safety-disabling text, prompt-injection
overrides ("ignore previous instructions"), exfiltration-shaped instructions.

> Review rules files in PRs as security-sensitive. Keep them minimal and declarative.

## 2. Claude Code permissions (`claude`)

`.claude/settings.json` / `settings.local.json` define what the agent can do without
asking. The dangerous patterns:

| Rule | Example | Fix |
|---|---|---|
| `claude-broad-read` | `Read(//Users/**)` | `Read(./**)`; deny home/root paths |
| `claude-wildcard-bash` | `Bash(*)` | `Bash(npm test*)` and other specifics |
| `claude-destructive-bash` | `Bash(rm -rf …)` | remove blanket approval |
| `claude-broad-network` | `WebFetch(*)` | restrict to trusted domains |
| `claude-bypass-mode` | `defaultMode: bypassPermissions` | use `default` (prompt) mode |

Never commit `settings.local.json` (machine paths + broad grants). A safe starting
point is [`examples/claude/settings.safe.example.json`](../examples/claude/settings.safe.example.json).

## 3. GitHub Actions (`github_actions`)

| Rule | Risk |
|---|---|
| `gha-unpinned-action` | Mutable tag/branch ref — a compromised tag runs attacker code with CI secrets (tj-actions, 2025). Pin to a full commit SHA. |
| `gha-pull-request-target` | Runs with secrets in the context of untrusted PR code. Prefer `pull_request`; never check out PR head with secrets. |
| `gha-script-injection` | `${{ github.event.* }}` interpolated into `run:` — pass via `env:` and reference `"$VAR"`. |
