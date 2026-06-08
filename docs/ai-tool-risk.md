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

## 4. Prompt privacy (`prompt_privacy`)

Anything in a rules/prompt file (`.cursorrules`, `.clinerules`, `.windsurfrules`,
`copilot-instructions.md`, `AGENTS.md`, `CLAUDE.md`, `.claude/*.md`) is fed to the
model and shared with the team, so it's the wrong place for sensitive content:

| Rule | Flags |
|---|---|
| `prompt-secret` | a token/key/private-key embedded in a rules/prompt file (HIGH) |
| `prompt-internal-url` | internal hostnames (`*.internal`, `*.corp`, `*.local`) — topology disclosure |
| `prompt-private-ip` | RFC-1918 IPs (`10.x`, `192.168.x`, `172.16–31.x`) |
| `prompt-email` | contact/customer emails (skips `example.com` and placeholders) |

## 5. Config secrets (`secrets`)

Local, scan-time secret detection in `.env` files and AI/tool config
(`mcp.json`, `.claude/*.json`) — complements Gitleaks (which scans git history in
CI). Credential-shaped values (`ghp_…`, `github_pat_…`, `sk-…`, `AKIA…`, Slack
tokens, PEM private keys) are `config-hardcoded-secret` (CRITICAL); a secret-named
`.env` variable set to a literal value is `env-hardcoded-secret` (HIGH).
`${VAR}`/`$VAR` references and obvious placeholders are ignored.
