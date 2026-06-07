# Secure AI Pipeline

> Security for AI-assisted development. A 5-minute checkup for developers shipping
> production code with Cursor, Copilot, Claude Code, and MCP — it finds the hidden
> **blast radius** of your AI coding workflow before it reaches production.

[![CI](https://github.com/AvinashNutalapati/secure-ai-pipeline/actions/workflows/ci.yml/badge.svg)](https://github.com/AvinashNutalapati/secure-ai-pipeline/actions/workflows/ci.yml)
[![Security Pipeline](https://github.com/AvinashNutalapati/secure-ai-pipeline/actions/workflows/security.yml/badge.svg)](https://github.com/AvinashNutalapati/secure-ai-pipeline/actions/workflows/security.yml)
[![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/AvinashNutalapati1.secure-ai-pipeline?label=VS%20Code%20Marketplace&logo=visualstudiocode)](https://marketplace.visualstudio.com/items?itemName=AvinashNutalapati1.secure-ai-pipeline)
[![Installs](https://img.shields.io/visual-studio-marketplace/i/AvinashNutalapati1.secure-ai-pipeline?logo=visualstudiocode)](https://marketplace.visualstudio.com/items?itemName=AvinashNutalapati1.secure-ai-pipeline)
[![Use this template](https://img.shields.io/badge/Use%20this-template-2ea44f?logo=github)](https://github.com/AvinashNutalapati/secure-ai-pipeline/generate)
![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)

## Quick start — the 5-minute checkup

```bash
npx secure-ai-pipeline@latest scan .
```

Runs locally (no code leaves your machine) and prints an **AI Agent Blast Radius
Score** — how far an attacker who gets a foothold in your AI workflow can reach —
with concrete fixes. Add `--html report.html` for a shareable report.

```text
  AI Agent Blast Radius Score: 0/100  (grade F)
  4 critical  11 high  2 medium

  ● CRITICAL  MCP server 'github' receives secrets via env   mcp.json
  ● CRITICAL  Claude can read outside the workspace          .claude/settings.json
  ● CRITICAL  Workflow uses pull_request_target              .github/workflows/deploy.yml
  ● HIGH      Cursor rule has a risky directive (auto-execution)  .cursorrules
  …
```

Try it on the bad-on-purpose demo repo (scores 0/100):

```bash
git clone https://github.com/AvinashNutalapati/secure-ai-pipeline
cd secure-ai-pipeline
npx secure-ai-pipeline scan examples/vulnerable-ai-workflow --html report.html
```

## Why this exists

AI coding assistants don't just write the occasional insecure line — they widen the
**attack surface around how you develop**. Untrusted text from issues, docs, repo
rules, and MCP tool output can steer an agent that has access to your files,
terminal, secrets, and deploy pipeline. Most AppSec tools scan code *after* it
lands; very few look at the **seam** between the assistant, the laptop, the repo,
MCP servers, and CI. That seam is what this project owns.

## What the blast-radius checkup finds

| Surface | Scanner | Examples |
|---|---|---|
| **AI IDE rules** | `ai_ide` | `.cursorrules`/Cline/Windsurf/Copilot rules that auto-run, skip approval, `curl\|bash`, or contain prompt-injection overrides |
| **Claude permissions** | `claude` | home/root reads (`Read(//Users/**)`), wildcard `Bash(*)`, `rm -rf`, `bypassPermissions` |
| **MCP configs** | `mcp` | secrets handed to servers, `bash`/`curl\|bash` startup, `/` filesystem mounts, unauthenticated remotes |
| **GitHub Actions** | `github_actions` | unpinned actions (tj-actions lesson), `pull_request_target`, `github.event` script injection |
| **Dependency trust** | `packages` | hallucinated / slopsquatted imports that don't exist on PyPI/npm |

Docs: [threat model](docs/threat-model.md) · [AI tool risk](docs/ai-tool-risk.md) ·
[MCP hardening](docs/mcp-hardening.md) · [privacy](docs/privacy.md).

### Gate it in CI

Drop a [`secure-ai-pipeline.yml`](examples/secure-ai-pipeline.example.yml) policy at
your repo root to turn the checkup into a build gate (`fail_on`, rule `ignore`,
`mcp.allowed_servers`, action-pinning toggles). Without a policy file, `scan` is
report-only and friendly.

## The code-security pipeline (still here)

Beyond workflow posture, the original CI pipeline catches AI-generated **code**
flaws. Install it with `init`, the template, or the Action:

<details>
<summary><b>npx installer</b></summary>

```bash
npx secure-ai-pipeline@latest init
```
Drops the CI workflow, anti-slopsquatting guard, AI-posture scanners, custom SAST
rules, and pre-commit hooks into your repo. Idempotent.
</details>

<details>
<summary><b>GitHub template</b> — click <b>Use this template</b>, the pipeline is pre-wired.</summary>
</details>

<details>
<summary><b>GitHub Action</b> (full workflow — copy to <code>.github/workflows/security.yml</code>)</summary>

```yaml
name: Secure AI Pipeline
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # required for SARIF upload to the Security tab

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: AvinashNutalapati/secure-ai-pipeline@v2
        with:
          staging-url: ${{ vars.STAGING_URL }}   # optional, enables DAST
          fail-on-warnings: "false"              # optional, block on WARN findings
```

The action runs the AI Blast Radius checkup plus package, secret, SAST, and SCA gates.
</details>

| # | Flaw | Caught by | Action |
|---|------|-----------|--------|
| F1 | Hallucinated package import (PyPI/npm) | `check_packages.py` | Hard block |
| F2 | Hardcoded API key / secret | Gitleaks | Hard block |
| F3 | SQL injection via f-string | Semgrep `sql-injection-fstring` | Block |
| F4 | `app.run(debug=True)` | Semgrep `flask-debug-true` | Block |
| F5 | Wildcard CORS (`origins="*"`) | Semgrep `wildcard-cors` | Warn |
| F6 | TLS `verify=False` | Semgrep `tls-verify-false` | Block |
| F7 | `subprocess(..., shell=True)` | Semgrep `subprocess-shell-true` | Block |
| F8 | Known-CVE dependency (e.g. Flask 1.0) | Trivy SCA | Block |

See [`demo/DEMO.md`](demo/DEMO.md) for the deliberately-vulnerable app that trips every gate.

## IDE & AI integrations

- **VS Code / Cursor** — inline diagnostics + quick fixes as you save.
  Install from the [**Marketplace**](https://marketplace.visualstudio.com/items?itemName=AvinashNutalapati1.secure-ai-pipeline)
  or search **"Secure AI Pipeline"**. ([details](extensions/vscode/README.md))
- **Claude Code (MCP)** — scan packages and code mid-session:
  `claude mcp add secure-ai-pipeline -- python -m extensions.claude_mcp.mcp_server` ([details](extensions/claude_mcp/README.md))
- **OpenAI Custom GPT** — deploy [`extensions/claude_mcp/server.py`](extensions/openai-gpt/DEPLOY.md)
  and add [`openapi.yaml`](extensions/openai-gpt/openapi.yaml) as an Action.

## CLI

```bash
npx secure-ai-pipeline scan .            # AI blast-radius checkup (default command)
npx secure-ai-pipeline scan . --html report.html --json report.json
npx secure-ai-pipeline scan . --fail-on high     # gate in CI
npx secure-ai-pipeline init              # install the CI pipeline + hooks
npx secure-ai-pipeline doctor            # check prerequisites
```

## Contributing

Issues and PRs welcome — see the [issue tracker](https://github.com/AvinashNutalapati/secure-ai-pipeline/issues).
Run the test suite with `python -m pytest tests/ -v` before opening a PR.

## License

[MIT](LICENSE)
