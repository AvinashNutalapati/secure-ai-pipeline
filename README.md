# Secure AI Pipeline

> **Ship AI-written code without shipping its mistakes.**
> A free, open-source security layer for developers who build with Cursor, Copilot,
> Claude Code, and MCP. One command tells you how exposed your AI workflow is —
> and the same toolkit gates your CI, your editor, and your AI assistant.
>
> 🌐 [mirawyn.com](https://mirawyn.com) · 100% free · MIT licensed · your code never leaves your machine

[![CI](https://github.com/AvinashNutalapati/secure-ai-pipeline/actions/workflows/ci.yml/badge.svg)](https://github.com/AvinashNutalapati/secure-ai-pipeline/actions/workflows/ci.yml)
[![Security Pipeline](https://github.com/AvinashNutalapati/secure-ai-pipeline/actions/workflows/security.yml/badge.svg)](https://github.com/AvinashNutalapati/secure-ai-pipeline/actions/workflows/security.yml)
[![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/AvinashNutalapati1.secure-ai-pipeline?label=VS%20Code%20Marketplace&logo=visualstudiocode)](https://marketplace.visualstudio.com/items?itemName=AvinashNutalapati1.secure-ai-pipeline)
[![Installs](https://img.shields.io/visual-studio-marketplace/i/AvinashNutalapati1.secure-ai-pipeline?logo=visualstudiocode)](https://marketplace.visualstudio.com/items?itemName=AvinashNutalapati1.secure-ai-pipeline)
[![Use this template](https://img.shields.io/badge/Use%20this-template-2ea44f?logo=github)](https://github.com/AvinashNutalapati/secure-ai-pipeline/generate)
![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)

## Try it — 60 seconds, nothing to install

```bash
npx secure-ai-pipeline@latest scan .
```

That's the whole onboarding. It runs locally (no account, no upload, no telemetry)
and prints your **AI Agent Blast Radius Score** — how far an attacker who gets a
foothold in your AI workflow could reach — with a concrete fix for every finding:

```text
  AI Agent Blast Radius Score: 55/100  (grade C)
  1 critical  2 high  1 medium

  ● CRITICAL  MCP server 'github' receives secrets via env      mcp.json
      fix: Use short-lived/OAuth tokens scoped to the server, or a secrets broker.
  ● HIGH      Claude has wildcard shell access                  .claude/settings.json
      fix: Allow only specific commands, e.g. Bash(npm test*).
  ● HIGH      Action not pinned by SHA: actions/checkout@v4     .github/workflows/ci.yml
      fix: Pin to a full 40-char commit SHA.
```

Add `--html report.html` for a shareable report. Want to watch it light up first?
Point it at the deliberately-insecure demo repo:

```bash
git clone https://github.com/AvinashNutalapati/secure-ai-pipeline-demo
npx secure-ai-pipeline scan secure-ai-pipeline-demo --html report.html
```

## The problem this solves

AI assistants don't just write the occasional insecure line — they widen the
**attack surface around how you develop**:

- **Slopsquatting.** Models invent plausible package names that don't exist.
  Attackers pre-register them on PyPI/npm; your next `pip install` runs malware.
  The anti-slopsquatting guard verifies every import against the live registry —
  no other drop-in pipeline does this.
- **Over-permissioned agents.** A bare `"Bash"` in `.claude/settings.json`, an MCP
  server holding your `GITHUB_TOKEN`, a `.cursorrules` file that says "run without
  asking" — each one turns a prompt injection into real damage.
- **Classic AI code smells.** `debug=True`, `verify=False`, f-string SQL,
  hardcoded keys, `shell=True` — generated faster than anyone reviews them.

Most AppSec tools scan code *after* it lands. This project owns the **seam**
between the assistant, your laptop, the repo, MCP servers, and CI.

## Pick how you want it — six doors, one engine

| You want… | Do this | You get |
|---|---|---|
| **A 5-minute checkup** | `npx secure-ai-pipeline scan .` | Blast Radius Score + fixes, in your terminal |
| **CI for an existing repo** | `npx secure-ai-pipeline init` | Workflow, scanners, SAST rules, pre-commit hooks — copied in, idempotent, never overwrites your files |
| **CI for a new repo** | [Use this template](https://github.com/AvinashNutalapati/secure-ai-pipeline/generate) | A repo born with the pipeline wired and a setup checklist issue |
| **One line in your workflow** | GitHub Action (snippet below) | Full pipeline as a single `uses:` step |
| **Findings while you type** | [VS Code / Cursor extension](https://marketplace.visualstudio.com/items?itemName=AvinashNutalapati1.secure-ai-pipeline) | Inline squiggles + one-click quick fixes, plus a Blast Radius command |
| **Your AI checks itself** | Claude MCP server / Custom GPT (below) | The assistant verifies packages and scans code mid-conversation |

### GitHub Action

Copy to `.github/workflows/security.yml`:

```yaml
name: Secure AI Pipeline
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # SARIF upload to the Security tab

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0                              # full history for the secrets scan
      - uses: AvinashNutalapati/secure-ai-pipeline@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}   # composite actions can't read secrets
        with:
          staging-url: ${{ vars.STAGING_URL }}        # optional, enables DAST
          fail-on-warnings: "false"                   # optional, block on WARN findings
```

The two extra lines matter: `fetch-depth: 0` lets Gitleaks scan your **full git
history** (a depth-1 clone only scans HEAD), and the `GITHUB_TOKEN` env line is
required because composite actions cannot read `secrets` themselves.

### Claude Code (MCP)

```bash
cd secure-ai-pipeline && pip install -r extensions/claude_mcp/requirements.txt
claude mcp add secure-ai-pipeline -- python -m extensions.claude_mcp.mcp_server
```

Claude can now call `check_package`, `sast_scan`, `sca_scan`, and `full_scan`
mid-session — ask it to "verify that package exists before importing it."
([details](extensions/claude_mcp/README.md))

### OpenAI Custom GPT

The scanner API runs at **https://api.mirawyn.com**. Create a GPT, paste
[`openapi.yaml`](extensions/openai-gpt/openapi.yaml) as an Action and
[`GPT_INSTRUCTIONS.md`](extensions/openai-gpt/GPT_INSTRUCTIONS.md) as its
instructions — done. (Self-hosting: [DEPLOY.md](extensions/openai-gpt/DEPLOY.md).)

## What it catches

**Your AI workflow** (the Blast Radius checkup — `scan`, the Action, and the editor):

| Surface | Examples |
|---|---|
| AI IDE rules | `.cursorrules`/Cline/Windsurf/Copilot rules that auto-run, skip approval, `curl\|bash`, prompt-injection overrides, exfiltration-shaped instructions |
| Claude permissions | bare `"Bash"`/`"Read"` allows, home/root reads, `rm -rf`, `bypassPermissions`, unrestricted WebFetch |
| MCP configs | secrets handed to servers, shell startup commands, `/` filesystem mounts, unauthenticated remotes |
| GitHub Actions | unpinned third-party actions (the tj-actions lesson), `pull_request_target`, `github.event` script injection |
| Prompt privacy | secrets, internal URLs/IPs, and emails sitting in files that get sent to model providers |
| Config secrets | hardcoded tokens in `.env`, `mcp.json`, Claude configs (GitHub, OpenAI, Anthropic, AWS, Slack, Stripe key shapes) |
| Dependency trust | hallucinated/slopsquatted imports verified against live PyPI & npm |

**Your AI-written code** (the CI pipeline — Stage 0 blocks before Stage 1 runs):

| Flaw | Caught by | Action |
|---|---|---|
| Hallucinated package import | `check_packages.py` (live registry check) | Hard block |
| Leaked secret anywhere in git history | Gitleaks | Hard block |
| SQL injection via f-string/concat/format | Semgrep `sql-injection-fstring` | Block |
| `app.run(debug=True)` (any arg position) | Semgrep `flask-debug-true` | Block |
| TLS `verify=False` | Semgrep `tls-verify-false` | Block |
| `subprocess(..., shell=True)` | Semgrep `subprocess-shell-true` | Block |
| `eval/exec(request...)` | Semgrep `eval-user-input` | Block |
| Hardcoded credentials | Semgrep + Gitleaks | Block |
| Wildcard CORS | Semgrep `wildcard-cors` | Warn |
| Known-CVE pinned dependency | Trivy SCA | Block |
| Live-site issues (XSS headers, cookies…) | ZAP baseline (needs `STAGING_URL`) | Report only |

## Gate it your way

Drop a [`secure-ai-pipeline.yml`](examples/secure-ai-pipeline.example.yml) at your
repo root to turn the checkup into a build gate:

```yaml
fail_on: [critical, high]   # threshold — listing high also gates critical
ignore: [gha-unpinned-action]   # rule IDs to suppress (say why!)
exclude: ["examples/**"]        # paths whose findings are dropped
mcp:
  allowed_servers: [github-readonly]   # anything else gets flagged
```

No policy file? `scan` stays report-only and friendly. There's also
`--fail-on high` for one-off CI gating, `--offline` to skip network checks, and a
pure-local pipeline rehearsal: `python scripts/run_pipeline.py app.py requirements.txt`.

## Privacy & trust

- **Local-first:** `scan`, the editor extension, and the pre-commit hooks never
  upload your code. The only network calls are existence checks of package
  *names* against PyPI/npm (skippable with `--offline`).
- **Fail-closed where it counts:** missing scanner output fails the gate; a
  pending (`underReview`) suppression doesn't sneak findings through; registry
  outages warn instead of inventing verdicts.
- **No accounts, no tiers, no telemetry.** MIT licensed. If it saves you once,
  it has paid for itself forever.

Docs: [threat model](docs/threat-model.md) · [AI tool risk](docs/ai-tool-risk.md) ·
[MCP hardening](docs/mcp-hardening.md) · [privacy](docs/privacy.md) ·
[domain setup](docs/domain-setup.md)

## Contributing

Issues and PRs welcome — [issue tracker](https://github.com/AvinashNutalapati/secure-ai-pipeline/issues).
Run `python -m pytest tests/ -v` before opening a PR. The pipeline runs on itself:
this repo must pass its own gates.

## License

[MIT](LICENSE) — free for personal and commercial use.
