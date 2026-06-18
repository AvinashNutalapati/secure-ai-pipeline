# Secure AI Pipeline

> **Ship AI-written code without shipping its mistakes.**
> Cursor, Copilot, and Claude Code write code fast — and quietly widen your attack
> surface: invented package names, inlined secrets, over-permissioned agents,
> insecure defaults. This is the free, open-source security layer that catches all
> of it — in your terminal, your editor, your CI, and inside the AI assistant itself.
> 100% free · MIT licensed · **your code never leaves your machine**

[![CI](https://github.com/AvinashNutalapati/secure-ai-pipeline/actions/workflows/ci.yml/badge.svg)](https://github.com/AvinashNutalapati/secure-ai-pipeline/actions/workflows/ci.yml)
[![Security Pipeline](https://github.com/AvinashNutalapati/secure-ai-pipeline/actions/workflows/security.yml/badge.svg)](https://github.com/AvinashNutalapati/secure-ai-pipeline/actions/workflows/security.yml)
[![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/AvinashNutalapati1.secure-ai-pipeline?label=VS%20Code%20Marketplace&logo=visualstudiocode)](https://marketplace.visualstudio.com/items?itemName=AvinashNutalapati1.secure-ai-pipeline)
[![Installs](https://img.shields.io/visual-studio-marketplace/i/AvinashNutalapati1.secure-ai-pipeline?logo=visualstudiocode)](https://marketplace.visualstudio.com/items?itemName=AvinashNutalapati1.secure-ai-pipeline)
[![Use this template](https://img.shields.io/badge/Use%20this-template-2ea44f?logo=github)](https://github.com/AvinashNutalapati/secure-ai-pipeline/generate)
![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)

---

## See it work — 30 seconds, nothing to configure

```bash
npx secure-ai-pipeline@latest scan .
```

One command. No account, no upload, no telemetry. It runs every security layer it
can and prints a compact verdict per layer:

```text
  Secure AI Pipeline — full scan

  ▍ SECRETS                          · gitleaks
      1 critical
      CRITICAL      Secret detected: AWS access key id

  ▍ DEPENDENCIES (SCA + malicious packages)   · trivy + osv-scanner
      1 critical  3 high
      CRITICAL      MALICIOUS PACKAGE: evil-pkg 1.0.0 — MAL-2024-0001
      HIGH     ×3   Vulnerable dependency: lodash 4.17.0 — CVE-…

  ▍ STATIC ANALYSIS (SAST)           · semgrep
      2 high
      HIGH          SQL query built from an f-string

  ▍ AI WORKFLOW BLAST RADIUS         · built-in
      1 critical  5 high
      CRITICAL      Workflow uses pull_request_target
      …

  ▍ DYNAMIC ANALYSIS (DAST)          · not run
      pass --dast-url <url> (or answer the prompt) to scan a running app
```

Want to watch it light up? Point it at the deliberately-insecure demo repo:

```bash
git clone https://github.com/AvinashNutalapati/secure-ai-pipeline-demo
npx secure-ai-pipeline scan secure-ai-pipeline-demo --html report.html
```

---

## Why this exists

AI assistants don't just write the occasional insecure line. They reshape **how you
develop** — and every new convenience is a new way in:

- **🎣 Slopsquatting — the one nobody else catches.** Models confidently invent
  package names that don't exist. Attackers pre-register those exact names on
  PyPI/npm, and your next `pip install` runs their malware. The built-in
  **anti-slopsquatting guard** verifies every import against the live registry
  before it can land. *No other drop-in pipeline does this.*
- **🤖 Over-permissioned agents.** A bare `"Bash"` in `.claude/settings.json`, an
  MCP server holding your `GITHUB_TOKEN`, a `.cursorrules` that says "run without
  asking" — each one turns a single prompt injection into real damage.
- **🩹 Classic AI code smells.** `debug=True`, `verify=False`, f-string SQL,
  hardcoded keys, `shell=True` — generated faster than anyone reviews them.

Most AppSec tools scan code *after* it lands. This one owns the **seam** between the
assistant, your laptop, the repo, your MCP servers, and CI — the place AI risk
actually lives.

---

## Pick your door — one engine, six ways in

| You want… | Do this | You get |
|---|---|---|
| **A 5-minute checkup** | `npx secure-ai-pipeline scan .` | Findings + Blast Radius Score + fix prompts, in your terminal |
| **One line in CI** ⭐ | [GitHub Action](#-github-action--recommended-zero-install) | The full pipeline as a single `uses:` step — zero local install |
| **CI for an existing repo** | `npx secure-ai-pipeline init` | Workflow, scanners, SAST rules, pre-commit hooks — copied in, idempotent, never overwrites your files |
| **CI for a new repo** | [Use this template](https://github.com/AvinashNutalapati/secure-ai-pipeline/generate) | A repo born with the pipeline wired and a setup checklist issue |
| **Findings while you type** | [VS Code / Cursor extension](#-vs-code--cursor) | Inline squiggles + one-click quick fixes + a Blast Radius command |
| **Your AI checks itself** | [MCP server](#-claude-code--codex--cursor-mcp) / [Custom GPT](#-openai-custom-gpt) | The assistant verifies packages & scans code mid-conversation |

---

## ⭐ GitHub Action — recommended, zero install

The simplest path: add one workflow file. GitHub's runner installs the scanners on
every run, so **you install nothing** and **your code never leaves your own GitHub
repo** — we never see it.

Add `.github/workflows/security.yml`:

```yaml
name: Secure AI Pipeline
on:
  push:
  pull_request:
  workflow_dispatch:          # also lets you run it by hand from the Actions tab

permissions:
  contents: read
  security-events: write      # lets findings show in the Security tab (public repos / GHAS)

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2 (SHA-pinned — the practice this tool checks for)
        with:
          fetch-depth: 0                              # full git history for the secret scan
      - uses: AvinashNutalapati/secure-ai-pipeline@v3
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}   # composite actions can't read secrets themselves
        with:
          fail-on-warnings: "false"                   # report-only by default; "true" blocks on CVEs/warnings
          # staging-url: ${{ vars.STAGING_URL }}      # optional: enables the ZAP DAST scan
          # upload-sarif: "auto"                       # auto (public repos) | true (force, needs GHAS) | false
          # deep-scan: "false"                         # "true" also runs the heaviest scanners (GuardDog) — slower, more thorough
```

Push it (or run it from the **Actions** tab) and every push / PR runs a whole stack
of OSS scanners in parallel, then **consolidated and de-duplicated across tools** —
the same issue found by N scanners shows as **one finding marked "confirmed by N
tools"**, never N copies:

| Layer | Engines (extras activate automatically when present) |
|---|---|
| **Secrets** | Gitleaks · TruffleHog (verified) · detect-secrets |
| **SAST** | Semgrep · Bandit · gosec · Brakeman · ESLint-security · opengrep + AI-specific rules (LLM-output→sink, weak-crypto, insecure-deserialization, JWT) |
| **Dependencies** | Trivy · OSV · Grype · pip-audit · npm-audit (reachability-triaged) |
| **Dependency trust** | anti-slopsquatting · typosquat near-miss · known-malicious (OSV MAL-) · lockfile integrity · GuardDog |
| **IaC** | Checkov · KICS · kube-linter |
| **CI/CD workflows** | zizmor · actionlint · Scorecard · poutine (GitLab/Azure/Tekton) |
| **AI workflow** | invisible-Unicode injection · MCP tool-poisoning & cross-server paths · rug-pull/TOCTOU drift · agent over-permission · the Blast Radius check |

Results land in a **job summary**: one table per scan type (severity, finding,
location, suggested fix — including the dependency's fixed version, each finding
tagged with its CWE + OWASP-LLM/Agentic class) plus **copy-paste AI fix prompts**
per type and one combined prompt.

> **Defaults are report-first, so the first run isn't a wall of red:** leaked
> secrets and hallucinated/malicious packages **always block**; CVEs and SAST
> warnings are **reported, not blocking**, until you set `fail-on-warnings: "true"`.

> **Two lines that matter:** `fetch-depth: 0` lets Gitleaks scan your full history
> (a shallow clone only sees HEAD), and the `GITHUB_TOKEN` env line is required
> because composite actions can't read `secrets` on their own.
>
> **Private repos:** the Security-tab upload needs a public repo or GitHub Advanced
> Security; without it the upload auto-skips, the run stays green, and findings
> still appear in the **Actions log** and the **job summary**.
>
> **Pin for production:** `@v3` tracks the latest fix; pin to a tag/SHA (e.g.
> `@v3.3.0`) to lock the version.

---

## Use it locally

`npx secure-ai-pipeline scan .` (above) runs locally with no account, no upload, no
telemetry. Output stays compact (**severity + title only**) — drill in, export, and
gate from there:

```bash
npx secure-ai-pipeline scan . --detail sast                       # expand one layer
npx secure-ai-pipeline scan . --fix                               # auto-apply deterministic fixes (verify=False→True, debug=True→False…)
npx secure-ai-pipeline scan . --reachable-only                    # drop CVEs in packages you never import
npx secure-ai-pipeline scan . --dast-url http://localhost:3000    # add a DAST pass
npx secure-ai-pipeline scan . --html report.html --json out.json  # shareable reports
npx secure-ai-pipeline scan . --tools                             # which OSS engines you have
npx secure-ai-pipeline posture .                                  # just the AI blast-radius checkup
npx secure-ai-pipeline init                                       # install the CI workflow + hooks here
```

A ready-to-paste **fix prompt per layer** is written to `.secure-ai-pipeline/`. Each
layer uses its open-source scanner when installed and a built-in Python fallback
otherwise — install the engines for deeper coverage (all open source, no accounts):

```bash
brew install gitleaks trivy osv-scanner   # secrets · CVEs · malicious packages
pipx install semgrep                      # full SAST (JS/TS + community rules)
# DAST uses ZAP via Docker (https://docs.docker.com/get-docker/)
```

> Malicious-package detection uses **OSV-Scanner** (open source, reads the OSV
> `MAL-` advisories). Socket.dev needs a paid account/API key, so it's an opt-in
> add-on (`SOCKET_API_KEY` + `npm i -g @socketsecurity/cli`), not the default.

---

## 🧩 VS Code / Cursor

Inline diagnostics as you write — no CI wait. Squiggles on insecure patterns,
one-click quick fixes, and a **Blast Radius** command for the whole workspace.

[**Install from the Marketplace →**](https://marketplace.visualstudio.com/items?itemName=AvinashNutalapati1.secure-ai-pipeline)

---

## 🔌 Claude Code · Codex · Cursor (MCP)

Let the assistant check *itself*. One install gives you the `sap-mcp` command, then
point your tool at it:

```bash
pipx install git+https://github.com/AvinashNutalapati/secure-ai-pipeline.git
# (or `pipx install secure-ai-pipeline` once it's on PyPI)
sap-mcp --selftest          # verify it works before wiring it up
```

- **Claude Code** — `claude mcp add secure-ai-pipeline -- sap-mcp`
- **Codex CLI** — add to `~/.codex/config.toml`:
  `[mcp_servers.secure-ai-pipeline]` / `command = "sap-mcp"`
- **Cursor / Windsurf / Cline** — add to the MCP config:
  `{ "mcpServers": { "secure-ai-pipeline": { "command": "sap-mcp" } } }`
- **Claude Desktop** — one-click: build a `.dxt` bundle
  (`python3 extensions/claude_mcp/dxt/build_dxt.py`) and install it via
  **Settings → Extensions → Install from file**.

Your assistant can now call `check_package`, `verify_install`, `sast_scan`,
`sca_scan`, `full_scan`, and `scan_repo` mid-session — ask it to *"verify that
package exists before importing it"* or *"scan this code before you give it to me."*
Every tool returns a **verdict** (block / warn / ok). The snippet tools work
standalone; `scan_repo` runs the full multi-tool scan when the pipeline is present.
([details](extensions/claude_mcp/README.md))

---

## 🤝 OpenAI Custom GPT

The scanner API runs at **https://api.mirawyn.com**. Create a GPT, paste
[`openapi.yaml`](extensions/openai-gpt/openapi.yaml) as an Action and
[`GPT_INSTRUCTIONS.md`](extensions/openai-gpt/GPT_INSTRUCTIONS.md) as its
instructions — done. (Self-hosting: [DEPLOY.md](extensions/openai-gpt/DEPLOY.md).)

---

## What it catches

**Your AI workflow** — the Blast Radius checkup (`scan`, the Action, and the editor):

| Surface | Examples |
|---|---|
| AI IDE rules | `.cursorrules`/Cline/Windsurf/Copilot/`CLAUDE.md` rules that auto-run, skip approval, `curl\|bash`, prompt-injection overrides, exfiltration-shaped instructions, **base64/hex/ROT/Zalgo-obfuscated payloads** |
| Invisible Unicode | **hidden Tag / bidi / zero-width characters** smuggled into rules/skill/MCP files — the "Rules File Backdoor" a human reviewer can't see |
| MCP servers | secrets handed to servers, shell startup, `/` mounts, unauthenticated remotes, **tool-poisoning language in tool descriptions, permissive input schemas, cross-server exfil/RCE attack-paths** |
| Claude permissions | bare `"Bash"`/`"Read"` allows, home/root reads, `rm -rf`, `bypassPermissions`, unrestricted WebFetch, **oversized allow lists** |
| Rug-pull / TOCTOU | **approval-sensitive files (rules, MCP, workflows) mutated after approval** — vs a committed integrity baseline (Cuckoo Attack) |
| Compound exfiltration | a skill/rule file that **both reads a credential and transmits it off-box** |
| GitHub Actions | unpinned third-party actions (the tj-actions lesson), `pull_request_target` **+ PR-head checkout (pwn request)**, **secrets→unpinned action**, `github.event` script injection |
| Prompt privacy | secrets, internal URLs/IPs, and emails sitting in files that get sent to model providers |
| Config secrets | hardcoded tokens in `.env`, `mcp.json`, Claude configs (GitHub, OpenAI, Anthropic, AWS, Slack, Stripe key shapes) |
| Dependency trust | hallucinated/slopsquatted imports (live PyPI/npm), **typosquat near-misses, known-malicious names (OSV MAL-), lockfile integrity** |

**Your AI-written code** — the CI pipeline (Stage 0 blocks before Stage 1 runs):

| Flaw | Caught by | Action |
|---|---|---|
| Hallucinated package import | `check_packages.py` (live registry check) | Hard block |
| Leaked secret anywhere in git history | Gitleaks | Hard block |
| SQL injection via f-string/concat/format | Semgrep `sql-injection-fstring` | Block |
| `app.run(debug=True)` (any arg position) | Semgrep `flask-debug-true` | Block |
| TLS `verify=False` | Semgrep `tls-verify-false` | Block |
| `subprocess(..., shell=True)` | Semgrep `subprocess-shell-true` | Block |
| `eval/exec(request...)` | Semgrep `eval-user-input` | Block |
| **LLM output → eval/exec/shell** (OWASP LLM05) | `llm-output-to-sink` | Block |
| **Unsafe deserialization** (`pickle`, `yaml.load`) | `insecure-deserialization` | Block |
| **JWT signature verification disabled** | `jwt-verify-disabled` | Block |
| **Weak crypto** (`md5`/`sha1`), **insecure-random tokens**, **bind `0.0.0.0`** | `weak-hash` / `insecure-random-token` / `bind-all-interfaces` | Warn |
| Hardcoded credentials | Semgrep + Gitleaks | Block |
| Wildcard CORS | Semgrep `wildcard-cors` | Warn |
| Known-CVE pinned dependency | Trivy SCA | Block |
| Live-site issues (XSS headers, cookies…) | ZAP baseline (needs `STAGING_URL`) | Report only |

Many of these have a **deterministic `--fix`** (e.g. `verify=False`→`verify=True`,
`debug=True`→`debug=False`), and every finding is tagged with its **CWE + OWASP
class** for governance reporting.

---

## Make it a gate

Drop a [`secure-ai-pipeline.yml`](examples/secure-ai-pipeline.example.yml) at your
repo root to turn the checkup into a build gate:

```yaml
fail_on: [critical, high]       # threshold — listing high also gates critical
ignore: [gha-unpinned-action]   # rule IDs to suppress (say why!)
exclude: ["examples/**"]        # paths whose findings are dropped
mcp:
  allowed_servers: [github-readonly]   # anything else gets flagged
```

No policy file? `scan` stays report-only and friendly. You also get `--fail-on high`
for one-off CI gating, `--offline` to skip network checks, `--exclude
'data/**,test/**'` to silence fixture/vendor dirs, and inline `# nosemgrep` /
`# nosec` comments to suppress a confirmed-safe line in place. In CI, the same is the
`fail-on-warnings` input on the Action (above).

---

## Privacy & trust

- **Local-first.** `scan`, the editor extension, and the pre-commit hooks never
  upload your code. The built-in scanners' only network calls are existence checks
  of package *names* against PyPI/npm (skippable with `--offline`). The optional OSS
  engines run locally too; trivy/osv-scanner fetch their own vulnerability
  databases, which you can pre-cache for air-gapped use.
- **Fail-closed where it counts.** Missing scanner output fails the gate; a pending
  (`underReview`) suppression doesn't sneak findings through; registry outages warn
  instead of inventing verdicts.
- **No accounts, no tiers, no telemetry.** MIT licensed. If it saves you once, it
  has paid for itself forever.

Docs: [threat model](docs/threat-model.md) · [AI tool risk](docs/ai-tool-risk.md) ·
[MCP hardening](docs/mcp-hardening.md) · [privacy](docs/privacy.md) ·
[domain setup](docs/domain-setup.md)

---

## Contributing

Issues and PRs welcome — [issue tracker](https://github.com/AvinashNutalapati/secure-ai-pipeline/issues).
Run `python -m pytest tests/ -v` before opening a PR. The pipeline runs on itself:
this repo must pass its own gates.

## License

[MIT](LICENSE) — free for personal and commercial use.
