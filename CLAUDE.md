# Secure AI Pipeline — Project Context for Claude Code

## What this project is

A production-ready security pipeline for developers who build apps using AI coding assistants
(Cursor, Copilot, Claude Code, etc.). It intercepts the specific failure modes of AI-generated
code — hallucinated package names, inlined secrets, insecure defaults, CVE-laden pinned deps —
before they reach production.

The core differentiator is the **anti-slopsquatting guard**: AI models invent plausible package
names that don't exist on PyPI/npm. An attacker pre-registers the name. The next `pip install`
silently installs malware. No existing DevSecOps tool catches this. We do.

## Product vision

Three distribution channels, one codebase:

1. **One-line installer** — `npx secure-ai-pipeline@latest init` drops the files into any repo
2. **GitHub template repo** — new projects click "Use this template", pipeline is pre-wired
3. **GitHub Action** — published to marketplace, single `uses:` line in any workflow

Three IDE/AI integrations:

4. **VS Code / Cursor extension** — inline diagnostics as code is written, no CI wait
5. **Claude MCP server** — Claude Code can call security tools mid-session
6. **OpenAI GPT Action** — custom GPT that reviews code snippets on demand

## Existing files (already built — do not recreate)

```
.github/workflows/security.yml     CI pipeline — 4 jobs, 3 stages
scripts/check_packages.py          Anti-slopsquatting guard (AST-based, PyPI + npm)
scripts/run_pipeline.py            Local runner — all gates in pure Python, no deps
.semgrep/ai-insecure-defaults.yml  7 custom Semgrep rules for AI coding patterns
.zap/rules.tsv                     ZAP baseline noise suppression
.pre-commit-config.yaml            Local hooks — Gitleaks + package check
scripts/blast_radius.py            AI Agent Blast Radius score + scanners/
scripts/scanners/                  AI IDE / Claude / MCP / Actions / prompt / secrets
```

Deliberately-vulnerable demo fixtures live in a SEPARATE repo
(`secure-ai-pipeline-demo`) so this repo stays a clean product that passes its own
security pipeline. Do not add intentionally-vulnerable code here.

## Gate architecture

```
Stage 0 (parallel, HARD BLOCK):
  check_packages.py  — hallucinated package names → exit 1
  Gitleaks           — secrets in full git history → exit 1

Stage 1 (parallel, runs only if Stage 0 passes):
  Semgrep            — SAST with custom AI-insecure-defaults ruleset → SARIF → GitHub UI
  Trivy              — SCA + IaC + container CVEs → SARIF → GitHub UI

Stage 2 (report only, never blocks):
  ZAP baseline       — DAST against $STAGING_URL → HTML artifact
```

## Gating policy

| Finding type | Action |
|---|---|
| Leaked secret | Hard block — always |
| Hallucinated / non-existent package | Hard block |
| Critical/High CVE with known fix | Block |
| High-confidence SAST (injection, hardcoded crypto) | Block |
| Medium/Low SCA + SAST | Warn / annotate PR |
| DAST findings | Report only |

## Tech stack decisions (already made — honour these)

- Python for all scripting (check_packages.py, run_pipeline.py) — stdlib only, no extra deps
- GitHub Actions for CI — composite action pattern for marketplace publish
- TypeScript for VS Code extension — standard for VS Code ecosystem
- Python FastAPI for MCP server — lightweight, Claude Code compatible
- OpenAPI 3.1 YAML for the GPT Action spec
- No paid tools, no SaaS accounts required for the core pipeline

## What still needs to be built (the production gaps)

See `BUILD_PROMPT.md` for the full Claude Code session prompt that drives this work.

Priority order:
1. Repo structure cleanup + `package.json` + `setup.py` (versioning foundation)
2. `npx`-compatible CLI installer (`init` command)
3. GitHub Action `action.yml` + marketplace metadata
4. VS Code / Cursor extension (`extensions/vscode/`)
5. Claude MCP server (`extensions/claude-mcp/`)
6. OpenAI GPT Action spec (`extensions/openai-gpt/`)
7. Tests for all scripts (`tests/`)
8. GitHub repo setup instructions for the user

## User info needed (ask once at session start, then never again)

- GitHub username — needed to personalise `action.yml`, template repo URLs, and README badges
- That is all. Derive everything else from the codebase.

## Coding conventions

- Python: stdlib only in `scripts/`. External deps only in `extensions/` with explicit `requirements.txt`.
- All shell scripts: `set -euo pipefail`
- TypeScript: strict mode, no `any`
- Every file that touches the user's code must be idempotent — safe to run multiple times
- Prefer additive changes. Never delete existing working code without an explicit instruction.

## Definition of done

- `npx secure-ai-pipeline@latest init` works end-to-end in a clean repo
- VS Code extension shows inline diagnostics on an insecure Python file
- MCP server responds to `check_packages`, `sast_scan`, `sca_scan` tool calls
- OpenAI GPT Action spec validates against the OpenAPI 3.1 linter
- All Python scripts pass `python -m pytest tests/` with no failures
- Workflows pass `actionlint`; `action.yml` passes the structural check in ci.yml
  (actionlint cannot lint composite-action files)
- README has a one-paragraph summary, a 60-second quickstart, and badge links
