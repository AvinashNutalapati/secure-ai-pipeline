# Secure AI Pipeline

> A drop-in security pipeline for developers who build with AI coding assistants
> (Cursor, Copilot, Claude Code) — it catches the failure modes those tools produce
> before they reach production.

[![CI](https://github.com/AvinashNutalapati/secure-ai-pipeline/actions/workflows/ci.yml/badge.svg)](https://github.com/AvinashNutalapati/secure-ai-pipeline/actions/workflows/ci.yml)
[![Security Pipeline](https://github.com/AvinashNutalapati/secure-ai-pipeline/actions/workflows/security.yml/badge.svg)](https://github.com/AvinashNutalapati/secure-ai-pipeline/actions/workflows/security.yml)
![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)

## The problem

AI coding assistants are fast, but they fail in specific, repeatable ways: they hardcode
secrets, ship insecure defaults (`debug=True`, `verify=False`, wildcard CORS), build SQL
with f-strings, and pin dependencies riddled with known CVEs. Generic DevSecOps templates
catch some of this — but not the most dangerous one.

The headline failure is **slopsquatting**. AI models confidently invent plausible package
names that don't exist. An attacker pre-registers the invented name on PyPI/npm and uploads
malware. The next `pip install` silently pulls it in. This pipeline's anti-slopsquatting
guard resolves every imported package against its registry and hard-blocks anything that
doesn't exist — the layer no other tool ships.

## Install

<details open>
<summary><b>Option A — one command (npx)</b></summary>

```bash
npx secure-ai-pipeline@latest init
```

Drops the CI workflow, the anti-slopsquatting guard, the custom SAST rules, and the
pre-commit hooks into your repo. Idempotent — safe to re-run.
</details>

<details>
<summary><b>Option B — GitHub template (one click)</b></summary>

Click **Use this template** on the repo page. A setup workflow personalises the README,
opens a "what to do next" issue, and the pipeline is live on your first push.
</details>

<details>
<summary><b>Option C — GitHub Action (4 lines)</b></summary>

```yaml
- uses: AvinashNutalapati/secure-ai-pipeline@v1
  with:
    staging-url: ${{ vars.STAGING_URL }}   # optional, enables DAST
```
</details>

## What gets caught

| # | Flaw | Caught by | Action |
|---|------|-----------|--------|
| F1 | Hallucinated package import (doesn't exist on PyPI/npm) | `check_packages.py` (Stage 0) | Hard block |
| F2 | Hardcoded API key / secret | Gitleaks (Stage 0) | Hard block |
| F3 | SQL injection via f-string | Semgrep `sql-injection-fstring` (Stage 1) | Block |
| F4 | `app.run(debug=True)` | Semgrep `flask-debug-true` (Stage 1) | Block |
| F5 | Wildcard CORS (`origins="*"`) | Semgrep `wildcard-cors` (Stage 1) | Warn |
| F6 | TLS `verify=False` | Semgrep `tls-verify-false` (Stage 1) | Block |
| F7 | `subprocess(..., shell=True)` | Semgrep `subprocess-shell-true` (Stage 1) | Block |
| F8 | Known-CVE dependency (e.g. Flask 1.0) | Trivy SCA (Stage 1) | Block |

See [`demo/DEMO.md`](demo/DEMO.md) for a deliberately-vulnerable app that trips every gate.

## IDE & AI integrations

- **VS Code / Cursor** — inline diagnostics + quick fixes as you save.
  Install: search **"Secure AI Pipeline"** in the Extensions panel. ([details](extensions/vscode/README.md))
- **Claude Code (MCP)** — scan packages and code mid-session:
  `claude mcp add secure-ai-pipeline -- uvicorn extensions.claude_mcp.server:app --port 8765` ([details](extensions/claude_mcp/README.md))
- **OpenAI Custom GPT** — paste [`extensions/openai-gpt/openapi.yaml`](extensions/openai-gpt/openapi.yaml)
  as an Action and the [instructions](extensions/openai-gpt/GPT_INSTRUCTIONS.md) as the system prompt.

## Gate architecture

```
Stage 0 ──► secrets-scan    ← Gitleaks (HARD BLOCK on any leak)
         ──► package-check  ← check_packages.py (HARD BLOCK on hallucinated deps)
                  │
                  ▼  (only if Stage 0 passes)
Stage 1 ──► sast            ← Semgrep + AI insecure-defaults ruleset (BLOCK on high-confidence)
         ──► sca-iac        ← Trivy (BLOCK on fixable Critical/High CVEs)
                  │
                  ▼  (only if Stage 1 passes)
Stage 2 ──► dast            ← ZAP baseline against STAGING_URL (report only, never blocks)
```

## Contributing

Issues and PRs welcome — see the [issue tracker](https://github.com/AvinashNutalapati/secure-ai-pipeline/issues).
Run the test suite with `python -m pytest tests/ -v` before opening a PR.

## License

[MIT](LICENSE)
