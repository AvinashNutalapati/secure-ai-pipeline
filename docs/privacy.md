# Privacy — what leaves your machine

"Uses my API key" is **not** the same as "my code never leaves." Know where your
prompts and code go.

## This project

| Component | Sends code off your machine? |
|---|---|
| `scan` CLI / local scanners | **No.** Runs locally. The only network calls are package-existence lookups to PyPI/npm (package **names**, not your code) — disable with `--offline`. |
| VS Code / Cursor extension | **No.** Local regex diagnostics only. |
| CI pipeline (Semgrep/Trivy/Gitleaks) | Runs in **your** CI runner. |
| Claude MCP server (`mcp_server.py`) | Local stdio; code stays on your machine. |
| OpenAI GPT Action (`server.py`) | **Yes** — snippets are sent to whatever host you deploy. Don't use a shared/demo endpoint for proprietary code; add auth. See [extensions/openai-gpt/DEPLOY.md](../extensions/openai-gpt/DEPLOY.md). |

## AI coding assistants (verify current vendor docs)

- **Cursor**: requests traverse Cursor's backend even with your own API key. Privacy
  Mode enables zero-data-retention with providers; with it off, codebase data,
  prompts, and editor actions may be stored.
- **GitHub Copilot**: prompts/metadata go to the relevant hosting clouds/providers
  depending on plan and feature; enterprise offers stronger retention controls.
- **Anthropic**: retention varies by product and opt-in settings.

## Practical guidance

- Turn on privacy / zero-retention modes by default.
- Never put secrets, customer data, or internal endpoints in prompts or rules files.
- Keep secrets out of `mcp.json`/agent configs (`scan` flags `mcp-secret-env`).
- Treat the OpenAI GPT Action host as a data-processing boundary: authenticate it,
  rate-limit it, and document retention before sending real code.
