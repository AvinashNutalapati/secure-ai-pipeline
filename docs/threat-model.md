# Threat model — the AI-assisted developer attack surface

The core problem in AI-assisted development is **ambient authority**: untrusted text
from repos, issues, docs, web pages, MCP servers, and extensions can influence an
agent that has access to code, terminals, files, secrets, and deploy paths. The
seam between the assistant, the laptop, the repo, the MCP/plugin ecosystem, and the
pipeline is where mainstream AppSec and cloud tools are weakest — and what this
project defends.

## Threats we map to (OWASP LLM Top 10 / MITRE ATLAS)

| Threat | Example | What we scan | Severity |
|---|---|---|---|
| Indirect prompt injection / context poisoning | A poisoned issue or rules file steers the agent (RoguePilot, 2026) | `ai_ide` — risky directives in `.cursorrules`/Cline/Windsurf/Copilot rules | HIGH–CRITICAL |
| Excessive agency / blast radius | Agent can read `~/`, run any shell, fetch any URL | `claude` — broad permissions, bypass mode | HIGH–CRITICAL |
| Malicious / over-scoped MCP server | Server gets `GITHUB_TOKEN`, mounts `/`, runs `curl\|bash`, unauth remote | `mcp` | HIGH–CRITICAL |
| Supply-chain via CI | Compromised action tag (tj-actions, 2025); `pull_request_target` with secrets | `github_actions` | MEDIUM–CRITICAL |
| Package hallucination / slopsquatting | AI invents a package; attacker pre-registers it | `packages` (anti-slopsquatting guard) | CRITICAL |
| Secret/code leakage to providers | Privacy mode off; secrets in prompts/configs | Gitleaks (CI), [privacy guidance](privacy.md) | HIGH |

## Assumptions

- All repo/issue/PR/rules text is **untrusted input** to the coding agent.
- MCP servers and IDE extensions are **privileged code** — treat them like prod integrations.
- Every package suggestion must be verified against a real registry.
- The laptop is now a production attack surface.

## What this project does and does not cover

Covers: AI-workflow posture (the scanners above), code SAST/SCA, secrets in code/history.
Out of scope (use the [tiered stack](../deep-research-report.md)): identity/SSO, managed
secrets, endpoint MDM, runtime detection, cloud posture, GRC automation.
