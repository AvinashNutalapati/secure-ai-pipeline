# Vulnerable AI workflow (demo fixture)

A deliberately unsafe repo that exercises every V2 AI-posture scanner. Use it to
see the **AI Agent Blast Radius Score** in action:

```bash
python scripts/blast_radius.py examples/vulnerable-ai-workflow --offline
# or, with package hallucination checks (needs network):
python scripts/blast_radius.py examples/vulnerable-ai-workflow
```

What each file trips:

| File | Scanner | Findings |
|------|---------|----------|
| `.cursorrules` | AI IDE rules | auto-run, skip-confirmation, curl\|bash, prompt-injection override |
| `.claude/settings.json` | Claude permissions | home-dir read, wildcard Bash, `rm -rf`, broad WebFetch, bypass mode |
| `mcp.json` | MCP | `GITHUB_TOKEN` to a server, `bash` startup, `/` filesystem mount, unauth `http` remote |
| `.github/workflows/deploy.yml` | GitHub Actions | `pull_request_target`, unpinned actions, `github.event` script injection |
| `app.py` | Dependency trust | hallucinated import `flaskutils_ai` |

Nothing here should ever ship. It exists only to demo detection.
