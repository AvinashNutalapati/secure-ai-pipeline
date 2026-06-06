# Secure AI Pipeline

![Security Pipeline](https://github.com/AvinashNutalapati/REPO_NAME/actions/workflows/security.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)

A drop-in security pipeline for code written with AI assistants (Cursor, Copilot, Claude Code).
It intercepts the failure modes those tools produce — hallucinated package names
(slopsquatting), hardcoded secrets, insecure defaults, and CVE-laden pinned dependencies —
before they reach production. The anti-slopsquatting guard is the differentiator: no generic
DevSecOps template catches AI-invented package names, and this one does.

## 60-second quickstart

1. You're already done — this repo was created from the template, so the pipeline is wired.
   The `Security Pipeline` workflow runs on every push and pull request.
2. *(Optional, enables DAST)* Set `STAGING_URL` in **Settings → Secrets and variables →
   Actions → Variables**.
3. *(Optional, local hooks)* `pip install pre-commit && pre-commit install`.
4. Push a commit and watch the pipeline run under the **Actions** tab.

## Use the marketplace Action in any other repo

```yaml
- uses: AvinashNutalapati/secure-ai-pipeline@v1
```

## What gets scanned

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

## License

[MIT](LICENSE)
