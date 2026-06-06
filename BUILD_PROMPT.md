# Claude Code Build Prompt — Secure AI Pipeline

> Paste everything below this line into Claude Code to start the production build.

---

You are building **Secure AI Pipeline** — a production-ready security product for developers
who build apps with AI coding assistants (Cursor, Copilot, Claude Code). The repo already
contains a working scaffold. Your job is to turn it into a shippable product.

Read CLAUDE.md first. It documents every file already built and every decision already made.
Do not recreate anything listed there.

## Step 0 — One question, then proceed

Ask the user exactly this, once, before doing anything else:

> "What is your GitHub username? (I need this to personalise the Action, template repo URLs,
> and README badges. That's the only thing I need from you — I'll handle everything else.)"

Store the answer as GITHUB_USER. Do not ask for anything else during this session.

---

## Phase 1 — Versioning foundation

Create these files in the repo root. Use GITHUB_USER where indicated.

**`package.json`**
```json
{
  "name": "secure-ai-pipeline",
  "version": "1.0.0",
  "description": "Production-ready security pipeline for AI-generated code",
  "bin": { "secure-ai-pipeline": "./cli/init.js" },
  "files": ["cli/", "scripts/", ".semgrep/", ".zap/", ".pre-commit-config.yaml", "action.yml"],
  "keywords": ["security", "ai", "devsecops", "sast", "sca", "slopsquatting"],
  "author": "GITHUB_USER",
  "license": "MIT",
  "repository": {
    "type": "git",
    "url": "https://github.com/GITHUB_USER/secure-ai-pipeline.git"
  },
  "engines": { "node": ">=18" }
}
```

**`setup.py`** — for the Python package (MCP server distribution)
```python
from setuptools import setup, find_packages
setup(
    name="secure-ai-pipeline",
    version="1.0.0",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=["fastapi>=0.110", "uvicorn>=0.29", "requests>=2.31"],
    entry_points={"console_scripts": ["sap-mcp=extensions.claude_mcp.server:main"]},
)
```

---

## Phase 2 — One-line installer (npx / Option 1)

Create `cli/init.js` — a Node.js CLI script runnable via `npx secure-ai-pipeline@latest init`.

### What it must do (in order, automatically):

1. Detect the project type — look for `requirements.txt`, `package.json`, `Pipfile`, `pyproject.toml`
   and set LANG to `python`, `node`, or `both`.

2. Copy the following files into the user's repo root, skipping any that already exist:
   - `.github/workflows/security.yml`
   - `scripts/check_packages.py`
   - `scripts/run_pipeline.py`
   - `.semgrep/ai-insecure-defaults.yml`
   - `.zap/rules.tsv`
   - `.pre-commit-config.yaml`

3. Append a `.gitignore` entry for `pipeline-results.json` if not already present.

4. Check if `pre-commit` is installed (`pre-commit --version`). If not, print a one-line
   instruction: `pip install pre-commit && pre-commit install`.
   If yes, run `pre-commit install` automatically.

5. Print a success summary:
   ```
   ✅ Secure AI Pipeline installed.

   What just happened:
     • .github/workflows/security.yml  — CI pipeline wired (runs on every push/PR)
     • scripts/check_packages.py       — anti-slopsquatting guard
     • .semgrep/ai-insecure-defaults.yml — 7 custom SAST rules for AI code
     • .pre-commit-config.yaml         — local hooks active

   One optional step:
     Set STAGING_URL in GitHub → Settings → Variables → Actions
     to enable DAST scanning against your staging environment.

   That's it. Push a commit to see the pipeline run.
   ```

6. Exit 0. Do not open a browser, do not ask follow-up questions, do not require network access.

### Requirements for the CLI:
- Zero npm dependencies — use only Node.js built-ins (`fs`, `path`, `child_process`, `https`)
- Idempotent — safe to run multiple times in the same repo
- Works on macOS, Linux, and Windows (use `path.join`, not string concatenation for paths)
- The files to copy are bundled inside the npm package itself (in the `files` array in package.json)

---

## Phase 3 — GitHub Action (Option 3 — marketplace publish)

Create `action.yml` in the repo root. This is the composite action developers add with one line.

```yaml
name: Secure AI Pipeline
description: Security pipeline for AI-generated code — catches slopsquatting, secrets, CVEs, and insecure defaults.
author: GITHUB_USER

branding:
  icon: shield
  color: red

inputs:
  staging-url:
    description: URL of your staging environment for DAST scanning. Leave empty to skip DAST.
    required: false
    default: ""
  python-version:
    description: Python version for running scripts.
    required: false
    default: "3.12"
  fail-on-warnings:
    description: Treat WARN-level findings as blocking failures.
    required: false
    default: "false"

runs:
  using: composite
  steps:
    - name: Set up Python
      uses: actions/setup-python@v5
      with:
        python-version: ${{ inputs.python-version }}

    - name: Install dependencies
      shell: bash
      run: pip install requests --quiet

    - name: Stage 0 — Package existence check (anti-slopsquatting)
      shell: bash
      run: python ${{ github.action_path }}/scripts/check_packages.py

    - name: Stage 0 — Secret scan (Gitleaks)
      uses: gitleaks/gitleaks-action@v2
      env:
        GITHUB_TOKEN: ${{ env.GITHUB_TOKEN }}

    - name: Stage 1 — SAST (Semgrep)
      uses: returntocorp/semgrep-action@v1
      with:
        config: >
          p/python p/javascript p/security-audit
          ${{ github.action_path }}/.semgrep/ai-insecure-defaults.yml
        generateSarif: "1"

    - name: Upload Semgrep SARIF
      if: always()
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: semgrep.sarif

    - name: Stage 1 — SCA + IaC (Trivy)
      uses: aquasecurity/trivy-action@0.20.0
      with:
        scan-type: fs
        format: sarif
        output: trivy.sarif
        severity: CRITICAL,HIGH
        exit-code: "1"
        ignore-unfixed: true

    - name: Upload Trivy SARIF
      if: always()
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: trivy.sarif

    - name: Stage 2 — DAST (ZAP baseline)
      if: ${{ inputs.staging-url != '' }}
      uses: zaproxy/action-baseline@v0.12.0
      with:
        target: ${{ inputs.staging-url }}
        rules_file_name: ${{ github.action_path }}/.zap/rules.tsv
        fail_action: false
```

Also create `.github/workflows/ci.yml` — a workflow that runs on pushes to this repo itself,
running `pytest tests/` and `actionlint` against `action.yml`.

---

## Phase 4 — VS Code / Cursor Extension

Create `extensions/vscode/` with a full TypeScript VS Code extension.

### What the extension must do:

1. On every Python or JS/TS file **save**, run the security rules locally (no network, no server).
   Show violations as VS Code Diagnostics (red/yellow underlines) with the rule ID as the source.

2. Rules to implement as in-editor checks (mirror the Semgrep rules):
   - `tls-verify-false` — flag `verify=False` in requests calls
   - `flask-debug-true` — flag `debug=True` in `app.run()`
   - `wildcard-cors` — flag `origins="*"`
   - `subprocess-shell-true` — flag `shell=True`
   - `sql-injection-fstring` — flag `cursor.execute(f"...`
   - `hardcoded-api-key` — flag variables named `api_key/secret/token` assigned a string literal

3. For each diagnostic, provide a **Quick Fix** (`vscode.CodeAction`) with the correct fix:
   - `verify=False` → `verify=True` (or remove the arg)
   - `debug=True` → `debug=os.getenv("FLASK_DEBUG","false")=="true"`
   - hardcoded key → `os.environ["KEY_NAME"]`

4. Add a **status bar item** bottom-right: `$(shield) SAP: 3 issues` that opens the Problems panel on click.

5. Add a **sidebar view** (Activity Bar icon: shield) showing a tree of all findings across open files,
   grouped by rule. Clicking a finding jumps to the line.

6. Settings (`contributes.configuration`):
   - `securePipeline.enable` — toggle extension on/off (default: true)
   - `securePipeline.severity` — minimum severity to show: `"error"` | `"warning"` (default: `"warning"`)
   - `securePipeline.runOnType` — also run while typing, not just on save (default: false)

### File structure:
```
extensions/vscode/
├── package.json          (extension manifest — publisher, activationEvents, contributes)
├── tsconfig.json
├── src/
│   ├── extension.ts      (activate / deactivate)
│   ├── diagnostics.ts    (rule engine — returns Diagnostic[] for a document)
│   ├── quickfix.ts       (CodeActionProvider)
│   ├── statusbar.ts      (status bar item)
│   └── sidebar.ts        (TreeDataProvider for the findings panel)
└── README.md
```

### Key implementation notes:
- Use `vscode.languages.createDiagnosticCollection("secure-ai-pipeline")` — one collection for all rules
- Implement rules as regex against `document.getText()` with line number extraction via `document.positionAt()`
- Do NOT shell out to Python or Semgrep — all checks run in the extension process via TypeScript regex
- The extension must work offline and in Cursor (which is VS Code-compatible)
- Publisher ID in package.json: `GITHUB_USER`
- Extension ID: `GITHUB_USER.secure-ai-pipeline`

---

## Phase 5 — Claude MCP Server

Create `extensions/claude-mcp/` — a FastAPI server exposing security tools as MCP tool calls.
Claude Code can call these mid-session to check packages or scan a file before committing.

### Tools to expose:

**`check_package`**
- Input: `{ "package": "string", "registry": "pypi" | "npm" }`
- Logic: HTTP GET to `https://pypi.org/pypi/{pkg}/json` or `https://registry.npmjs.org/{pkg}`
- Output: `{ "exists": bool, "latest_version": "string" | null, "warning": "string" | null }`

**`sast_scan`**
- Input: `{ "code": "string", "language": "python" | "javascript" }`
- Logic: Run the same regex rules from `run_pipeline.py` against the code string
- Output: `{ "findings": [{ "rule": str, "line": int, "severity": str, "message": str, "fix": str }] }`

**`sca_scan`**
- Input: `{ "requirements": "string" }` — raw content of requirements.txt or package.json
- Logic: Parse deps, check each against the embedded CVE table from `run_pipeline.py`
- Output: `{ "vulnerabilities": [{ "package": str, "version": str, "cve": str, "severity": str, "fix_version": str }] }`

**`full_scan`**
- Input: `{ "code": "string", "requirements": "string", "language": "python" | "javascript" }`
- Logic: Runs check_package + sast_scan + sca_scan in sequence
- Output: Combined findings from all three tools with a `blocked: bool` top-level field

### File structure:
```
extensions/claude-mcp/
├── server.py             (FastAPI app, all 4 tool endpoints)
├── rules.py              (rule engine — shared with run_pipeline.py logic)
├── mcp_manifest.json     (MCP server manifest for Claude Code)
├── requirements.txt      (fastapi, uvicorn, requests)
└── README.md             (how to connect to Claude Code)
```

### `mcp_manifest.json` format:
```json
{
  "name": "secure-ai-pipeline",
  "version": "1.0.0",
  "description": "Security scanner for AI-generated code",
  "tools": [
    { "name": "check_package", "description": "Verify a package exists on PyPI or npm before importing it" },
    { "name": "sast_scan", "description": "Scan a code snippet for insecure patterns (injection, hardcoded secrets, etc.)" },
    { "name": "sca_scan", "description": "Check dependency versions for known CVEs" },
    { "name": "full_scan", "description": "Run all security checks on code + requirements" }
  ]
}
```

README.md must include exact steps to connect the MCP server to Claude Code:
```
claude mcp add secure-ai-pipeline -- uvicorn extensions.claude_mcp.server:app --port 8765
```

---

## Phase 6 — OpenAI GPT Action

Create `extensions/openai-gpt/` — an OpenAPI 3.1 spec for a Custom GPT that can scan code.

### Spec requirements:

- File: `extensions/openai-gpt/openapi.yaml`
- Base URL: `https://api.secure-ai-pipeline.dev` (placeholder — user replaces with their deploy URL)
- Three operations:
  - `POST /scan/packages` — body: `{ packages: string[] }` — checks each name against registries
  - `POST /scan/sast` — body: `{ code: string, language: string }` — returns SAST findings
  - `POST /scan/full` — body: `{ code: string, requirements: string }` — full scan

- Every response includes `{ findings: [...], blocked: bool, summary: string }`
  where `summary` is a human-readable sentence Claude can read directly.

- Include `x-openai-isConsequential: false` on all operations (read-only, no side effects)

Also create `extensions/openai-gpt/GPT_INSTRUCTIONS.md` — the system prompt to paste into
the Custom GPT configuration. It should instruct the GPT to:
- Proactively call `/scan/full` on any code snippet the user shares
- Explain each finding in plain English with the fix
- Never ask the user to run a separate tool — just scan automatically

---

## Phase 7 — GitHub template repository structure (Option 2)

Create `.github/TEMPLATE_README.md` — a README pre-configured for a template repo. It must contain:
- A one-paragraph description of what the pipeline does
- A "60-second quickstart" section (numbered, 4 steps max)
- Badge placeholders:
  ```
  ![Security Pipeline](https://github.com/GITHUB_USER/REPO_NAME/actions/workflows/security.yml/badge.svg)
  ```
- A link to the marketplace Action: `uses: GITHUB_USER/secure-ai-pipeline@v1`
- A "What gets scanned" table (the 8 flaw types from the demo)
- MIT license badge

Also create `.github/template-setup.yml` — a GitHub Actions workflow that fires once when
a user creates a repo from this template. It:
1. Renames all `GITHUB_USER` placeholders in README to the actual repo owner (using `${{ github.repository_owner }}`)
2. Creates an initial commit: "chore: initialise from secure-ai-pipeline template"
3. Opens a GitHub Issue titled "✅ Pipeline is live — here's what to do next" with a checklist:
   - [ ] Set `STAGING_URL` in repo Settings → Variables → Actions (enables DAST)
   - [ ] Install pre-commit locally: `pip install pre-commit && pre-commit install`
   - [ ] Push a test commit to see the pipeline run
   - [ ] (Optional) Install the VS Code extension: search "Secure AI Pipeline" in the Extensions panel

---

## Phase 8 — Tests

Create `tests/` with pytest tests for every Python script.

**`tests/test_check_packages.py`**
- Test that stdlib names (`os`, `sys`, `json`) are correctly excluded
- Test that `extract_python_imports()` correctly parses `import foo`, `from foo.bar import baz`, aliased imports
- Test that a known-good package (mock PyPI returning 200) passes
- Test that a hallucinated package (mock PyPI returning 404) fails and returns the right error message
- Use `unittest.mock.patch` to mock `urllib.request.urlopen` — no real network calls in tests

**`tests/test_run_pipeline.py`**
- Test each SAST rule fires on the matching snippet and not on a clean equivalent
- Test the requirements parser handles comments, blank lines, version specifiers correctly
- Test CVE lookup returns the right CVE IDs for Flask==1.0
- Test exit code is 1 when there are blocking findings and 0 when clean

**`tests/test_sast_rules.py`**
- One test per Semgrep rule: provide a positive example (should fire) and a negative example (should not fire)
- Rules: tls-verify-false, flask-debug-true, wildcard-cors, subprocess-shell-true, sql-injection-fstring, hardcoded-api-key

All tests must pass with `python -m pytest tests/ -v`. No external network calls. No external packages beyond `pytest`.

---

## Phase 9 — README

Overwrite `README.md` with a production README. Structure:

1. **Hero line** — one sentence: what it is and who it's for
2. **Badges** — CI status, version, license (use GITHUB_USER)
3. **The problem** — 2 short paragraphs on AI coding failure modes and slopsquatting
4. **Install** — three tabs (use HTML details/summary for tab-like UX in GitHub):
   - Option A: `npx secure-ai-pipeline@latest init` — one command
   - Option B: GitHub Template — one click
   - Option C: GitHub Action — paste 4 lines of YAML
5. **What gets caught** — the 8-flaw table from DEMO.md
6. **IDE extensions** — VS Code/Cursor, Claude Code, OpenAI GPT — each with a one-line install
7. **Gate architecture** — the 3-stage diagram as ASCII (copy from DEMO.md)
8. **Contributing** — one paragraph, link to issues

---

## Phase 10 — Final checklist (run this before declaring done)

Run each of these and confirm they pass:

```bash
# Tests
python -m pytest tests/ -v

# Actionlint (GitHub Action syntax)
actionlint action.yml

# OpenAPI lint
npx @redocly/cli lint extensions/openai-gpt/openapi.yaml

# TypeScript compile check
cd extensions/vscode && npx tsc --noEmit

# Dry-run the CLI installer against a temp directory
mkdir /tmp/test-repo && cd /tmp/test-repo && git init
node /path/to/cli/init.js
ls -la  # confirm the expected files are present
```

If any check fails, fix it before finishing. Do not mark the task done until all pass.

---

## What to tell the user when everything is built

Print this summary at the end of the session:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Secure AI Pipeline — ready to ship
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Two things you need to do once:

1. CREATE A GITHUB REPO
   Go to https://github.com/new
   Name it: secure-ai-pipeline
   Visibility: Public (required for GitHub Marketplace)
   Do NOT initialise with README (we have one)

   Then run:
     git remote add origin https://github.com/GITHUB_USER/secure-ai-pipeline.git
     git push -u origin main

2. PUBLISH THE VS CODE EXTENSION
   a. Create a publisher account: https://marketplace.visualstudio.com/manage
   b. Generate a Personal Access Token (PAT) with Marketplace scope
   c. Run: npx @vscode/vsce publish --pat YOUR_PAT

After those two steps:
  • npx secure-ai-pipeline@latest init  — works for any developer
  • uses: GITHUB_USER/secure-ai-pipeline@v1  — works in any GitHub workflow
  • Template repo: https://github.com/GITHUB_USER/secure-ai-pipeline
    (go to Settings → check "Template repository")
  • VS Code extension: searchable in the Extensions panel immediately
  • Claude Code MCP: claude mcp add secure-ai-pipeline (see extensions/claude-mcp/README.md)
  • OpenAI GPT: paste extensions/openai-gpt/openapi.yaml into a Custom GPT action
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Rules for this session

- Ask only for GitHub username. Nothing else.
- Never ask "should I proceed?" — just proceed.
- Never recreate files listed in CLAUDE.md as already built.
- When something requires a user account (VS Code Marketplace, npm publish), build the code
  fully and add the one-time human steps to the final summary — do not block on them.
- If a file is over 200 lines, write it in sections rather than one block.
- Commit message style: `feat:`, `chore:`, `fix:` prefixes.
- All code must be production quality — no TODOs, no placeholder logic, no stub functions.
