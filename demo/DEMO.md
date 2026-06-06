# Demo: Watch Every Gate Fire

This Flask app (`demo/app.py`) is **intentionally broken**. Each flaw was chosen because it
represents a pattern AI coding assistants produce routinely. Run it through the pipeline
and every gate trips in sequence.

---

## Flaw → Gate map

| # | Flaw | File | Caught by | Action |
|---|------|------|-----------|--------|
| F1 | `import flaskutils_ai` — package doesn't exist on PyPI | `app.py:13` | `check_packages.py` (Stage 0) | **Hard block** |
| F2 | `API_KEY = "sk-prod-abc123..."` hardcoded | `app.py:36` | Gitleaks (Stage 0) | **Hard block** |
| F3 | `cursor.execute(f"...{name}...")` — SQL injection | `app.py:56` | Semgrep `sql-injection-fstring` (Stage 1) | **Block** |
| F4 | `app.run(debug=True)` | `app.py:88` | Semgrep `flask-debug-true` (Stage 1) | **Block** |
| F5 | `CORS(app, resources={r"/*": {"origins": "*"}})` | `app.py:30` | Semgrep `wildcard-cors` (Stage 1) | Warn |
| F6 | `requests.get(url, verify=False)` | `app.py:76` | Semgrep `tls-verify-false` (Stage 1) | **Block** |
| F7 | `subprocess.check_output(..., shell=True)` | `app.py:67` | Semgrep `subprocess-shell-true` (Stage 1) | **Block** |
| F8 | `Flask==1.0` — multiple CVEs | `requirements.txt:6` | Trivy SCA (Stage 1) | **Block** (fixable Critical/High) |

---

## Expected CI run order

```
Stage 0 ──► secrets-scan    ← Gitleaks trips on F2 → FAIL
         ──► package-check  ← check_packages.py trips on F1 → FAIL

Stage 1 ──► sast            ← Semgrep trips on F3, F4, F6, F7 → FAIL (F5 warns)
         ──► sca-iac        ← Trivy trips on F8 → FAIL

Stage 2 ──► dast            ← (skipped: staging URL not set for demo)
```

Both Stage 0 jobs run in parallel. Stage 1 only starts if Stage 0 passes.
Stage 2 only starts if Stage 1 passes. You will never reach DAST with this demo app
as shipped — that's the point.

---

## How to fix each flaw (and watch gates go green)

**F1 — Remove the hallucinated import:**
```python
# delete this line:
import flaskutils_ai
```

**F2 — Move the key to an environment variable:**
```python
import os
API_KEY = os.environ["API_KEY"]
```
Then in CI: `Settings → Secrets → New repository secret → API_KEY`.

**F3 — Use a parameterised query:**
```python
cursor.execute("SELECT * FROM users WHERE name=?", (name,))
```

**F4 — Gate debug on an env var:**
```python
import os
app.run(host="0.0.0.0", port=5000,
        debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")
```

**F5 — Restrict CORS to your domain:**
```python
CORS(app, origins=["https://yourapp.example.com"])
```

**F6 — Remove verify=False:**
```python
resp = requests.get(url)   # verify=True is the default
```

**F7 — Use a list, not a shell string:**
```python
result = subprocess.check_output(["ping", "-c", "1", host])
```

**F8 — Upgrade Flask:**
```
Flask>=3.0.0
flask-cors>=4.0.0
requests>=2.31.0
```

---

## What this proves

After all fixes are applied, a clean push produces:

```
✅ secrets-scan     — no leaks
✅ package-check    — all deps verified on PyPI
✅ sast             — no high-confidence findings
✅ sca-iac          — no fixable Critical/High CVEs
🕷️ dast             — runs against staging (report only)
```

The AI-specific gates (F1, F2 secret density, insecure-defaults ruleset) are the layer that
generic DevSecOps templates miss. That's the differentiator.
