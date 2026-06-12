"""
secure-ai-pipeline:rule-source — excluded from the built-in scan (the pattern
strings below look like insecure code but are rule definitions).

Canonical SAST rule catalog — the single source for the AI-insecure-default
checks across every channel.

Each rule carries every representation it needs, because the three engines speak
different pattern languages and can't be derived from each other:
  - ``py``      Python ``re`` source — applied by run_pipeline.py (→ npx scan)
  - ``semgrep`` Semgrep AST patterns — the real CI SAST
  - ``js``      VS Code RegExp sources — the in-editor extension
plus the shared metadata (id, severity, message, fix, cwe, languages).

Edit a rule HERE, then run ``python scripts/gen_rules.py`` to regenerate the
Semgrep ruleset (.semgrep/ai-insecure-defaults.yml) and the VS Code rule table
(extensions/vscode/src/rules.generated.ts). The MCP server + run_pipeline import
the Python forms directly; tests/test_rule_parity.py fails if anything drifts.

stdlib only.
"""

import re

# severity: ERROR | WARNING   (run_pipeline action: ERROR→BLOCK, WARNING→WARN)
RULES = [
    {
        "id": "tls-verify-false",
        "severity": "ERROR",
        "cwe": "CWE-295: Improper Certificate Validation",
        "message": "TLS certificate verification disabled (verify=False) — allows man-in-the-middle attacks.",
        "fix": "Remove verify=False (the default is verify=True).",
        "languages": ["python"],
        "py": r'requests\.\w+\s*\(.*verify\s*=\s*False',
        "semgrep": ["requests.$METHOD(..., verify=False, ...)"],
        "js": {"trigger": r"requests\.\w+\s*\([^)]*\bverify\s*=\s*False\b",
               "target": r"\bverify\s*=\s*False\b", "flags": ""},
    },
    {
        "id": "flask-debug-true",
        "severity": "ERROR",
        "cwe": "CWE-94: Improper Control of Generation of Code",
        "message": "Flask debug=True exposes an interactive debugger that allows arbitrary code execution.",
        "fix": 'debug=os.getenv("FLASK_DEBUG", "false") == "true"',
        "languages": ["python"],
        "py": r'app\.run\s*\(.*debug\s*=\s*True',
        "semgrep": ["app.run(..., debug=True, ...)"],
        "js": {"trigger": r"app\.run\s*\([^)]*\bdebug\s*=\s*True\b",
               "target": r"\bdebug\s*=\s*True\b", "flags": ""},
    },
    {
        "id": "wildcard-cors",
        "severity": "WARNING",
        "cwe": "CWE-942: Permissive Cross-domain Policy with Untrusted Domains",
        "message": 'Wildcard CORS (origins="*") lets any website make credentialed requests. Restrict to trusted origins.',
        "fix": 'Restrict to explicit origins, e.g. origins=["https://yourapp.example.com"].',
        "languages": ["python", "javascript"],
        "py": r'origins\s*=\s*["\']\*["\']|Access-Control-Allow-Origin.*\*',  # nosemgrep: rule definition, not a CORS misconfig
        "semgrep": ['CORS($APP, resources={r"/*": {"origins": "*"}})',
                    'CORS($APP, origins="*")',
                    'response.headers["Access-Control-Allow-Origin"] = "*"'],
        "js": {"trigger": r"origins\s*=\s*[\"']\*[\"']|Access-Control-Allow-Origin[\"']?\s*[:=]\s*[\"']\*[\"']",  # nosemgrep: rule definition
               "target": r"[\"']\*[\"']", "flags": ""},
    },
    {
        "id": "subprocess-shell-true",
        "severity": "ERROR",
        "cwe": "CWE-78: OS Command Injection",
        "message": "subprocess with shell=True and user input enables command injection. Pass an argument list instead.",
        "fix": 'Pass an argument list and drop shell=True: subprocess.run(["ping", "-c", "1", host]).',
        "languages": ["python"],
        "py": r'subprocess\.\w+\s*\(.*shell\s*=\s*True',
        "semgrep": ["subprocess.$FUNC(..., shell=True, ...)"],
        "js": {"trigger": r"subprocess\.\w+\s*\([^)]*\bshell\s*=\s*True\b",
               "target": r"\bshell\s*=\s*True\b", "flags": ""},
    },
    {
        "id": "sql-injection-fstring",
        "severity": "ERROR",
        "cwe": "CWE-89: Improper Neutralization of Special Elements in SQL Command",
        "message": "SQL query built from an f-string or concatenation — use parameterised queries (execute(sql, (param,))).",
        "fix": 'Use parameters: cursor.execute("SELECT * FROM t WHERE x=?", (val,)).',
        "languages": ["python"],
        # The %/+/.format branches require the operator AFTER the closing quote so
        # the safe parameterised form execute("… %s", (val,)) never matches.
        "py": (r'\.execute\s*\(\s*f["\']'
               r'|\.execute\s*\(\s*["\'][^"\']*["\']\s*(?:%|\+|\.\s*format\s*\()'),
        "semgrep": ['$CURSOR.execute(f"...{$VAR}...")',
                    '$CURSOR.execute("..." % $VAR)',
                    '$CURSOR.execute("..." % (...))',
                    '$CURSOR.execute("..." + $VAR)',
                    '$CURSOR.execute("..." + $VAR + "...")',
                    '$CURSOR.execute("...".format(...))'],
        "js": {"trigger": (r"\.execute\s*\(\s*f[\"']"
                           r"|\.execute\s*\(\s*[\"'][^\"']*[\"']\s*%\s*\w"
                           r"|\.execute\s*\(\s*[\"'][^\"']*[\"']\s*\+\s*\w"),
               "target": None, "flags": ""},
    },
    {
        "id": "hardcoded-api-key",
        "severity": "ERROR",
        "cwe": "CWE-798: Use of Hard-coded Credentials",
        "message": "Hardcoded credential in source. Load it from the environment (os.environ[...]) or a secrets manager.",
        "fix": 'Load from the environment: os.environ["API_KEY"].',
        "languages": ["python", "javascript"],
        # run_pipeline detects this as a SECRET (secrets/code_secrets.py), not via
        # the SAST regex set — so no `py` here. Semgrep needs metavariable-regex.
        "py": None,
        "semgrep_raw": (
            "    patterns:\n"
            "      - pattern-either:\n"
            "          - pattern: $KEY = \"...\"\n"
            "          - pattern: $KEY = '...'\n"
            "      - metavariable-regex:\n"
            "          metavariable: $KEY\n"
            "          regex: (?i)(api_key|secret|password|token|passwd|auth_key|access_key)\n"
        ),
        "js": {"trigger": r"\b(api_key|secret|password|passwd|token|auth_key|access_key)\s*=\s*[\"'][^\"']{8,}[\"']",
               "target": r"[\"'][^\"']{8,}[\"']", "flags": "i"},
    },
    {
        "id": "eval-user-input",
        "severity": "ERROR",
        "cwe": "CWE-94: Code Injection",
        "message": "eval/exec on request data allows arbitrary code execution. Remove it or use a safe parser.",
        "fix": "Remove eval/exec or replace with a safe parser.",
        "languages": ["python"],
        "py": r'eval\s*\(\s*request\.|exec\s*\(\s*request\.',
        "semgrep": ["eval(request.$METHOD(...))", "exec(request.$METHOD(...))"],
        "js": {"trigger": r"\b(?:eval|exec)\s*\(\s*request\.",
               "target": None, "flags": ""},
    },
]

# Derived: the (id, severity, action, compiled_regex, message) tuples the local
# runner (run_pipeline.py → npx scan) applies. Only rules with a Python regex.
SAST_REGEX_RULES = [
    (r["id"], r["severity"], "BLOCK" if r["severity"] == "ERROR" else "WARN",
     re.compile(r["py"]), r["message"])
    for r in RULES if r.get("py")
]
