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
        # Deterministic single-token autofix (applied only by `scan_all --fix` to
        # lines the rule already flags; comments/suppressed lines are skipped).
        "autofix": {"find": r"\bverify\s*=\s*False\b", "repl": "verify=True"},
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
        "autofix": {"find": r"\bdebug\s*=\s*True\b", "repl": "debug=False"},
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
        # No leading \b: it sits between '_' and the keyword in UPPER_SNAKE names
        # (OPENAI_API_KEY, DB_PASSWORD, AWS_SECRET) and would never match them.
        # Matching the keyword anywhere in the identifier mirrors the Semgrep
        # metavariable-regex above, which has no boundary either.
        "js": {"trigger": r"(api_key|secret|password|passwd|token|auth_key|access_key)\s*=\s*[\"'][^\"']{8,}[\"']",
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
    {
        # OWASP LLM02 (insecure output handling): model output is untrusted input.
        # AI-written code frequently pipes a completion straight into a sink.
        "id": "llm-output-to-sink",
        "severity": "ERROR",
        "cwe": "CWE-94: Improper Control of Generation of Code",
        "message": "LLM output flows into a code/command execution sink (eval/exec/shell) — model output is untrusted; never execute it.",
        "fix": "Never pass model output to eval/exec/os.system/subprocess; parse and validate it, or use a safe interpreter.",
        "languages": ["python", "javascript"],
        "py": r"(?i)(?:eval|exec|os\.system|subprocess\.\w+)\s*\([^)]*(?:completion|chat_response|llm_output|llm_response|ai_response|\.content|choices\[0\]|output_text)",
        "semgrep": [
            "eval(<... $X.choices[0].message.content ...>)",
            "exec(<... $X.choices[0].message.content ...>)",
            "eval(<... $X.output_text ...>)",
            "exec(<... $X.output_text ...>)",
            "os.system(<... $X.choices[0].message.content ...>)",
            "subprocess.$F(<... $X.choices[0].message.content ...>, ...)",
        ],
        "js": {"trigger": r"(eval|exec|child_process\.\w+)\s*\([^)]*(completion|llm_response|\.content|choices\[0\]|output_text)",
               "target": None, "flags": "i"},
    },
    {
        "id": "jwt-verify-disabled",
        "severity": "ERROR",
        "cwe": "CWE-347: Improper Verification of Cryptographic Signature",
        "message": "JWT signature verification disabled — tokens can be forged. Verify the signature and pin the algorithm (never 'none').",
        "fix": "Remove verify=False / verify_signature:false; set algorithms=['RS256'] and verify the signature.",
        "languages": ["python", "javascript"],
        "py": r"jwt\.decode\s*\([^)]*verify\s*=\s*False|verify_signature[\x22\x27]?\s*:\s*False|algorithms\s*=\s*\[\s*[\x22\x27]none",
        "semgrep": [
            "jwt.decode(..., verify=False, ...)",
            'jwt.decode(..., options={..., "verify_signature": False}, ...)',
        ],
        "js": {"trigger": r"verify_signature[\x22\x27]?\s*[:=]\s*false|algorithms?\s*[:=]\s*\[\s*[\x22\x27]none",
               "target": None, "flags": "i"},
    },
    {
        # AI models reach for md5/sha1 by habit. WARNING (not block): these are
        # legitimate for non-security checksums, so flag-don't-fail.
        "id": "weak-hash",
        "severity": "WARNING",
        "cwe": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
        "message": "MD5/SHA-1 are broken for security use (collisions). Use SHA-256+ for integrity/signatures; only keep MD5/SHA-1 for non-security checksums.",
        "fix": "Use hashlib.sha256 (or bcrypt/argon2 for passwords); reserve MD5/SHA-1 for non-security checksums only.",
        "languages": ["python", "javascript"],
        "py": r"hashlib\.(?:md5|sha1)\s*\(",
        "semgrep": ["hashlib.md5(...)", "hashlib.sha1(...)"],
        "js": {"trigger": r"createHash\s*\(\s*[\x22\x27](?:md5|sha1)[\x22\x27]",
               "target": None, "flags": "i"},
    },
    {
        "id": "insecure-deserialization",
        "severity": "ERROR",
        "cwe": "CWE-502: Deserialization of Untrusted Data",
        "message": "Unsafe deserialization (pickle / yaml.load without SafeLoader) executes arbitrary code on untrusted input.",
        "fix": "Use json, or yaml.safe_load / Loader=yaml.SafeLoader; never pickle.load untrusted data.",
        "languages": ["python"],
        "py": r"\bpickle\.loads?\s*\(|\byaml\.load\s*\((?![^)\n]*Safe(?:C)?Loader)",
        "semgrep": [
            "pickle.loads(...)",
            "pickle.load(...)",
            "yaml.load($DATA)",
            "yaml.load(..., Loader=yaml.Loader)",
        ],
        "js": {"trigger": r"\b(?:pickle\.loads?|yaml\.load)\s*\(",
               "target": None, "flags": ""},
    },
    {
        "id": "insecure-random-token",
        "severity": "WARNING",
        "cwe": "CWE-330: Use of Insufficiently Random Values",
        "message": "The `random` module is not cryptographically secure. Use `secrets` (Python) / crypto.randomBytes (Node) to mint tokens, keys, OTPs, salts.",
        "fix": "Use secrets.token_urlsafe()/secrets.choice() (Python) or crypto.randomBytes (Node) for security values.",
        "languages": ["python"],
        "py": r"(?i)(?:token|secret|password|api[_ ]?key|otp|nonce|salt|session)\b[^\n]{0,40}\brandom\.(?:random|randint|randrange|choice|getrandbits|sample)\b|\brandom\.(?:random|randint|randrange|choice|getrandbits|sample)\b[^\n]{0,40}(?:token|secret|password|api[_ ]?key|otp|nonce|salt|session)",
        # semgrep_raw (not a bare random.* pattern, which would flag ALL random use):
        # only random.* assigned to a security-named variable.
        "semgrep_raw": (
            "    patterns:\n"
            "      - pattern: $X = random.$F(...)\n"
            "      - metavariable-regex:\n"
            "          metavariable: $X\n"
            "          regex: (?i)(token|secret|password|api_?key|otp|nonce|salt|session)\n"
        ),
        "js": {"trigger": r"(?:token|secret|password|otp|nonce|salt)[^\n]{0,40}Math\.random\s*\(|Math\.random\s*\([^\n]{0,40}(?:token|secret|password|otp|nonce|salt)",
               "target": None, "flags": "i"},
    },
    {
        "id": "bind-all-interfaces",
        "severity": "WARNING",
        "cwe": "CWE-605: Multiple Binds to the Same Port / Exposure on All Interfaces",
        "message": "Binding to 0.0.0.0 exposes the service on every network interface. Bind to 127.0.0.1 unless external exposure is intended.",
        "fix": "Bind to 127.0.0.1 (or a specific interface); only use 0.0.0.0 when external access is required and firewalled.",
        "autofix": {"find": r"([\x22\x27])0\.0\.0\.0\1", "repl": r"\g<1>127.0.0.1\g<1>"},
        "languages": ["python"],
        "py": r"(?:host\s*=\s*|\.run\s*\(\s*|bind\s*\(\s*\(?\s*)[\x22\x27]0\.0\.0\.0[\x22\x27]",
        "semgrep": ["$APP.run(host='0.0.0.0', ...)", "$APP.run('0.0.0.0', ...)"],
        "js": {"trigger": r"[\x22\x27]0\.0\.0\.0[\x22\x27]",
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
