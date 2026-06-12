"""
SAST rules for AI-insecure defaults — the single source for the regex-based
static checks. Edit a rule here and it propagates to every Python channel that
applies them: the local runner (run_pipeline.py → npx scan), and (mirrored) the
MCP server. The Semgrep YAML and the VS Code extension are generated from this
list by scripts/gen_rules.py.

Each rule: (rule_id, severity, action, compiled_pattern, message).
  severity = ERROR | WARNING        action = BLOCK | WARN

stdlib only.
"""

import re

SAST_REGEX_RULES = [
    ("flask-debug-true", "ERROR", "BLOCK",
     re.compile(r'app\.run\s*\(.*debug\s*=\s*True'),
     "Flask debug=True exposes interactive debugger — allows arbitrary code execution in browser."),
    ("tls-verify-false", "ERROR", "BLOCK",
     re.compile(r'requests\.\w+\s*\(.*verify\s*=\s*False'),
     "TLS certificate verification disabled (verify=False). Allows MITM attacks."),
    ("wildcard-cors", "WARNING", "WARN",
     re.compile(r'origins\s*=\s*["\']\*["\']|Access-Control-Allow-Origin.*\*'),  # nosemgrep: rule definition, not a CORS misconfig
     "Wildcard CORS — any origin can make credentialed requests to this API."),
    ("subprocess-shell-true", "ERROR", "BLOCK",
     re.compile(r'subprocess\.\w+\s*\(.*shell\s*=\s*True'),
     "subprocess shell=True with user input → command injection."),
    ("sql-injection-fstring", "ERROR", "BLOCK",
     # The %/+/.format branches require the operator AFTER the closing quote so
     # the safe parameterised form execute("… %s", (val,)) never matches.
     re.compile(r'\.execute\s*\(\s*f["\']'
                r'|\.execute\s*\(\s*["\'][^"\']*["\']\s*(?:%|\+|\.\s*format\s*\()'),
     "SQL query built via f-string/concatenation — parameterise with cursor.execute(sql,(val,))."),
    ("eval-user-input", "ERROR", "BLOCK",
     re.compile(r'eval\s*\(\s*request\.|exec\s*\(\s*request\.'),
     "eval/exec on request data → arbitrary code execution."),
]
