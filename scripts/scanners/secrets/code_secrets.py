"""
secure-ai-pipeline:rule-source — excluded from the built-in scan.

Hardcoded-secret patterns for scanning SOURCE CODE — the regex set the local
pipeline + scan_all's built-in secrets fallback apply line by line. Distinct
from config_secrets.py (which scans .env / mcp.json / Claude config) and from
the high-confidence provider patterns in scanners.base.SECRET_VALUE_PATTERNS.

Edit the patterns / placeholder shapes here to improve code-secret detection
everywhere it's used.

stdlib only.
"""

import re

SECRET_PATTERNS = [
    # (rule_id, regex, description)
    ("hardcoded-api-key",
     re.compile(r'(?i)(api_key|secret|password|token|passwd|auth_key|access_key)\s*=\s*["\']([A-Za-z0-9\-_]{8,})["\']'),
     "Hardcoded credential assigned to variable"),
    ("aws-key",
     re.compile(r'AKIA[0-9A-Z]{16}'),
     "AWS Access Key ID pattern"),
    ("generic-secret-str",
     re.compile(r'["\']([A-Za-z0-9+/]{40,})["\']'),
     "Long high-entropy string — possible hardcoded secret"),
    ("private-key-header",
     re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'),
     "Private key block in source"),
]

# A value is a placeholder only when the WHOLE value matches one of these
# shapes. Substring checks are dangerous: a real key that merely contains
# "example" (e.g. examplecorp_prod_8f3a…) must still block.
PLACEHOLDER_VALUE = re.compile(
    r"^(?:x{4,}|\*{3,}|\.{3,}|<[^<>]{0,60}>"
    r"|changeme|change[-_]me|placeholder|dummy|redacted|todo|tbd|none|null"
    r"|example(?:[-_](?:api[-_]?key|key|token|secret|value|password))?"
    r"|sample(?:[-_](?:api[-_]?key|key|token|secret|value))?"
    r"|your[-_][a-z_-]{0,40})$",
    re.IGNORECASE,
)


def is_placeholder(value: str) -> bool:
    v = value.strip().strip("'\"")
    return bool(PLACEHOLDER_VALUE.match(v))
