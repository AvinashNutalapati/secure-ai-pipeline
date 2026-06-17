"""
secure-ai-pipeline:rule-source — excluded from the built-in scan.

Canonical catalog of the AI-workflow POSTURE rules (the checks the SAST rule
catalog in ai_insecure_defaults.py does NOT cover). It is the single source of
truth for posture-rule metadata across channels: `gen_rules.py` ships it into the
MCP server's bundled `_rules_data.py`, so the assistant can enumerate/describe the
posture checks it runs under the same parity guarantee the SAST rules have.

Adding a posture rule? Add its id here too (tests/test_posture_catalog.py guards
that the catalog stays well-formed and covers the key rule ids).

stdlib only (plain data).
"""

# Each entry: id, category, severity, title.
POSTURE_RULES = [
    # AI IDE / rules files
    {"id": "ai-ide-auto-execution", "category": "AI IDE rules", "severity": "HIGH",
     "title": "Rules file encourages running commands automatically"},
    {"id": "ai-ide-disable-approval", "category": "AI IDE rules", "severity": "HIGH",
     "title": "Rules file tells the agent to skip human confirmation"},
    {"id": "ai-ide-fetch-execute", "category": "AI IDE rules", "severity": "HIGH",
     "title": "Rules file contains a fetch-and-execute (curl|bash) instruction"},
    {"id": "ai-ide-destructive", "category": "AI IDE rules", "severity": "HIGH",
     "title": "Rules file references destructive / safety-disabling actions"},
    {"id": "ai-ide-prompt-injection", "category": "AI IDE rules", "severity": "CRITICAL",
     "title": "Rules file contains prompt-injection override language"},
    {"id": "ai-ide-exfiltration", "category": "AI IDE rules", "severity": "CRITICAL",
     "title": "Rules file resembles an exfiltration instruction"},
    {"id": "ai-ide-encoded-payload", "category": "AI IDE rules", "severity": "HIGH",
     "title": "Rules file has a base64 blob next to a decode/exec verb"},
    {"id": "ai-ide-hex-encoded", "category": "AI IDE rules", "severity": "MEDIUM",
     "title": "Rules file contains a long hex-escaped byte string"},
    {"id": "ai-ide-rot-encoded", "category": "AI IDE rules", "severity": "MEDIUM",
     "title": "Rules file references ROT-n encoding"},
    {"id": "ai-ide-obfuscation-zalgo", "category": "AI IDE rules", "severity": "MEDIUM",
     "title": "Rules file uses stacked combining marks (Zalgo) obfuscation"},
    # Invisible Unicode
    {"id": "ai-unicode-tag", "category": "Hidden Unicode", "severity": "CRITICAL",
     "title": "Unicode Tag characters in an agent-instruction file"},
    {"id": "ai-unicode-bidi", "category": "Hidden Unicode", "severity": "HIGH",
     "title": "Bidirectional-override characters in an agent-instruction file"},
    {"id": "ai-unicode-zerowidth", "category": "Hidden Unicode", "severity": "HIGH",
     "title": "Zero-width / invisible characters in an agent-instruction file"},
    # Claude permissions
    {"id": "claude-bypass-mode", "category": "Claude permissions", "severity": "HIGH",
     "title": "Claude defaultMode removes the human approval step"},
    {"id": "claude-wildcard-bash", "category": "Claude permissions", "severity": "HIGH",
     "title": "Claude has unrestricted / wildcard shell access"},
    {"id": "claude-broad-read", "category": "Claude permissions", "severity": "CRITICAL",
     "title": "Claude can read/write/edit any path without prompting"},
    {"id": "claude-broad-network", "category": "Claude permissions", "severity": "MEDIUM",
     "title": "Claude has unrestricted network fetch/search"},
    {"id": "claude-destructive-bash", "category": "Claude permissions", "severity": "HIGH",
     "title": "Claude is pre-authorized for a destructive command"},
    {"id": "claude-excessive-tools", "category": "Claude permissions", "severity": "LOW",
     "title": "Claude has a large pre-approved allow list"},
    # MCP
    {"id": "mcp-secret-env", "category": "MCP", "severity": "CRITICAL",
     "title": "MCP server receives long-lived secrets via env"},
    {"id": "mcp-shell-exec", "category": "MCP", "severity": "HIGH",
     "title": "MCP server launches via a shell / pipe-to-shell"},
    {"id": "mcp-broad-fs", "category": "MCP", "severity": "HIGH",
     "title": "MCP server mounts a broad filesystem path"},
    {"id": "mcp-remote-unauth", "category": "MCP", "severity": "HIGH",
     "title": "Remote MCP server has no auth header"},
    {"id": "mcp-tool-poisoning", "category": "MCP", "severity": "HIGH",
     "title": "MCP config contains tool-poisoning language"},
    {"id": "mcp-tool-hidden-unicode", "category": "MCP", "severity": "CRITICAL",
     "title": "Hidden Unicode in an MCP tool definition"},
    {"id": "mcp-permissive-schema", "category": "MCP", "severity": "LOW",
     "title": "MCP tool input schema is permissive (additionalProperties open)"},
    {"id": "mcp-cross-server-exfil", "category": "MCP", "severity": "HIGH",
     "title": "MCP servers form a read-local + send-remote chain"},
    {"id": "mcp-cross-server-rce", "category": "MCP", "severity": "HIGH",
     "title": "MCP servers form a fetch + shell-exec chain"},
    {"id": "mcp-server-not-allowlisted", "category": "MCP", "severity": "HIGH",
     "title": "MCP server is not on the policy allowlist"},
    # GitHub Actions
    {"id": "gha-pull-request-target", "category": "CI/CD", "severity": "CRITICAL",
     "title": "Workflow uses pull_request_target"},
    {"id": "gha-prtarget-untrusted-checkout", "category": "CI/CD", "severity": "CRITICAL",
     "title": "pull_request_target checks out the untrusted PR head (pwn request)"},
    {"id": "gha-script-injection", "category": "CI/CD", "severity": "HIGH",
     "title": "Untrusted github.event interpolation in a run step"},
    {"id": "gha-unpinned-action", "category": "CI/CD", "severity": "HIGH",
     "title": "Action not pinned by commit SHA"},
    {"id": "gha-secret-to-untrusted-action", "category": "CI/CD", "severity": "HIGH",
     "title": "Secrets passed to an unpinned third-party action"},
    # Integrity / supply-chain
    {"id": "integrity-drift", "category": "Config integrity", "severity": "CRITICAL",
     "title": "Approval-sensitive file changed without re-approval (rug-pull/TOCTOU)"},
    {"id": "integrity-new-file", "category": "Config integrity", "severity": "HIGH",
     "title": "New approval-sensitive file since the baseline"},
    {"id": "ai-exfiltration-compound", "category": "Exfiltration", "severity": "CRITICAL",
     "title": "Skill/rule file both reads a credential and transmits off-box"},
    {"id": "pkg-hallucinated", "category": "Dependency trust", "severity": "CRITICAL",
     "title": "Hallucinated / non-existent package (slopsquatting)"},
    {"id": "pkg-typosquat-suspect", "category": "Dependency trust", "severity": "MEDIUM",
     "title": "Package name is a typosquat near-miss of a popular package"},
    {"id": "pkg-known-malicious", "category": "Dependency trust", "severity": "CRITICAL",
     "title": "Package is on the known-malicious (OSV MAL-) denylist"},
]

POSTURE_RULE_IDS = {r["id"] for r in POSTURE_RULES}
