"""
secure-ai-pipeline:rule-source — excluded from the built-in scan.

Maps a finding's identity (rule id / CWE) to standard threat-taxonomy tags for
governance reporting: GitHub-recognised CWE tags (`external/cwe/cwe-NNN`, which
render as CWE links in code scanning) plus OWASP LLM / OWASP Agentic / MITRE ATLAS
labels for the AI-specific checks.

stdlib only (plain data + a helper).
"""

# rule_key -> OWASP-LLM (2025) / OWASP-Agentic (2026) / MITRE-ATLAS tag.
OWASP_BY_RULE = {
    # code-level (OWASP LLM Top 10)
    "llm-output-to-sink": "OWASP-LLM05-Improper-Output-Handling",
    "jwt-verify-disabled": "OWASP-LLM-Broken-Authentication",
    "eval-user-input": "OWASP-LLM05-Improper-Output-Handling",
    "sql-injection-fstring": "OWASP-LLM05-Improper-Output-Handling",
    # AI-workflow posture (OWASP Agentic / MITRE ATLAS)
    "mcp-tool-poisoning": "OWASP-Agentic-ASI01-Tool-Misuse",
    "mcp-tool-hidden-unicode": "OWASP-Agentic-ASI01-Tool-Misuse",
    "mcp-permissive-schema": "OWASP-Agentic-ASI01-Tool-Misuse",
    "mcp-cross-server-exfil": "OWASP-Agentic-ASI03-Privilege-Abuse",
    "mcp-cross-server-rce": "OWASP-Agentic-ASI03-Privilege-Abuse",
    "mcp-secret-env": "OWASP-Agentic-ASI06-Memory-Secret-Exposure",
    "ai-exfiltration-compound": "OWASP-Agentic-Sensitive-Data-Exfiltration",
    "ai-unicode-tag-injection": "MITRE-ATLAS-AML.T0051-Prompt-Injection",
    "ai-unicode-tag": "MITRE-ATLAS-AML.T0051-Prompt-Injection",
    "ai-unicode-bidi": "MITRE-ATLAS-AML.T0051-Prompt-Injection",
    "ai-unicode-zerowidth": "MITRE-ATLAS-AML.T0051-Prompt-Injection",
    "ai-ide-prompt-injection": "MITRE-ATLAS-AML.T0051-Prompt-Injection",
    "ai-ide-encoded-payload": "MITRE-ATLAS-AML.T0051-Prompt-Injection",
    "ai-ide-exfiltration": "OWASP-Agentic-Sensitive-Data-Exfiltration",
    "integrity-drift": "MITRE-ATLAS-AML.T0010-Supply-Chain",
    "pkg-hallucinated": "OWASP-LLM03-Supply-Chain",
    "pkg-typosquat-suspect": "OWASP-LLM03-Supply-Chain",
}


def tags_for(rule_key: str = "", cwe_id: str = "") -> list:
    """Standard-taxonomy tags for a finding (CWE link + OWASP/ATLAS label)."""
    tags = []
    if cwe_id:
        tags.append(f"external/cwe/cwe-{cwe_id}")
    owasp = OWASP_BY_RULE.get(rule_key or "")
    if owasp:
        tags.append(owasp)
    return tags
