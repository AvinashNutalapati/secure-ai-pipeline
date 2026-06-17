"""ESLint security adapter — SAST (JavaScript / TypeScript).

JS/TS SAST was Semgrep + the built-in regex only. This wraps the repo's own ESLint
when `eslint-plugin-security` (or similar) is configured, surfacing its `security/*`
findings. Bring-your-own: it uses the repo's ESLint config and only reports rules in
the security namespace, so it adds no noise from style lint. Returns None when eslint
isn't installed; [] when there's no JS/TS or no security findings.

Each finding carries rule_key + cwe_id so the consolidation layer collapses overlaps
with Semgrep on the same (cwe, file, line).

stdlib only.
"""

from __future__ import annotations

from typing import Optional

from external_tools import _which
from scanners.registry import ScanContext, ToolAdapter, finding, has_files, register, run_json

_INSTALL = "npm i -D eslint eslint-plugin-security  (then enable the plugin in your eslint config)"

# eslint-plugin-security rule -> CWE (the common ones), for cross-tool dedup.
_ESLINT_CWE = {
    "security/detect-child-process": "78",
    "security/detect-non-literal-fs-filename": "22",
    "security/detect-eval-with-expression": "95",
    "security/detect-non-literal-require": "95",
    "security/detect-pseudoRandomBytes": "330",
    "security/detect-unsafe-regex": "1333",
    "security/detect-non-literal-regexp": "1333",
    "security/detect-buffer-noassert": "119",
    "security/detect-no-csrf-before-method-override": "352",
    "security/detect-possible-timing-attacks": "208",
    "security/detect-object-injection": "915",
    "security/detect-bidi-characters": "1007",
}

_ESLINT_SEV = {2: "HIGH", 1: "MEDIUM", 0: "INFO"}


def parse(data) -> list:
    """`eslint -f json` → [{filePath, messages:[{ruleId, severity, message, line}]}].
    Keep only security-namespace rules (severity 2=error→HIGH, 1=warn→MEDIUM)."""
    out = []
    for fileobj in data or []:
        path = fileobj.get("filePath", "")
        for m in fileobj.get("messages", []) or []:
            rid = m.get("ruleId") or ""
            if not rid.lower().startswith("security/"):
                continue
            sev = _ESLINT_SEV.get(m.get("severity"), "MEDIUM")
            out.append(finding(
                sev, f"{m.get('message', rid)} [{rid}]", m.get("message", ""),
                path, int(m.get("line") or 0),
                "Apply the secure pattern this ESLint security rule describes.",
                "eslint-security", rule_key=rid, cwe_id=_ESLINT_CWE.get(rid, "")))
    return out


def run(ctx: ScanContext) -> Optional[list]:
    if not _which("eslint"):
        return None
    if not has_files(ctx.root, "*.js", "*.ts", "*.jsx", "*.tsx", "*.mjs", "*.cjs"):
        return []
    # Use the repo's own ESLint config; non-zero exit on findings is fine.
    return run_json(ctx, ["eslint", "-f", "json", "."], parse, cwd=ctx.root)


register(ToolAdapter(name="eslint-security", scan_type="sast", binary="eslint",
                     run=run, install=_INSTALL))
