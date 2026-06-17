"""
Cross-tool finding consolidation — the ONE place that collapses duplicates.

The pipeline runs many overlapping scanners (gitleaks + trufflehog + detect-secrets
on secrets; trivy + osv + grype + pip-audit + npm-audit on SCA; semgrep + bandit +
gosec on SAST). Without this module the same issue is reported 2–5×: each tool words
its title differently, so a naive (title, file, line) key never matches.

``consolidate(scan_type, findings)`` groups findings by a *semantic* fingerprint and
merges each group into one finding that:
  - keeps the **most severe** verdict across the group (fail-closed),
  - records every contributing tool in ``sources`` (so renderers can show
    "confirmed by K tools" instead of K duplicate rows),
  - prefers a **verified** source's wording when present.

It runs inside ``scan_all._assemble_layer`` so EVERY channel (CLI table, HTML,
``--json``, SARIF/GitHub code-scanning, the MCP server) inherits one de-duplicated
result — not just the Action's job summary.

Findings are the normalised dict shape from ``registry.finding`` (or any object
exposing the same attributes, e.g. ``scan_all.ScanFinding``). Operates on plain
dicts and returns plain dicts; the caller round-trips its own type.

stdlib only.
"""

from __future__ import annotations

import hashlib

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def _rank(sev) -> int:
    return _RANK.get((sev or "").strip().upper(), len(SEVERITIES))


def _get(f, key, default=""):
    """Read a field from a dict OR an object (ScanFinding) uniformly."""
    if isinstance(f, dict):
        return f.get(key, default)
    return getattr(f, key, default)


def _norm_pkg(name: str) -> str:
    return (name or "").strip().lower().replace("-", "_")


# ─────────────────────────────────────────────────────────────────────────────
# Fingerprint — the per-scan-type identity that defines "the same finding"
# ─────────────────────────────────────────────────────────────────────────────

def fingerprint(scan_type: str, f) -> tuple:
    """A hashable identity for ``f`` within ``scan_type``.

    The whole point is that two tools describing the SAME issue produce the SAME
    fingerprint despite different wording — and two genuinely different issues do
    not. Severity is deliberately NOT part of the key (it's merged, not matched),
    so a HIGH-from-tool-A and MEDIUM-from-tool-B for one issue still collapse.
    """
    file = _get(f, "file", "") or ""
    # Stringify the line so a tool emitting "10" and another emitting 10 still
    # produce the same key (line types vary across raw tool output).
    line = str(_get(f, "line", 0) or 0)
    vuln_id = (_get(f, "vuln_id", "") or "").strip().upper()
    rule_key = (_get(f, "rule_key", "") or "").strip()
    cwe_id = (_get(f, "cwe_id", "") or "").strip()
    signature = (_get(f, "signature", "") or "").strip()
    title = (_get(f, "title", "") or "").strip().lower()

    if scan_type in ("sca", "packages"):
        # A CVE/GHSA/MAL advisory is the stable identity. signature carries the
        # normalised package name so the same advisory on two *different* packages
        # stays distinct, while file/line (unstable across tools — Trivy reports
        # line 0, the curated built-in the import line) are ignored.
        if vuln_id:
            return ("vuln", vuln_id, _norm_pkg(signature))

    if scan_type == "secrets":
        # Same credential = same secret regardless of how a tool worded it.
        # Prefer the value signature *within a file* (survives a 1-line offset
        # between tools) — but the SAME value in two files stays two findings, so
        # both get fixed. Without a signature, the location is the identity.
        if signature:
            return ("secret", file, signature)
        return ("secret", file, line)

    if scan_type in ("sast", "iac", "ci_cd"):
        # The weakness CLASS at a location — CWE is the cross-tool key (semgrep's
        # flask-debug and bandit's B201 both map to CWE-94 at one line); fall back
        # to the tool's own rule id, then the wording.
        ident = cwe_id or rule_key
        if ident:
            return ("rule", ident, file, line)

    # Fallback for everything else (and identity-less findings): wording +
    # location, but NOT severity, so duplicate wording at one line still merges.
    return ("loc", title, file, line)


def fingerprint_hash(scan_type: str, f) -> str:
    """A stable short hex digest of the fingerprint — used as the SARIF
    partialFingerprints value so GitHub code scanning de-dupes across runs."""
    return hashlib.sha256(repr(fingerprint(scan_type, f)).encode("utf-8")).hexdigest()[:16]


# ─────────────────────────────────────────────────────────────────────────────
# Consolidate — group by fingerprint, merge each group
# ─────────────────────────────────────────────────────────────────────────────

def _sources_of(f) -> list:
    """Every tool credited to a finding: its own ``sources`` plus its ``tool``.
    Empty entries are dropped so a tool-less finding never injects '' into the
    merged source list (which would surface as a blank tool in CLI/SARIF output)."""
    src = _get(f, "sources", None) or []
    if isinstance(src, str):
        src = [src]
    out = [s for s in src if s]
    tool = _get(f, "tool", "")
    if tool and tool not in out:
        out.append(tool)
    return out


def _is_verified(f) -> bool:
    return (_get(f, "confidence", "") or "").strip().lower() == "verified"


def consolidate(scan_type: str, findings) -> list:
    """Collapse same-issue findings into one each. Input/output are dicts.

    Order is stable (first appearance of each fingerprint preserved). A group's
    merged finding takes its wording/location/identity from the most severe member
    (verified sources win ties), its severity = the max in the group, and its
    ``sources`` = the ordered union of every contributing tool.
    """
    groups: dict = {}
    order: list = []
    for f in findings:
        f = f if isinstance(f, dict) else _to_dict(f)
        key = fingerprint(scan_type, f)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)

    out: list = []
    for key in order:
        group = groups[key]
        # Representative: verified first, then most severe, then first-seen.
        rep = min(group, key=lambda g: (0 if _is_verified(g) else 1, _rank(g.get("severity"))))
        merged = dict(rep)
        # Severity = the worst opinion in the group (fail-closed gating). Default
        # to INFO if every member is missing/blank, so downstream renderers and
        # the SARIF level map never receive None.
        merged["severity"] = min((g.get("severity") for g in group), key=_rank) or "INFO"
        # Confidence = verified if any tool verified it.
        if any(_is_verified(g) for g in group):
            merged["confidence"] = "verified"
        # Sources = ordered union of every tool that reported this.
        srcs: list = []
        for g in group:
            for s in _sources_of(g):
                if s not in srcs:
                    srcs.append(s)
        merged["sources"] = srcs
        out.append(merged)
    return out


def _to_dict(f) -> dict:
    """Best-effort dict view of a finding object (e.g. ScanFinding)."""
    if hasattr(f, "to_dict"):
        return f.to_dict()
    return {k: getattr(f, k) for k in (
        "scan_type", "severity", "title", "detail", "file", "line", "fix", "tool",
        "vuln_id", "rule_key", "cwe_id", "signature", "confidence", "reachable",
        "sources") if hasattr(f, k)}
