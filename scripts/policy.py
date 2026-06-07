#!/usr/bin/env python3
"""
Policy loading + application for the AI workflow scanner.

A repo can drop a `secure-ai-pipeline.yml` (or .yaml / .json) at its root to
control gating and tighten the scanners. Example:

    fail_on: [critical, high]      # severities that fail the build
    ignore: [gha-unpinned-action]  # rule_ids to suppress
    github_actions:
      require_sha_pinning: true
      block_pull_request_target: true
    mcp:
      allowed_servers: [github-readonly, docs-search]

stdlib only. YAML is parsed via PyYAML if installed, otherwise a small subset
parser that handles this flat schema; JSON policy files always work.
"""

from __future__ import annotations

import json
from pathlib import Path

from scanners.base import SEVERITIES, SEVERITY_WEIGHT

POLICY_FILENAMES = (
    "secure-ai-pipeline.yml",
    "secure-ai-pipeline.yaml",
    "secure-ai-pipeline.json",
)

DEFAULT_POLICY = {
    "fail_on": ["critical", "high"],
    "ignore": [],
    "github_actions": {
        "require_sha_pinning": True,
        "block_pull_request_target": True,
    },
    "mcp": {
        "allowed_servers": [],
    },
}


# ── loading ──────────────────────────────────────────────────────────────────

def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _coerce_scalar(token: str):
    t = token.strip()
    if (t.startswith('"') and t.endswith('"')) or (t.startswith("'") and t.endswith("'")):
        return t[1:-1]
    low = t.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "~", ""):
        return None
    if t.lstrip("-").isdigit():
        return int(t)
    return t


def _parse_inline_list(token: str):
    inner = token.strip()[1:-1].strip()
    if not inner:
        return []
    return [_coerce_scalar(x) for x in inner.split(",")]


def _strip_comment(line: str) -> str:
    if line.lstrip().startswith("#"):
        return ""
    i = line.find(" #")
    return line[:i] if i != -1 else line


def parse_yaml_subset(text: str) -> dict:
    """Parse the constrained policy schema: nested maps (indented), block lists
    (`- item`, indented under their key), inline lists (`[a, b]`), scalars and
    comments. Not a general YAML parser — just enough for policy files."""
    rows = []
    for raw in text.splitlines():
        line = _strip_comment(raw).rstrip()
        if line.strip() == "":
            continue
        indent = len(line) - len(line.lstrip(" "))
        rows.append((indent, line.strip()))

    pos = 0

    def parse_block(min_indent):
        nonlocal pos
        result = None
        while pos < len(rows):
            indent, content = rows[pos]
            if indent < min_indent:
                break
            if content.startswith("- "):
                if result is None:
                    result = []
                pos += 1
                result.append(_coerce_scalar(content[2:]))
            elif ":" in content:
                if result is None:
                    result = {}
                key, _, rest = content.partition(":")
                key, rest = key.strip(), rest.strip()
                pos += 1
                if rest == "":
                    if pos < len(rows) and rows[pos][0] > indent:
                        result[key] = parse_block(indent + 1)
                    else:
                        result[key] = None
                elif rest.startswith("["):
                    result[key] = _parse_inline_list(rest)
                else:
                    result[key] = _coerce_scalar(rest)
            else:
                pos += 1  # ignore lines we don't understand
        return result if result is not None else {}

    parsed = parse_block(0)
    return parsed if isinstance(parsed, dict) else {}


def load_policy(root: Path, path: str | None = None) -> dict:
    """Load + merge the repo policy over defaults. Missing file → defaults."""
    target = None
    if path:
        target = Path(path)
    else:
        for name in POLICY_FILENAMES:
            candidate = root / name
            if candidate.is_file():
                target = candidate
                break
    if not target or not target.is_file():
        # No policy file → friendly, report-only (never gates). Add a policy file
        # to opt into CI gating.
        p = dict(DEFAULT_POLICY)
        p["fail_on"] = []
        return p

    text = target.read_text(encoding="utf-8", errors="ignore")
    data: dict
    if target.suffix == ".json":
        data = json.loads(text)
    else:
        try:
            import yaml  # optional
            data = yaml.safe_load(text) or {}
        except ImportError:
            data = parse_yaml_subset(text)
    if not isinstance(data, dict):
        data = {}
    return _deep_merge(DEFAULT_POLICY, data)


# ── application ──────────────────────────────────────────────────────────────

def _recount(findings: list[dict]) -> dict:
    by_sev = {s: 0 for s in SEVERITIES}
    by_cat: dict[str, dict] = {}
    for f in findings:
        sev = f["severity"]
        by_sev[sev] = by_sev.get(sev, 0) + 1
        cat = by_cat.setdefault(f["category"], {s: 0 for s in SEVERITIES})
        cat[sev] += 1
    return by_sev, by_cat


def _score(by_sev: dict) -> int:
    penalty = sum(SEVERITY_WEIGHT.get(s, 0) * n for s, n in by_sev.items())
    return max(0, 100 - penalty)


def _grade(score: int) -> str:
    return ("A" if score >= 90 else "B" if score >= 75 else
            "C" if score >= 60 else "D" if score >= 40 else "F")


def apply(report: dict, policy: dict) -> dict:
    """Return a new report with policy suppressions, allowlist findings, a
    recomputed score, and a gate decision."""
    ignore = set(policy.get("ignore", []) or [])
    gha = policy.get("github_actions", {}) or {}
    mcp_pol = policy.get("mcp", {}) or {}
    allowed = set(mcp_pol.get("allowed_servers", []) or [])

    kept: list[dict] = []
    for f in report.get("findings", []):
        rid = f.get("rule_id")
        if rid in ignore:
            continue
        if rid == "gha-unpinned-action" and not gha.get("require_sha_pinning", True):
            continue
        if rid == "gha-pull-request-target" and not gha.get("block_pull_request_target", True):
            continue
        kept.append(f)

    # MCP allowlist: any inventoried server not on the allowlist is a finding.
    if allowed:
        for f in report.get("findings", []):
            if f.get("rule_id") == "mcp-server-inventory":
                name = f.get("title", "").split("configured:", 1)[-1].strip()
                if name and name not in allowed:
                    kept.append({
                        "scanner": "mcp", "category": "MCP",
                        "rule_id": "mcp-server-not-allowlisted", "severity": "HIGH",
                        "title": f"MCP server '{name}' is not on the allowlist",
                        "detail": f"Policy allows {sorted(allowed)}; '{name}' is not "
                                  "listed. Unreviewed MCP servers expand blast radius.",
                        "fix": f"Add '{name}' to mcp.allowed_servers after review, "
                               "or remove the server.",
                        "file": f.get("file", ""), "line": 0,
                    })

    by_sev, by_cat = _recount(kept)
    score = _score(by_sev)
    fail_on = {s.upper() for s in (policy.get("fail_on", []) or [])}
    triggered = sorted({f["severity"] for f in kept if f["severity"] in fail_on},
                       key=lambda s: SEVERITIES.index(s))

    return {
        **report,
        "findings": kept,
        "counts": by_sev,
        "by_category": by_cat,
        "score": score,
        "grade": _grade(score),
        "policy": {
            "fail_on": sorted(fail_on, key=lambda s: SEVERITIES.index(s)) if fail_on else [],
            "gate_failed": bool(triggered),
            "triggered_by": triggered,
        },
    }


if __name__ == "__main__":
    import sys
    pol = load_policy(Path(sys.argv[1] if len(sys.argv) > 1 else "."))
    print(json.dumps(pol, indent=2))
