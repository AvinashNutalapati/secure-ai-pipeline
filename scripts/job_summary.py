#!/usr/bin/env python3
"""
Build the GitHub Actions job summary for the security pipeline.

Reads the SARIF outputs of the secret / SCA / SAST scanners and writes a uniform
summary to the run's Step Summary: one table per scan type (severity, finding,
location, suggested fix — including Trivy's fixed-version), a copy-paste AI fix
prompt per type, and one combined "fix everything" prompt at the end. Report-only;
always exits 0 (gating is sarif_gate.py's job).

Usage:
    python job_summary.py --scan TYPE LABEL SARIF [--scan ...]
      TYPE = secrets | sca | sast   (controls fix wording + fixed-version parsing)

stdlib only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

_RANK = {"error": 0, "warning": 1, "note": 2, "none": 3}
_EMOJI = {"error": "🟥", "warning": "🟧", "note": "🟦", "none": "⬜"}

_INTRO = {
    "secrets": "remove every hardcoded secret, replace it with an environment "
               "variable or secrets-manager lookup, and note that the exposed value must be rotated",
    "sca": "upgrade each vulnerable dependency to the fixed version shown (or "
           "replace the package if no fix exists)",
    "sast": "fix each insecure code pattern using the secure idiom the rule describes",
}

_RULES = [
    "- Fix only what each finding lists; do not touch unrelated code.",
    "- Show a diff per file and explain each change in one line.",
    "- If a fix needs a decision (e.g. a breaking upgrade), ask before guessing.",
]


def load(path):
    """None = scanner produced no report; [] = ran clean; [..] = findings."""
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None
    out = []
    for run in data.get("runs", []):
        rules = {r.get("id"): r for r in
                 run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            rid = res.get("ruleId", "")
            rule = rules.get(rid, {})
            level = res.get("level") or \
                rule.get("defaultConfiguration", {}).get("level", "warning")
            msg = (res.get("message", {}) or {}).get("text", "") or rid
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            out.append({
                "level": level, "rule": rid, "msg": msg, "rule_obj": rule,
                "file": loc.get("artifactLocation", {}).get("uri", ""),
                "line": loc.get("region", {}).get("startLine", ""),
            })
    out.sort(key=lambda f: _RANK.get(f["level"], 9))
    return out


def title_and_fix(scan_type, f):
    """Return (title, suggested_fix). For SCA, pull Trivy's fixed-version."""
    msg, rid = f["msg"], f["rule"]
    first = msg.splitlines()[0] if msg else rid
    if scan_type == "secrets":
        return (first or rid)[:120], (
            "Remove the secret, load it from the environment / a secrets manager, "
            "and ROTATE the exposed value.")
    if scan_type == "sca":
        name = _grab(r"Package:\s*([^\n]+)", msg)
        installed = _grab(r"Installed Version:\s*([^\n]+)", msg)
        fixed = _grab(r"Fixed Version:\s*([^\n]+)", msg)
        prefix = " ".join(p for p in (name, installed) if p)
        title = f"{prefix} — {rid}" if prefix else (rid or first)
        if fixed:
            fix = f"Upgrade {name or 'the package'} to {fixed}."
        else:
            fix = "No fixed version published — assess exposure or replace the dependency."
        return title[:120], fix
    help_txt = (f["rule_obj"].get("help", {}) or {}).get("text") or \
        (f["rule_obj"].get("fullDescription", {}) or {}).get("text", "")
    fix = help_txt.splitlines()[0][:200] if help_txt else \
        "Apply the secure pattern this rule describes."
    return (first or rid)[:120], fix


def _grab(pattern, text):
    m = re.search(pattern, text)
    return m.group(1).strip() if m else ""


def _esc(s):
    return str(s).replace("|", "\\|").replace("\n", " ").strip()


def _prompt(scan_type, label, lines):
    return (
        "You are a senior application-security engineer working in this repository.\n"
        f"Task: {_INTRO.get(scan_type, 'fix the security findings below')}.\n\n"
        "Rules:\n" + "\n".join(_RULES) + "\n\n"
        f"Findings — {label}:\n" + "\n".join(lines)
    )


def build(scans):
    """scans = [(type, label, sarif_path)]. Returns the markdown + a log digest."""
    md = ["## 🔒 Secure AI Pipeline — results", ""]
    log = []
    combined = []  # (label, lines)
    any_findings = False

    for scan_type, label, path in scans:
        findings = load(path)
        if findings is None:
            md += [f"### {label} — not run", ""]
            log.append(f"  [{label}] not run")
            continue
        if not findings:
            md += [f"### {label} — ✅ no findings", ""]
            log.append(f"  [{label}] ✅ no findings")
            continue
        any_findings = True
        log.append(f"  [{label}] ⚠️ {len(findings)} finding(s)")
        md += [f"### {label} — ⚠️ {len(findings)} finding(s)", "",
               "| Severity | Finding | Location | Suggested fix |",
               "|---|---|---|---|"]
        lines = []
        for f in findings[:100]:
            title, fix = title_and_fix(scan_type, f)
            loc = f"{f['file']}:{f['line']}" if f["file"] and f["line"] else (f["file"] or "—")
            md.append(f"| {_EMOJI.get(f['level'], '')} {f['level']} | {_esc(title)} "
                      f"| `{_esc(loc)}` | {_esc(fix)} |")
            lines.append(f"- [{f['level'].upper()}] {title}  ({loc}) — fix: {fix}")
        md += ["",
               f"<details><summary>🤖 Copy the fix prompt for {label}</summary>", "",
               "```text", _prompt(scan_type, label, lines), "```", "", "</details>", ""]
        combined.append((label, lines))

    if any_findings:
        overall = ["You are a senior application-security engineer working in this repository.",
                   "Task: fix ALL the security findings below, grouped by type.", "",
                   "Rules:", *_RULES, ""]
        for label, lines in combined:
            overall += [f"## {label}", *lines, ""]
        md += ["---", "## 🤖 Fix everything — one prompt", "",
               "```text", "\n".join(overall).rstrip(), "```"]
    else:
        md.append("✅ **All clear** — no findings to fix.")

    return "\n".join(md) + "\n", log


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--scan", nargs=3, action="append", default=[],
                   metavar=("TYPE", "LABEL", "SARIF"))
    args = p.parse_args(argv)

    text, log = build(args.scan)
    step = os.environ.get("GITHUB_STEP_SUMMARY")
    if step:
        try:
            with open(step, "a", encoding="utf-8") as fh:
                fh.write(text)
        except OSError:
            pass
    print("\n".join(log) or "  (no scans)")
    print("  Full results + copy-paste fix prompts → the run's Step Summary.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
