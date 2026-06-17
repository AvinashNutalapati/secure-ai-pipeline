#!/usr/bin/env python3
"""
Build the GitHub Actions job summary for the security pipeline.

Reads the SARIF outputs of the secret / SCA / SAST scanners and writes a uniform
summary to the run's Step Summary: one table per scan type (severity, finding,
location, suggested fix — including Trivy's fixed-version), a copy-paste AI fix
prompt per type, and one combined "fix everything" prompt at the end. Report-only;
always exits 0 (gating is sarif_gate.py's job).

Usage:
    python job_summary.py --scan TYPE LABEL PATH [--scan ...]
      TYPE = secrets | sca | sast       (reads a SARIF file)
           | ai_posture                 (reads blast_radius.py --json output)
           | packages                   (reads check_packages.py --json output)

stdlib only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scanners import registry  # noqa: E402  (per-type AI fix-prompt wording + labels)

_RANK = {"error": 0, "warning": 1, "note": 2, "none": 3}
_EMOJI = {"error": "🟥", "warning": "🟧", "note": "🟦", "none": "⬜"}

# blast_radius / scan_all severities → SARIF-style levels used by the renderer.
_SEV_TO_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                 "LOW": "note", "INFO": "none"}

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


def _read_json(path):
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None


def load_blast_radius(path):
    """Normalise blast_radius.py --json output. Drops INFO (inventory/registry
    noise) so the section is actionable."""
    data = _read_json(path)
    if data is None:
        return None
    out = []
    for f in data.get("findings", []):
        sev = (f.get("severity") or "INFO").upper()
        if sev == "INFO":
            continue
        out.append({"level": _SEV_TO_LEVEL.get(sev, "note"), "rule": f.get("rule_id", ""),
                    "msg": f.get("title", "") or f.get("rule_id", ""),
                    "rule_obj": {"help": {"text": f.get("fix", "")}},
                    "file": f.get("file", ""), "line": f.get("line") or ""})
    out.sort(key=lambda x: _RANK.get(x["level"], 9))
    return out


def load_packages(path):
    """Normalise check_packages.py --json output (blocked = hallucinated/missing,
    warnings = could-not-verify)."""
    data = _read_json(path)
    if data is None:
        return None
    out = []
    for b in data.get("blocked", []):
        out.append({"level": "error", "rule": "non-existent-package",
                    "msg": f"Package '{b.get('package', '')}' not found on "
                           f"{b.get('registry', '')} — hallucinated / slopsquatting risk",
                    "rule_obj": {"help": {"text": "Remove or correct the import; verify the "
                                          "real package name on the registry before installing."}},
                    "file": b.get("file", ""), "line": 0})
    for w in data.get("warnings", []):
        out.append({"level": "note", "rule": "unverified-package",
                    "msg": f"Could not verify '{w.get('package', '')}' on "
                           f"{w.get('registry', '')} ({w.get('reason', 'registry unreachable')})",
                    "rule_obj": {"help": {"text": "Re-run when the registry is reachable."}},
                    "file": w.get("file", ""), "line": 0})
    for s in data.get("suspect", []):
        out.append({"level": "warning", "rule": "typosquat-suspect",
                    "msg": f"Possible typosquat: '{s.get('package', '')}' looks like "
                           f"the popular '{s.get('suggestion', '')}' ({s.get('registry', '')})",
                    "rule_obj": {"help": {"text": f"Confirm you meant '{s.get('package', '')}' "
                                          f"and not '{s.get('suggestion', '')}'."}},
                    "file": s.get("file", ""), "line": 0})
    out.sort(key=lambda x: _RANK.get(x["level"], 9))
    return out


def load_scan_all(path):
    """Read scan_all.py --json output into {scan_type: [finding rows]}.

    This is how the consolidated multi-tool scan (every installed OSS scanner,
    merged per type by scan_all) feeds the summary: one section per type, with
    each tool's findings already grouped together. INFO is dropped."""
    data = _read_json(path)
    if data is None:
        return {}
    out = {}
    for stype, layer in (data.get("layers", {}) or {}).items():
        findings_raw = layer.get("findings", []) or []
        # A type whose scanner wasn't installed didn't actually run — skip it so
        # the summary never claims "no findings" for something it never scanned.
        if not findings_raw and layer.get("engine", "") in ("not run", "unavailable", ""):
            continue
        rows = []
        for f in findings_raw:
            sev = (f.get("severity") or "INFO").upper()
            if sev == "INFO":
                continue
            fix = f.get("fix", "")
            rows.append({
                "level": _SEV_TO_LEVEL.get(sev, "note"),
                "rule": f.get("tool", "") or stype,
                "msg": f.get("title", "") or f.get("detail", ""),
                "rule_obj": {"help": {"text": fix}},
                "file": f.get("file", ""), "line": f.get("line") or "",
                "tool": f.get("tool", ""), "fix": fix,
                # scan_all has already consolidated cross-tool duplicates; carry the
                # contributing tools so the summary can show "confirmed by K tools".
                "sources": f.get("sources") or [],
            })
        rows.sort(key=lambda x: _RANK.get(x["level"], 9))
        out[stype] = rows
    return out


def _load_for(scan_type, path):
    if scan_type == "ai_posture":
        return load_blast_radius(path)
    if scan_type == "packages":
        return load_packages(path)
    return load(path)


def title_and_fix(scan_type, f):
    """Return (title, suggested_fix). For SCA, pull Trivy's fixed-version."""
    msg, rid = f["msg"], f["rule"]
    first = msg.splitlines()[0] if msg else rid
    # scan_all-sourced findings carry their own explicit fix — use it verbatim;
    # the per-type SARIF heuristics below are only for tool-native SARIF.
    if f.get("fix"):
        return (first or rid)[:120], f["fix"]
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
        f"Task: {registry.intro_for(scan_type)}.\n\n"
        "Rules:\n" + "\n".join(_RULES) + "\n\n"
        f"Findings — {label}:\n" + "\n".join(lines)
    )


def _dedup(findings, scan_type=""):
    """Collapse duplicate findings so two tools reporting the same issue show once.
    For secrets, the same (file, line) is the same leaked credential regardless of
    how the tool worded it (gitleaks's SARIF vs trufflehog via --scan-all), so we
    dedup on location there; otherwise key on the full (level, msg, file, line) so
    distinct issues at one line (e.g. two SAST rules) both stay.

    When a duplicate is dropped its contributing tools are folded into the kept
    finding's ``sources`` — so the "engines:" line and "✓K" count still credit
    every tool that found it (e.g. native gitleaks SARIF + the scan_all secrets
    layer), rather than silently losing the dropped row's attribution."""
    def _srcs(f):
        out = [s for s in (f.get("sources") or []) if s]
        if f.get("tool") and f.get("tool") not in out:
            out.append(f.get("tool"))
        return out

    seen, out = {}, []
    for f in findings:
        if scan_type == "secrets" and f.get("file") and f.get("line"):
            key = ("secret", f.get("file"), f.get("line"))
        else:
            key = (f.get("level"), f.get("msg"), f.get("file"), f.get("line"))
        if key in seen:
            kept = seen[key]
            merged = list(kept.get("sources") or [])
            for s in _srcs(f):
                if s not in merged:
                    merged.append(s)
            kept["sources"] = merged
            continue
        f = dict(f)
        f["sources"] = _srcs(f)
        seen[key] = f
        out.append(f)
    return out


def _engines_line(findings):
    """A small line naming every tool that contributed to this section — the
    visible proof that the type was scanned by the whole stack, consolidated.
    Counts each finding's merged `sources` (set by consolidation) plus its tool."""
    tools = []
    for f in findings:
        for t in (f.get("sources") or []):
            if t and t not in tools:
                tools.append(t)
        t = f.get("tool")
        if t and t not in tools:
            tools.append(t)
    return f"<sub>🔧 engines: {', '.join(tools)}</sub>" if tools else ""


def _merge_sections(scans, scan_all):
    """Order = explicit --scan inputs first (as given), then any scan_all-only
    types in canonical registry order. Findings for a type present in both merge.
    Returns [(type, label, findings|None)] — None means the type didn't run."""
    ordered, seen = [], set()
    for scan_type, label, path in scans:
        base = _load_for(scan_type, path)
        extra = scan_all.get(scan_type)
        findings = None if (base is None and extra is None) else (base or []) + (extra or [])
        ordered.append((scan_type, label, findings))
        seen.add(scan_type)
    for stype in registry.SCAN_TYPE_KEYS:
        if stype in scan_all and stype not in seen:
            ordered.append((stype, registry.label_for(stype), scan_all[stype]))
            seen.add(stype)
    return ordered


def build(scans, section_only=False, scan_all=None):
    """scans = [(type, label, path)]. Returns the markdown + a log digest.

    scan_all = {type: [rows]} from load_scan_all() merges the consolidated
    multi-tool scan in, so each section shows every tool's findings together.

    section_only=True omits the top header and the combined prompt — used when
    each job in a multi-job workflow contributes its own section to the shared
    run summary (so the sections concatenate without repeated headers)."""
    md = [] if section_only else ["## 🔒 Secure AI Pipeline — results", ""]
    log = []
    combined = []  # (label, lines)
    any_findings = False

    for scan_type, label, findings in _merge_sections(scans, scan_all or {}):
        if findings is None:
            md += [f"### {label} — not run", ""]
            log.append(f"  [{label}] not run")
            continue
        findings = _dedup(findings, scan_type)
        if not findings:
            md += [f"### {label} — ✅ no findings", ""]
            log.append(f"  [{label}] ✅ no findings")
            continue
        any_findings = True
        log.append(f"  [{label}] ⚠️ {len(findings)} finding(s)")
        md += [f"### {label} — ⚠️ {len(findings)} finding(s)", ""]
        engines = _engines_line(findings)
        if engines:
            md += [engines, ""]
        md += ["| Severity | Finding | Location | Suggested fix |", "|---|---|---|---|"]
        lines = []
        for f in findings[:100]:
            title, fix = title_and_fix(scan_type, f)
            k = len(f.get("sources") or [])
            if k > 1:                       # confirmed by multiple tools → trust signal
                title = f"{title} ✓{k}"
            loc = f"{f['file']}:{f['line']}" if f.get("file") and f.get("line") else (f.get("file") or "—")
            md.append(f"| {_EMOJI.get(f['level'], '')} {f['level']} | {_esc(title)} "
                      f"| `{_esc(loc)}` | {_esc(fix)} |")
            lines.append(f"- [{f['level'].upper()}] {title}  ({loc}) — fix: {fix}")
        md += ["",
               f"<details><summary>🤖 Fix prompt — {label} (click to copy)</summary>", "",
               "```text", _prompt(scan_type, label, lines), "```", "", "</details>", ""]
        combined.append((label, lines))

    # Combined prompt is a dropdown too (same as the per-type ones) so it's never
    # a loose visible block that reads as belonging to the section above it.
    if not section_only:
        if any_findings:
            overall = ["You are a senior application-security engineer working in this repository.",
                       "Task: fix ALL the security findings below, grouped by type.", "",
                       "Rules:", *_RULES, ""]
            for label, lines in combined:
                overall += [f"## {label}", *lines, ""]
            md += ["---",
                   "<details><summary>🤖 <b>Fix everything</b> — one combined prompt for all "
                   "findings (click to copy)</summary>", "",
                   "```text", "\n".join(overall).rstrip(), "```", "", "</details>"]
        else:
            md.append("✅ **All clear** — no findings to fix.")

    return "\n".join(md) + "\n", log


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--scan", nargs=3, action="append", default=[],
                   metavar=("TYPE", "LABEL", "PATH"))
    p.add_argument("--scan-all", default="", metavar="SCAN_JSON",
                   help="scan_all.py --json output: its per-type layers are merged "
                        "into the matching sections (the consolidated multi-tool scan).")
    p.add_argument("--section-only", action="store_true",
                   help="Omit the top header + combined prompt (one job's section).")
    args = p.parse_args(argv)

    scan_all = load_scan_all(args.scan_all) if args.scan_all else None
    text, log = build(args.scan, section_only=args.section_only, scan_all=scan_all)
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
