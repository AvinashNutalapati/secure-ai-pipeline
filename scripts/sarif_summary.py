#!/usr/bin/env python3
"""
Report-only SARIF summarizer (never fails the build).

Prints a human-readable summary of a SARIF file to the job log and, when run in
GitHub Actions, to the run's Step Summary — so SAST/SCA findings are visible
even on private repos where SARIF can't be uploaded to the Security tab (that
needs GitHub Advanced Security). Always exits 0; gating is a separate concern
(sarif_gate.py).

Usage:
    python sarif_summary.py <file.sarif> [--label NAME]

stdlib only.
"""

import argparse
import json
import os
import sys

_LEVEL_RANK = {"error": 0, "warning": 1, "note": 2, "none": 3}


def collect(data) -> list:
    """Return [(level, rule_id, message, location)] sorted by severity."""
    out = []
    for run in (data or {}).get("runs", []):
        rules = {r.get("id"): r
                 for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            rid = res.get("ruleId", "")
            level = res.get("level") or \
                rules.get(rid, {}).get("defaultConfiguration", {}).get("level", "warning")
            msg = ((res.get("message", {}) or {}).get("text", "") or rid).splitlines()
            msg = msg[0][:140] if msg else rid
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = loc.get("artifactLocation", {}).get("uri", "")
            line = loc.get("region", {}).get("startLine", "")
            where = f"{uri}:{line}" if uri and line else uri
            out.append((level, rid, msg, where))
    out.sort(key=lambda r: _LEVEL_RANK.get(r[0], 9))
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sarif")
    parser.add_argument("--label", default="SARIF")
    parser.add_argument("--max", type=int, default=100)
    args = parser.parse_args(argv)

    if not os.path.exists(args.sarif):
        print(f"  [{args.label}] no report produced (scanner skipped or wrote nothing).")
        return 0
    try:
        with open(args.sarif, encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"  [{args.label}] could not read report: {exc}")
        return 0

    rows = collect(data)
    counts = {}
    for level, *_ in rows:
        counts[level] = counts.get(level, 0) + 1
    summary = ", ".join(f"{n} {lvl}" for lvl, n in sorted(counts.items())) or "none"
    print(f"  [{args.label}] {len(rows)} finding(s): {summary}")
    for level, rid, msg, where in rows[:args.max]:
        print(f"    {level.upper():8} {rid}  {where}")
        print(f"             {msg}")

    # GitHub Actions Step Summary (rendered markdown on the run page).
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        lines = [f"### {args.label} — {len(rows)} finding(s) ({summary})", ""]
        if rows:
            lines += ["| Severity | Rule | Location | Finding |",
                      "|---|---|---|---|"]
            for level, rid, msg, where in rows[:args.max]:
                m = msg.replace("|", "\\|")
                lines.append(f"| {level} | `{rid}` | {where or '—'} | {m} |")
        else:
            lines.append("✅ No findings.")
        try:
            with open(step_summary, "a", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n\n")
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
