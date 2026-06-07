#!/usr/bin/env python3
"""Severity-aware gate for SARIF output (Semgrep, etc.).

Reads a SARIF file and applies the pipeline's gating policy:

  - ERROR-level findings   -> always BLOCK (exit 1)
  - WARNING-level findings -> BLOCK only when FAIL_ON_WARNINGS is truthy
  - note/INFO findings      -> never block

This lets one knob (the GitHub Action's `fail-on-warnings` input, surfaced as
the FAIL_ON_WARNINGS env var) decide whether WARN-level findings are blocking,
matching the BLOCK/WARN model in run_pipeline.py.

Usage:
    python scripts/sarif_gate.py <file.sarif> [--label NAME]

stdlib only — no third-party deps.
"""
import argparse
import json
import os
import sys

TRUTHY = {"1", "true", "yes", "on"}


def _level_for(result, rules_by_id):
    """Resolve a SARIF result's level, falling back to the rule default."""
    level = result.get("level")
    if level:
        return level
    rule_id = result.get("ruleId")
    rule = rules_by_id.get(rule_id, {})
    return rule.get("defaultConfiguration", {}).get("level", "warning")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sarif", help="Path to the SARIF file to gate on.")
    parser.add_argument("--label", default="SARIF", help="Tool name for log output.")
    args = parser.parse_args(argv)

    fail_on_warnings = os.environ.get("FAIL_ON_WARNINGS", "false").strip().lower() in TRUTHY

    if not os.path.exists(args.sarif):
        # No SARIF means the scanner produced nothing to gate on; treat as clean.
        print(f"  [{args.label}] no SARIF file at '{args.sarif}' — nothing to gate.")
        return 0

    try:
        with open(args.sarif, encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"  [FAIL] could not read SARIF '{args.sarif}': {exc}")
        return 1

    errors, warnings = [], []
    for run in data.get("runs", []):
        rules_by_id = {
            r.get("id"): r
            for r in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        for result in run.get("results", []):
            level = _level_for(result, rules_by_id)
            rule_id = result.get("ruleId", "<unknown>")
            if level == "error":
                errors.append(rule_id)
            elif level == "warning":
                warnings.append(rule_id)

    print(f"  [{args.label}] {len(errors)} error(s), {len(warnings)} warning(s).")
    for rid in errors:
        print(f"    [BLOCK] {rid}")
    for rid in warnings:
        verb = "BLOCK" if fail_on_warnings else "WARN "
        print(f"    [{verb}] {rid}")

    blocking = len(errors) > 0 or (fail_on_warnings and len(warnings) > 0)
    if blocking:
        msg = "errors" if errors else "warnings (fail-on-warnings=true)"
        print(f"  [FAIL] {args.label} gate blocked the build on {msg}.")
        return 1

    if warnings:
        print(f"  [OK] {args.label} gate passed (warnings reported, not blocking).")
    else:
        print(f"  [OK] {args.label} gate passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
