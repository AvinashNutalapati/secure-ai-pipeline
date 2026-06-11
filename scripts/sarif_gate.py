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


def _is_suppressed(result) -> bool:
    """True if a SARIF result is effectively suppressed (e.g. an inline
    `nosemgrep`). Per SARIF semantics a suppression only takes effect once it
    is `accepted` (an absent status means accepted). `underReview` and
    `rejected` suppressions do NOT suppress — the finding still gates the
    build (fail-closed)."""
    suppressions = result.get("suppressions")
    if not suppressions:
        return False
    return any((s or {}).get("status", "accepted") == "accepted" for s in suppressions)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sarif", help="Path to the SARIF file to gate on.")
    parser.add_argument("--label", default="SARIF", help="Tool name for log output.")
    args = parser.parse_args(argv)

    fail_on_warnings = os.environ.get("FAIL_ON_WARNINGS", "false").strip().lower() in TRUTHY

    if not os.path.exists(args.sarif):
        # Fail closed: a missing SARIF means the scanner never ran or wrote to
        # a different path. Exiting 0 here would silently disable the gate.
        print(f"  [FAIL] no SARIF file at '{args.sarif}' — scanner output is "
              "missing, failing closed. (Did the scan step crash, or write to "
              "a different path?)")
        return 1

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
            # Honor accepted SARIF suppressions (e.g. an inline `nosemgrep`).
            # `underReview`/`rejected` suppressions do NOT suppress — those
            # results still gate (fail-closed).
            if _is_suppressed(result):
                continue
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
