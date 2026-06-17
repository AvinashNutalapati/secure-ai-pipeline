#!/usr/bin/env python3
"""
Write/refresh the config-integrity baseline used by the integrity posture scanner
(rug-pull / TOCTOU / Cuckoo-attack drift detection).

It records a SHA-256 of every approval-sensitive file (AI rules, MCP configs, CI
workflows, Claude settings) into `.secure-ai-pipeline/integrity-baseline.json`.
Commit that file so CI and PR diffs can detect any later unreviewed change.

Usage:
    python scripts/integrity_baseline.py [ROOT]

stdlib only.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from scanners.posture import integrity  # noqa: E402


def main(argv=None) -> int:
    root = Path((argv or sys.argv[1:] or [os.environ.get("GITHUB_WORKSPACE", os.getcwd())])[0]).resolve()
    hashes = integrity.compute_hashes(root)
    out = root / integrity.BASELINE_REL
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"version": 1, "files": hashes}, indent=2,
                              sort_keys=True) + "\n", encoding="utf-8")
    print(f"  Wrote integrity baseline: {integrity.BASELINE_REL} "
          f"({len(hashes)} file(s) pinned).")
    print(f"  Commit it so drift is detected in CI/PRs:")
    print(f"    git add -f {integrity.BASELINE_REL} && git commit -m "
          f"'chore: pin config-integrity baseline'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
