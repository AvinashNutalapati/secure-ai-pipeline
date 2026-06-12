#!/usr/bin/env python3
"""
Thin entry-point shim. The anti-slopsquatting implementation now lives at
scripts/scanners/packages/slopsquatting.py — one scanner per scan-type folder.

This shim is kept so the existing entry points keep working unchanged:
  - `python scripts/check_packages.py [ROOT] [--json OUT]`  (the GitHub Action,
    the pre-commit hook, the npx-installed pipeline)
  - `import check_packages` / `from check_packages import …`  (run_pipeline,
    scan_all, blast_radius, the tests)

It re-exports the whole implementation namespace, so every name the old module
exposed (scan, pypi_status, npm_status, main, PYTHON_STDLIB, _skip, …) resolves
here too. Edit behaviour in slopsquatting.py.

stdlib only.
"""

import sys
from pathlib import Path

# Put scripts/ on the path so `scanners.packages.slopsquatting` resolves whether
# this is run as a script or imported as a top-level module.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import scanners.packages.slopsquatting as _impl  # noqa: E402

# Re-export the entire implementation (functions, constants, and the private
# helpers callers reach for, e.g. check_packages._skip) so this module behaves
# exactly like the old one.
globals().update({k: v for k, v in vars(_impl).items() if not k.startswith("__")})

if __name__ == "__main__":
    sys.exit(_impl.main())
