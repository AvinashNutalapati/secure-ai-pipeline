"""
Anti-slopsquatting / package-existence scanner — the scan-type home for the
dependency-trust check.

The implementation currently lives at ``scripts/check_packages.py`` because the
GitHub Action, CI and the pre-commit hook invoke that path directly; this module
re-exports it so the scanner is reachable under its scan-type package
(``scanners.packages.slopsquatting``) like the others. Edit ``check_packages.py``
to change behaviour. (Relocating the implementation here behind a thin entry-point
shim at the old path is a planned follow-up.)

stdlib only.
"""

import sys
from pathlib import Path

# scripts/ on the path so `check_packages` resolves when imported via the
# scanners package (it already is for the orchestrators that add scripts/).
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from check_packages import *  # noqa: F401,F403,E402
from check_packages import (  # noqa: F401,E402  (explicit, incl. names import * skips)
    scan, pypi_status, npm_status, main, PYTHON_STDLIB,
)
