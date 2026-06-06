"""Test bootstrap — make the project's scripts and packages importable."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# `scripts/` holds plain modules (check_packages.py, run_pipeline.py).
sys.path.insert(0, str(ROOT / "scripts"))
# Repo root for the `extensions` package (extensions.claude_mcp.rules).
sys.path.insert(0, str(ROOT))
