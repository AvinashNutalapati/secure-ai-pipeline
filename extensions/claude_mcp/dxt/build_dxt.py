#!/usr/bin/env python3
"""Build a Claude **Desktop** one-click extension (.dxt) for the stdio MCP server.

A .dxt is just a zip of ``manifest.json`` + ``server/`` (the ``claude_mcp`` package,
a tiny ``main.py`` bootstrap, and vendored dependencies under ``server/lib``).
Claude Desktop unpacks it and launches ``python3 server/main.py``, which serves the
exact same tools as ``sap-mcp``.

    python3 extensions/claude_mcp/dxt/build_dxt.py
    # -> dist/secure-ai-pipeline-<version>.dxt
    #    Claude Desktop -> Settings -> Extensions -> Install from file -> pick the .dxt

Build on the machine + Python you'll install on. The vendored deps include a
compiled binary (pydantic-core), so the build host must match the host Claude
Desktop runs the server on — which, on your own laptop, it does.

(Claude Code / Codex / Cursor don't need this — they use `pipx install … ; sap-mcp`.
 The .dxt is purely the one-click path for Claude *Desktop*.)
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

DXT_DIR = Path(__file__).resolve().parent          # extensions/claude_mcp/dxt
PKG = DXT_DIR.parent                                 # extensions/claude_mcp
ROOT = DXT_DIR.parents[2]                            # repo root
DIST = ROOT / "dist"
BUILD = ROOT / "build" / "dxt"

# Claude Desktop runs this. Keep the package importable as a top-level `claude_mcp`
# and prepend the vendored deps so it needs nothing pre-installed.
_BOOTSTRAP = '''\
"""Claude Desktop entry point: serve the secure-ai-pipeline MCP tools over stdio."""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "lib"))   # vendored deps (mcp, requests, ...)
sys.path.insert(0, _HERE)                         # the `claude_mcp` package

from claude_mcp import mcp_server

if __name__ == "__main__":
    mcp_server.main()
'''


def _version() -> str:
    m = re.search(r'version="([^"]+)"', (ROOT / "setup.py").read_text(encoding="utf-8"))
    return m.group(1) if m else "0.0.0"


def main() -> int:
    version = _version()
    if BUILD.exists():
        shutil.rmtree(BUILD)
    server = BUILD / "server"
    server.mkdir(parents=True)

    # 1. the package (incl. the bundled _rules_data.py) as a top-level `claude_mcp`,
    #    minus the build tooling and caches.
    shutil.copytree(
        PKG, server / "claude_mcp",
        ignore=shutil.ignore_patterns("dxt", "__pycache__", "*.pyc"),
    )
    # 2. bootstrap entry point + 3. vendored runtime deps
    (server / "main.py").write_text(_BOOTSTRAP, encoding="utf-8")
    print("Vendoring dependencies (mcp, requests) — this downloads wheels...")
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "--quiet", "--target",
         str(server / "lib"), "mcp>=1.2", "requests>=2.31"],
        check=True,
    )
    # 4. manifest with the real version stamped in
    manifest = (DXT_DIR / "manifest.json").read_text(encoding="utf-8")
    (BUILD / "manifest.json").write_text(
        manifest.replace("__VERSION__", version), encoding="utf-8")

    # 5. zip it up as the .dxt
    DIST.mkdir(exist_ok=True)
    out = DIST / f"secure-ai-pipeline-{version}.dxt"
    out.unlink(missing_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for path in sorted(BUILD.rglob("*")):
            if path.is_file():
                z.write(path, path.relative_to(BUILD))

    print(f"\nBuilt {out.relative_to(ROOT)} ({out.stat().st_size / 1_048_576:.1f} MB)")
    print("Install: Claude Desktop -> Settings -> Extensions -> Install from file.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
