#!/usr/bin/env python3
"""
Anti-slopsquatting guard.

Scans all Python and JS/TS files in the repo for imported package names,
then verifies each one actually exists on PyPI (for Python) or npm (for JS/TS).
Exits 1 if any hallucinated / non-existent package is found.

Requires: requests  (pip install requests)
"""

import ast
import json
import re
import sys
import urllib.request
from pathlib import Path

# ── Stdlib packages that are never on PyPI ──────────────────────────────────
PYTHON_STDLIB = {
    "os", "sys", "re", "io", "abc", "ast", "csv", "json", "math", "time",
    "enum", "copy", "uuid", "hmac", "hash", "stat", "glob", "shutil",
    "queue", "array", "heapq", "struct", "socket", "select", "signal",
    "string", "struct", "random", "logging", "hashlib", "pathlib", "urllib",
    "typing", "decimal", "inspect", "functools", "itertools", "datetime",
    "calendar", "textwrap", "threading", "multiprocessing", "subprocess",
    "contextlib", "collections", "dataclasses", "configparser", "http",
    "html", "xml", "email", "smtplib", "ftplib", "telnetlib", "ssl",
    "base64", "binascii", "codecs", "pickle", "shelve", "sqlite3", "zlib",
    "gzip", "bz2", "lzma", "zipfile", "tarfile", "tempfile", "platform",
    "traceback", "warnings", "unittest", "doctest", "pdb", "profile",
    "timeit", "argparse", "getopt", "getpass", "readline", "rlcompleter",
    "curses", "tkinter", "webbrowser", "gc", "weakref", "ctypes",
    "concurrent", "asyncio", "selectors", "mmap", "msvcrt", "winreg",
    "winsound", "posix", "pwd", "grp", "termios", "tty", "pty", "fcntl",
    "pipes", "resource", "syslog", "optparse", "imp", "importlib",
    "builtins", "__future__", "types", "numbers", "fractions", "cmath",
    "statistics", "secrets", "token", "tokenize", "keyword", "dis",
    "marshal", "compileall", "py_compile", "zipimport", "pkgutil",
    "modulefinder", "runpy", "site", "sysconfig",
}


def extract_python_imports(path: Path) -> set[str]:
    """Return top-level package names imported in a Python file."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
    except SyntaxError:
        return set()
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module.split(".")[0])
    return names - PYTHON_STDLIB


def extract_js_imports(path: Path) -> set[str]:
    """Return package names from require/import statements in JS/TS files."""
    text = path.read_text(encoding="utf-8", errors="ignore")
    patterns = [
        r'require\(["\'](@?[^./"\'][^"\']*)["\']',   # require('pkg')
        r'from\s+["\'](@?[^./"\'][^"\']*)["\']',      # import ... from 'pkg'
    ]
    names = set()
    for pat in patterns:
        for m in re.finditer(pat, text):
            pkg = m.group(1)
            # Normalise scoped packages: @scope/name → @scope/name (keep as-is)
            names.add(pkg)
    return names


def pypi_exists(pkg: str) -> bool:
    url = f"https://pypi.org/pypi/{pkg}/json"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return resp.status == 200
    except Exception:
        return False


def npm_exists(pkg: str) -> bool:
    encoded = pkg.replace("/", "%2F")
    url = f"https://registry.npmjs.org/{encoded}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return resp.status == 200
    except Exception:
        return False


def main() -> int:
    repo_root = Path(__file__).parent.parent
    failures: list[str] = []

    # ── Python files ────────────────────────────────────────────────────────
    for py_file in repo_root.rglob("*.py"):
        # Skip virtual envs and node_modules
        if any(p in py_file.parts for p in ("venv", ".venv", "node_modules", ".git")):
            continue
        for pkg in extract_python_imports(py_file):
            if not pypi_exists(pkg):
                print(f"  [FAIL] Python package not found on PyPI: '{pkg}'  ({py_file})")
                failures.append(pkg)
            else:
                print(f"  [ OK ] {pkg}")

    # ── JS / TS files ────────────────────────────────────────────────────────
    for js_file in repo_root.rglob("*.{js,ts,jsx,tsx,mjs,cjs}"):
        if any(p in js_file.parts for p in ("node_modules", ".git", "dist", "build")):
            continue
        for pkg in extract_js_imports(js_file):
            if not npm_exists(pkg):
                print(f"  [FAIL] npm package not found: '{pkg}'  ({js_file})")
                failures.append(pkg)
            else:
                print(f"  [ OK ] {pkg}")

    if failures:
        print(f"\n❌  {len(failures)} hallucinated / non-existent package(s) found:")
        for f in failures:
            print(f"       - {f}")
        print("\nThis is a hard block. Remove or replace these imports before merging.")
        return 1

    print("\n✅  All packages verified on their registries.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
