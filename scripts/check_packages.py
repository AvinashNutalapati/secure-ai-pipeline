#!/usr/bin/env python3
"""
Anti-slopsquatting guard.

Scans Python and JS/TS files in a repository for imported package names, then
verifies each one actually exists on PyPI (Python) or npm (JS/TS). AI models
invent plausible-but-nonexistent package names; an attacker can pre-register the
name and ship malware. This catches that before `pip install` / `npm install`.

Gating:
  - package not found on its registry  -> BLOCK (exit 1)
  - registry unreachable (network/5xx) -> WARN  (never blocks the build)

False-positive controls:
  - stdlib modules are ignored
  - relative imports (`from . import x`) are ignored
  - first-party / local modules (a dir with __init__.py, or a top-level .py)
    are ignored
  - common import->distribution aliases are mapped (PIL->pillow, yaml->PyYAML…)

Usage:
    python check_packages.py [ROOT] [--json OUT]

ROOT defaults to $GITHUB_WORKSPACE, then the current directory. Passing ROOT
explicitly is important inside the GitHub Action, where the script lives in the
action's own checkout, not the caller's repository.

Requires: stdlib only.
"""

import argparse
import ast
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# ── Stdlib packages that are never on PyPI ──────────────────────────────────
PYTHON_STDLIB = {
    "os", "sys", "re", "io", "abc", "ast", "csv", "json", "math", "time",
    "enum", "copy", "uuid", "hmac", "hash", "stat", "glob", "shutil",
    "queue", "array", "heapq", "struct", "socket", "select", "signal",
    "string", "struct", "random", "logging", "hashlib", "pathlib", "urllib",
    "fnmatch", "linecache", "filecmp", "fileinput", "difflib", "bisect",
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
    "modulefinder", "runpy", "site", "sysconfig", "venv", "ensurepip",
    "shlex", "operator", "errno", "locale", "unicodedata", "pprint",
    "atexit", "ipaddress", "zoneinfo", "graphlib", "sched", "wave",
}

# ── Import name → PyPI distribution name (common mismatches) ─────────────────
# Without this the guard false-positives on packages whose import name differs
# from the name you `pip install`.
IMPORT_TO_PYPI = {
    "PIL": "pillow",
    "yaml": "PyYAML",
    "cv2": "opencv-python",
    "sklearn": "scikit-learn",
    "dotenv": "python-dotenv",
    "bs4": "beautifulsoup4",
    "git": "GitPython",
    "jose": "python-jose",
    "dateutil": "python-dateutil",
    "attr": "attrs",
    "OpenSSL": "pyOpenSSL",
    "Crypto": "pycryptodome",
    "psycopg2": "psycopg2-binary",
    "serial": "pyserial",
    "yaml_": "PyYAML",
    "mcp": "mcp",
}

# Node.js core modules — never on npm (the JS analog of PYTHON_STDLIB).
NODE_BUILTINS = {
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console",
    "constants", "crypto", "dgram", "diagnostics_channel", "dns", "domain",
    "events", "fs", "fs/promises", "http", "http2", "https", "inspector",
    "module", "net", "os", "path", "perf_hooks", "process", "punycode",
    "querystring", "readline", "repl", "stream", "stream/promises",
    "string_decoder", "timers", "timers/promises", "tls", "trace_events", "tty",
    "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib",
}
# Editor/host-provided modules that are not installable from npm.
HOST_MODULES = {"vscode"}

JS_GLOBS = ("*.js", "*.ts", "*.jsx", "*.tsx", "*.mjs", "*.cjs")
SKIP_DIRS = {
    "venv", ".venv", "env", ".env", "node_modules", ".git", "dist", "build",
    "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", "site-packages",
    ".next", "out", "coverage",
}


def _skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def extract_python_imports(path: Path) -> set[str]:
    """Return top-level, non-stdlib package names imported in a Python file.

    Relative imports (`from . import x`, `from .mod import y`) are excluded
    because `node.module` is None / handled by `level`.
    """
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
            # level > 0 means a relative import — skip it entirely.
            if node.level and node.level > 0:
                continue
            if node.module:
                names.add(node.module.split(".")[0])
    return names - PYTHON_STDLIB


def extract_js_imports(path: Path) -> set[str]:
    """Return external package names from require/import statements (skips
    relative paths starting with . or /)."""
    text = path.read_text(encoding="utf-8", errors="ignore")
    patterns = [
        r'require\(\s*["\'](@?[^./"\'][^"\']*)["\']',   # require('pkg')
        r'from\s+["\'](@?[^./"\'][^"\']*)["\']',         # import ... from 'pkg'
        r'import\s+["\'](@?[^./"\'][^"\']*)["\']',        # import 'pkg'
    ]
    names = set()
    for pat in patterns:
        for m in re.finditer(pat, text):
            names.add(_npm_base(m.group(1)))
    return names


def _npm_base(spec: str) -> str:
    """Reduce an import specifier to its installable package name.
    '@scope/pkg/sub' -> '@scope/pkg'; 'pkg/sub' -> 'pkg'."""
    if spec.startswith("@"):
        parts = spec.split("/")
        return "/".join(parts[:2])
    return spec.split("/")[0]


def discover_first_party(root: Path) -> set[str]:
    """Names that resolve to local code and must not be checked on a registry:
    any directory containing __init__.py, plus the stem of every .py file in the
    repo (a `foo.py` anywhere means `import foo` resolves locally, not from PyPI)."""
    names: set[str] = set()
    for init in root.rglob("__init__.py"):
        if _skip(init):
            continue
        names.add(init.parent.name)
    for py in root.rglob("*.py"):
        if _skip(py):
            continue
        names.add(py.stem)
    # JS first-party: the package.json "name", if present.
    pkg_json = root / "package.json"
    if pkg_json.is_file():
        try:
            name = json.loads(pkg_json.read_text(encoding="utf-8")).get("name")
            if name:
                names.add(_npm_base(name))
        except (json.JSONDecodeError, OSError):
            pass
    return names


# ── Registry existence checks (tri-state, with retry + cache) ───────────────
# Returns one of: "exists" | "missing" | "error"
_STATUS_CACHE: dict[tuple[str, str], str] = {}


def _query(url: str, *, attempts: int = 3, backoff: float = 0.5) -> str:
    for i in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                return "exists" if resp.status == 200 else "missing"
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return "missing"
            # 5xx / rate limit → retry
        except (urllib.error.URLError, OSError, ValueError):
            # ValueError covers http.client.InvalidURL from malformed import
            # names — report "error" (WARN), never crash the gate.
            pass
        if i < attempts - 1 and backoff:
            time.sleep(backoff * (i + 1))
    # Only confirmed 404s return "missing" above; anything else after all
    # attempts is a registry problem, which must WARN rather than hard-block.
    return "error"


def pypi_status(pkg: str, *, attempts: int = 3, backoff: float = 0.5) -> str:
    key = ("pypi", pkg)
    if key not in _STATUS_CACHE:
        _STATUS_CACHE[key] = _query(
            f"https://pypi.org/pypi/{pkg}/json", attempts=attempts, backoff=backoff
        )
    return _STATUS_CACHE[key]


def npm_status(pkg: str, *, attempts: int = 3, backoff: float = 0.5) -> str:
    key = ("npm", pkg)
    if key not in _STATUS_CACHE:
        encoded = pkg.replace("/", "%2F")
        _STATUS_CACHE[key] = _query(
            f"https://registry.npmjs.org/{encoded}", attempts=attempts, backoff=backoff
        )
    return _STATUS_CACHE[key]


# Back-compat thin booleans (single attempt — used by older callers/tests).
def pypi_exists(pkg: str) -> bool:
    return pypi_status(pkg, attempts=1, backoff=0) == "exists"


def npm_exists(pkg: str) -> bool:
    return npm_status(pkg, attempts=1, backoff=0) == "exists"


def scan(root: Path) -> dict:
    """Scan a repo tree; return {'blocked': [...], 'warnings': [...], 'ok': [...]}."""
    first_party = discover_first_party(root)
    blocked: list[dict] = []
    warnings: list[dict] = []
    ok: list[str] = []

    def record(import_name: str, dist_name: str, status: str, registry: str, where: Path):
        rel = str(where.relative_to(root)) if where.is_relative_to(root) else str(where)
        if status == "missing":
            blocked.append({"package": dist_name, "import": import_name,
                            "registry": registry, "file": rel})
        elif status == "error":
            warnings.append({"package": dist_name, "import": import_name,
                             "registry": registry, "file": rel,
                             "reason": "registry unreachable"})
        else:
            ok.append(dist_name)

    # Collect every (import, distribution, registry, file) first, then resolve
    # the unique lookups concurrently — one HTTP probe per unique package
    # instead of a serial walk.
    pending: list[tuple[str, str, str, Path]] = []

    # Python
    for py in root.rglob("*.py"):
        if _skip(py):
            continue
        for name in extract_python_imports(py):
            if name in first_party:
                continue
            dist = IMPORT_TO_PYPI.get(name, name)
            pending.append((name, dist, "pypi", py))

    # JS / TS — one rglob per extension (brace globs do NOT expand in rglob).
    for pattern in JS_GLOBS:
        for js in root.rglob(pattern):
            if _skip(js):
                continue
            for name in extract_js_imports(js):
                if name.startswith("node:"):
                    # The `node:` prefix is reserved for Node core modules and
                    # can never resolve to an npm package — nothing to verify.
                    continue
                if name in first_party or name in NODE_BUILTINS or name in HOST_MODULES:
                    continue
                pending.append((name, name, "npm", js))

    unique = {(reg, dist) for _, dist, reg, _ in pending}
    statuses: dict[tuple[str, str], str] = {}
    if unique:
        def resolve(item: tuple[str, str]) -> tuple[tuple[str, str], str]:
            reg, dist = item
            return item, (pypi_status(dist) if reg == "pypi" else npm_status(dist))

        with ThreadPoolExecutor(max_workers=min(8, len(unique))) as pool:
            statuses = dict(pool.map(resolve, sorted(unique)))

    for import_name, dist, reg, where in pending:
        record(import_name, dist, statuses[(reg, dist)], reg, where)

    return {"blocked": blocked, "warnings": warnings, "ok": sorted(set(ok))}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Anti-slopsquatting package guard.")
    parser.add_argument(
        "root",
        nargs="?",
        default=os.environ.get("GITHUB_WORKSPACE", os.getcwd()),
        help="Repository root to scan (default: $GITHUB_WORKSPACE or cwd).",
    )
    parser.add_argument("--json", metavar="OUT", help="Write findings as JSON to OUT.")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    result = scan(root)

    for w in result["warnings"]:
        print(f"  [WARN] {w['registry']} unreachable for '{w['package']}' ({w['file']})")
    for b in result["blocked"]:
        # Precomputed (not a nested f-string): same-quote nesting needs PEP 701,
        # which is Python 3.12+ — this file must run on 3.10.
        imported_as = f" (imported as {b['import']})" if b["import"] != b["package"] else ""
        print(f"  [FAIL] {b['registry']} package not found: '{b['package']}'"
              f"{imported_as}  ({b['file']})")

    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2), encoding="utf-8")

    if result["blocked"]:
        print(f"\n❌  {len(result['blocked'])} hallucinated / non-existent package(s). "
              "Hard block — remove or fix these before merging.")
        return 1

    if result["warnings"]:
        print(f"\n⚠️  Verified with {len(result['warnings'])} registry warning(s) "
              "(network issues — not blocking).")
    print(f"\n✅  All resolvable packages verified ({len(result['ok'])} ok).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
