"""
Anti-slopsquatting / package-existence scanner — the dependency-trust check in
its scan-type home (``scanners.packages.slopsquatting``). THIS is the real
implementation; ``scripts/check_packages.py`` is a thin entry-point shim over it,
so ``python scripts/check_packages.py`` (the GitHub Action, the pre-commit hook)
and ``import check_packages`` (run_pipeline, scan_all, blast_radius, tests) keep
working unchanged.

Scans Python and JS/TS files for imported package names, then verifies each one
actually exists on PyPI (Python) or npm (JS/TS). AI models invent plausible-but-
nonexistent package names; an attacker pre-registers the name and ships malware.
This catches that before `pip install` / `npm install`.

Gating:
  - package not found on its registry  -> BLOCK (exit 1)
  - registry unreachable (network/5xx) -> WARN  (never blocks the build)

False-positive controls: stdlib modules, relative imports, first-party/local
modules, and common import->distribution aliases (PIL->pillow, yaml->PyYAML…)
are all handled.

Requires: stdlib only.
"""

import argparse
import ast
import http.client
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
# Use the running Python's own authoritative stdlib list (sys.stdlib_module_names,
# 3.10+): complete and version-accurate, so the guard never false-blocks a real
# stdlib import. A hand-maintained set silently omitted modules (socketserver,
# wsgiref, xmlrpc, tomllib, contextvars, …) and reported them as hallucinated.
# Union a handful of removed-but-historically-valid names so older code still
# scans clean on newer interpreters.
PYTHON_STDLIB = set(sys.stdlib_module_names) | {
    "imp", "telnetlib", "cgi", "cgitb", "nntplib", "smtpd", "asynchat", "asyncore",
    "audioop", "chunk", "crypt", "imghdr", "mailcap", "msilib", "nis", "ossaudiodev",
    "pipes", "sndhdr", "spwd", "sunau", "uu", "xdrlib",
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


# ── Typosquat near-miss (Damerau-Levenshtein) ───────────────────────────────

def _dl_distance(a: str, b: str, *, max_d: int = 2) -> int:
    """Damerau-Levenshtein edit distance (incl. adjacent transposition), capped:
    returns max_d+1 once it's clearly over the cap (cheap early-out on length)."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > max_d:
        return max_d + 1
    la, lb = len(a), len(b)
    prev2 = list(range(lb + 1))
    prev = None
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        best = cur[0]
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev2[j] + 1, cur[j - 1] + 1, prev2[j - 1] + cost)
            if (i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]):
                cur[j] = min(cur[j], (prev[j - 2] if prev else prev2[j - 2]) + 1)
            best = min(best, cur[j])
        if best > max_d:
            return max_d + 1
        prev, prev2 = prev2, cur
    return prev2[lb]


def typosquat_match(name: str, registry: str):
    """The popular package `name` is a 1-2 edit near-miss of (a classic typosquat
    shape), or None. `name` must NOT itself be popular. Distance 2 is only allowed
    for longer names to keep short-name false positives down."""
    from scanners.packages.popular_packages import popular_for
    norm = (name or "").lower().replace("-", "_")
    popular = popular_for(registry)
    if not norm or norm in popular:
        return None
    best, best_d = None, 3
    for cand in popular:
        d = _dl_distance(norm, cand, max_d=2)
        if d < best_d:
            best, best_d = cand, d
            if d == 1:
                break
    if best_d == 1 or (best_d == 2 and len(norm) >= 6):
        return best
    return None


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


# A registry-checkable package specifier: optional @scope/, no whitespace or
# control characters, bounded length (npm's max is 214). Anything else is a
# parser artifact — e.g. a string literal that ran across lines — and must
# never become a registry lookup, because building a URL from it raises
# http.client.InvalidURL.
_VALID_PKG_NAME = re.compile(r"^@?[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)?$")


def _is_checkable(name: str) -> bool:
    return bool(name) and len(name) <= 214 and _VALID_PKG_NAME.match(name) is not None


def extract_js_imports(path: Path) -> set[str]:
    """Return external package names from require/import statements.

    Specifiers are matched within a single line — the character classes exclude
    whitespace, so a string that spans lines can't be captured — and each
    candidate is validated, so relative paths and malformed blobs never become
    registry lookups.
    """
    text = path.read_text(encoding="utf-8", errors="ignore")
    patterns = [
        r'require\(\s*["\'](@?[^./"\'\s][^"\'\s]*)["\']',   # require('pkg')
        r'from\s+["\'](@?[^./"\'\s][^"\'\s]*)["\']',         # import ... from 'pkg'
        r'import\s+["\'](@?[^./"\'\s][^"\'\s]*)["\']',        # import 'pkg'
    ]
    names = set()
    for pat in patterns:
        for m in re.finditer(pat, text):
            base = _npm_base(m.group(1))
            if _is_checkable(base):
                names.add(base)
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
# ts (epoch seconds) for disk-loaded cache entries, so TTL actually expires
# instead of being refreshed every run.
_CACHE_META: dict[tuple[str, str], float] = {}

# On-disk cache so repeated runs (and CI, if the file is cached) don't re-probe
# every package name. Only DEFINITIVE verdicts are persisted; "error" never is.
CACHE_REL = ".secure-ai-pipeline/registry-cache.json"
_CACHE_TTL = 7 * 24 * 3600  # package existence is stable; 7-day TTL


def _cache_path(root) -> Path:
    return Path(root) / CACHE_REL


def load_cache(root) -> None:
    """Seed the in-memory status cache from disk (best-effort, TTL-filtered)."""
    try:
        data = json.loads(_cache_path(root).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return
    now = time.time()
    for key, val in (data.get("entries") or {}).items():
        try:
            status, ts = val
            reg, _, name = key.partition(":")
        except (ValueError, TypeError):
            continue
        if status in ("exists", "missing") and reg and name and (now - ts) < _CACHE_TTL:
            _STATUS_CACHE[(reg, name)] = status
            _CACHE_META[(reg, name)] = ts


def save_cache(root) -> None:
    """Persist definitive verdicts, preserving original timestamps so TTL works.

    Only writes when the pipeline's `.secure-ai-pipeline/` dir ALREADY exists (i.e.
    the repo opted into the pipeline). It never creates that dir, so scanning an
    arbitrary tree (the `posture`/check_packages paths) leaves no surprise files."""
    cache_dir = Path(root) / ".secure-ai-pipeline"
    if not cache_dir.is_dir():
        return
    now = time.time()
    entries = {f"{reg}:{name}": [status, _CACHE_META.get((reg, name), now)]
               for (reg, name), status in _STATUS_CACHE.items()
               if status in ("exists", "missing")}
    if not entries:
        return
    try:
        (cache_dir / "registry-cache.json").write_text(
            json.dumps({"version": 1, "entries": entries}, indent=2,
                       sort_keys=True) + "\n", encoding="utf-8")
    except OSError:
        pass


def _query(url: str, *, attempts: int = 3, backoff: float = 0.5) -> str:
    for i in range(attempts):
        try:
            # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected -- URL is a hardcoded registry host + a validated package name; this guard exists precisely to vet package names.
            with urllib.request.urlopen(url, timeout=10) as resp:
                return "exists" if resp.status == 200 else "missing"
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return "missing"
            # 5xx / rate limit → retry
        except (urllib.error.URLError, OSError, ValueError,
                http.client.HTTPException):
            # http.client.InvalidURL (a name with control chars) is an
            # HTTPException, NOT a ValueError — catch it so a malformed import
            # can never crash the gate; report "error" (WARN) instead.
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
    load_cache(root)  # reuse prior definitive verdicts (offline-friendly, faster CI)
    first_party = discover_first_party(root)
    blocked: list[dict] = []
    warnings: list[dict] = []
    suspect: list[dict] = []
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
            # It EXISTS but is 1-2 edits from a hugely popular name → likely a
            # typosquat squatter you actually installed.
            near = typosquat_match(dist_name, registry)
            if near:
                suspect.append({"package": dist_name, "import": import_name,
                                "registry": registry, "file": rel, "suggestion": near})

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

    save_cache(root)  # persist definitive verdicts for the next run
    return {"blocked": blocked, "warnings": warnings, "suspect": suspect,
            "ok": sorted(set(ok))}


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
