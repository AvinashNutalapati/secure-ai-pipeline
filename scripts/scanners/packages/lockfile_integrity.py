"""
secure-ai-pipeline:rule-source — excluded from the built-in scan.

Offline supply-chain checks that complement the (network) anti-slopsquatting guard:

  1. Lockfile integrity — npm package-lock.json entries that resolve to a registry
     tarball but carry no `integrity` hash (tampering / cache-poisoning risk).
  2. Known-malicious denylist — a bundled set of package names from public OSV
     `MAL-` / OpenSSF malicious-packages advisories, matched against imports and
     lockfiles with no network. Extend MALICIOUS_DENYLIST from an OSV mirror in CI.

Both run even with --offline. Returns normalised finding dicts (scan_type packages).

stdlib only.
"""

from __future__ import annotations

import json
from pathlib import Path

from scanners.base import skip
from scanners.registry import finding

# A small, conservatively-curated seed of names from WELL-DOCUMENTED public
# malicious-package incidents only — every entry maps to a real reported attack, so
# a CRITICAL "malicious package" verdict is never cried-wolf on a legitimate package.
# Extend from the OpenSSF malicious-packages / OSV MAL- feed in CI. Normalised
# lowercase. Exact-identifier match only (a scoped @org/name is a DIFFERENT package
# and is deliberately NOT matched by basename, which would false-flag legitimate orgs).
MALICIOUS_DENYLIST = {
    "pypi": {
        "colourama",          # colorama typosquat (PyPI)
        "jeilyfish",          # jeIlyfish — 2019 SSH/credential stealer
        "python3-dateutil",   # 2019 typosquat paired with jeIlyfish
        "djanga",             # django typosquat
        "ssh-decorate",       # 2018 SSH-key stealer
    },
    "npm": {
        "crossenv",           # 2017 cross-env typosquat campaign
        "cross-env.js",       # 2017 cross-env typosquat campaign
        "node-fabric",        # 2017 typosquat campaign
        "fabric-js",          # 2017 typosquat campaign
        "flatmap-stream",     # 2018 event-stream supply-chain compromise
        "electron-native-notify",  # 2019 Komodo wallet attack
    },
}


def _norm(name: str) -> str:
    return (name or "").strip().lower()


# The effective denylist = the in-code seed ∪ the bundled OSV-MAL mirror
# (malicious_mirror.json, refreshed weekly in CI). Loaded once and cached.
_MIRROR_PATH = Path(__file__).with_name("malicious_mirror.json")
_DENYLIST_CACHE = None


def _denylist_for(registry: str) -> frozenset:
    global _DENYLIST_CACHE
    if _DENYLIST_CACHE is None:
        merged = {"pypi": set(MALICIOUS_DENYLIST["pypi"]),
                  "npm": set(MALICIOUS_DENYLIST["npm"])}
        try:
            data = json.loads(_MIRROR_PATH.read_text(encoding="utf-8"))
            for eco in ("pypi", "npm"):
                merged[eco] |= {_norm(n) for n in (data.get(eco) or []) if n}
        except (OSError, json.JSONDecodeError, ValueError):
            pass  # mirror missing/corrupt → fall back to the in-code seed
        # frozenset so callers get an immutable view and can't corrupt the cache.
        _DENYLIST_CACHE = {k: frozenset(v) for k, v in merged.items()}
    return _DENYLIST_CACHE.get(registry, frozenset())


def _lockfile_integrity(root: Path) -> list:
    out = []
    for lock in root.rglob("package-lock.json"):
        if skip(lock):
            continue
        try:
            data = json.loads(lock.read_text(encoding="utf-8", errors="ignore"))
        except (json.JSONDecodeError, OSError):
            continue
        rel = str(lock.relative_to(root)) if lock.is_relative_to(root) else str(lock)
        pkgs = data.get("packages")
        if not isinstance(pkgs, dict):
            continue  # v1 lockfile (no per-package integrity map) — skip quietly
        missing = []
        for path, meta in pkgs.items():
            if not path or not isinstance(meta, dict):
                continue  # "" is the root project
            # A registry dependency has a resolved tarball URL; it should also pin
            # an integrity hash. Local/link deps legitimately have neither, and
            # BUNDLED deps ship inside the parent tarball (no own integrity) — both
            # are excluded so they aren't false-flagged.
            if (meta.get("resolved", "").startswith("http")
                    and not meta.get("integrity")
                    and not meta.get("inBundle") and not meta.get("bundled")):
                missing.append(path.split("node_modules/")[-1])
        if missing:
            sample = ", ".join(sorted(set(missing))[:5])
            out.append(finding(
                "HIGH", f"Lockfile entries missing integrity hashes ({rel})",
                f"{len(missing)} dependency entr(ies) in {rel} resolve to a registry "
                f"tarball with no integrity hash (e.g. {sample}). Without it, npm "
                "can't detect a tampered/cache-poisoned package.",
                rel, 0,
                "Regenerate the lockfile (npm install) so every dependency pins an "
                "integrity (SRI) hash; commit the result.",
                "lockfile-integrity", rule_key="lockfile-missing-integrity"))
    return out


def _denylist(root: Path) -> list:
    """Match imported / locked package names against the malicious denylist."""
    from scanners.packages import slopsquatting as cp  # import extractors (canonical path)
    out = []
    seen = set()

    def flag(name, registry, where):
        key = (registry, _norm(name), where)
        if _norm(name) in _denylist_for(registry) and key not in seen:
            seen.add(key)
            out.append(finding(
                "CRITICAL", f"MALICIOUS PACKAGE: {name} ({registry})",
                f"'{name}' appears on the known-malicious advisory denylist (OSV MAL-/"
                f"OpenSSF). It was referenced in {where}.",
                where, 0,
                "Remove this dependency NOW and audit anything it may have run; rotate "
                "any credentials it could have accessed.",
                "built-in (denylist)", vuln_id=f"MAL-DENYLIST-{_norm(name)}",
                rule_key="pkg-known-malicious"))

    for py in root.rglob("*.py"):
        if cp._skip(py):
            continue
        rel = str(py.relative_to(root)) if py.is_relative_to(root) else str(py)
        for name in cp.extract_python_imports(py):
            flag(cp.IMPORT_TO_PYPI.get(name, name), "pypi", rel)
    for pattern in cp.JS_GLOBS:
        for js in root.rglob(pattern):
            if cp._skip(js):
                continue
            rel = str(js.relative_to(root)) if js.is_relative_to(root) else str(js)
            for name in cp.extract_js_imports(js):
                flag(name, "npm", rel)
    return out


def scan(root: Path) -> list:
    """Offline supply-chain findings (normalised dicts). Safe to run with --offline."""
    return _lockfile_integrity(root) + _denylist(root)
