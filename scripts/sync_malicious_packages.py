#!/usr/bin/env python3
"""
Refresh the offline malicious-package mirror from OSV.

Downloads OSV's bulk PyPI + npm exports, keeps only the `MAL-` advisories (the
OpenSSF malicious-packages feed mirrored into OSV), and writes the affected
package names to scripts/scanners/packages/malicious_mirror.json — which the
anti-slopsquatting guard checks OFFLINE before install.

Run weekly in CI (see .github/workflows/sync-malicious-packages.yml). Best-effort:
on any download/parse failure it keeps the existing mirror rather than wiping it.

    python scripts/sync_malicious_packages.py

stdlib only.
"""

from __future__ import annotations

import io
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scanners.packages.lockfile_integrity import MALICIOUS_DENYLIST  # noqa: E402

MIRROR = Path(__file__).resolve().parent / "scanners" / "packages" / "malicious_mirror.json"

# OSV bulk exports (one JSON per advisory, zipped per ecosystem).
SOURCES = {
    "pypi": "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
    "npm": "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
}


def _norm(name: str) -> str:
    return (name or "").strip().lower()


def _fetch_mal_names(url: str) -> set:
    """Return normalised package names from every MAL- advisory in an OSV zip."""
    names: set = set()
    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected -- URL is a hardcoded, trusted OSV host (a public threat-feed), not user input.
    with urllib.request.urlopen(url, timeout=120) as resp:
        blob = resp.read()
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        for info in zf.infolist():
            if not info.filename.endswith(".json"):
                continue
            try:
                adv = json.loads(zf.read(info.filename))
            except (json.JSONDecodeError, ValueError):
                continue
            ids = [adv.get("id", "")] + list(adv.get("aliases", []) or [])
            if not any(str(i).startswith("MAL-") for i in ids):
                continue
            for aff in adv.get("affected", []) or []:
                n = _norm((aff.get("package") or {}).get("name"))
                if n:                       # normalize THEN check — drops whitespace-only names
                    names.add(n)
    return names


def main(argv=None) -> int:
    try:
        existing = json.loads(MIRROR.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        existing = {"pypi": [], "npm": []}

    out = {"_comment": existing.get("_comment", ""), "version": 1,
           "source": "https://github.com/ossf/malicious-packages (OSV MAL- advisories)",
           "generated": "ci-sync"}
    changed = False
    for eco, url in SOURCES.items():
        try:
            fetched = _fetch_mal_names(url)
        except Exception as exc:  # network/parse failure → keep what we have
            print(f"  [warn] {eco}: sync failed ({exc.__class__.__name__}); keeping existing")
            out[eco] = sorted(existing.get(eco, []))
            continue
        # Never SHRINK below the committed seed: union the fetched feed with BOTH the
        # existing mirror AND the in-code MALICIOUS_DENYLIST, so curated IOCs always
        # survive even if the mirror file was emptied/corrupted by a prior bad sync.
        seed = {_norm(n) for n in MALICIOUS_DENYLIST.get(eco, set())}
        merged = sorted(set(fetched) | {_norm(n) for n in existing.get(eco, [])} | seed)
        if merged != sorted(existing.get(eco, [])):
            changed = True
        out[eco] = merged
        print(f"  {eco}: {len(merged)} malicious names")

    MIRROR.write_text(json.dumps(out, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"  {'updated' if changed else 'unchanged'}: {MIRROR.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
