#!/usr/bin/env python3
"""
Install the OSS scanners the registry knows about — best-effort, for CI.

Reads ``ci_install`` from every registered ToolAdapter, so adding a scanner file
under scripts/scanners/ (with a ci_install) makes it install AND run in the
GitHub Action automatically: one more piece of the "edit the scanners folder,
every channel updates" guarantee. A failed install is logged and skipped — a
missing tool just means that scanner is absent, never a failed build.

pip-installable tools are batched into one install for speed; binary installers
(curl/bash one-liners) run individually. Already-present tools are skipped.

    python scripts/install_scanners.py            # install everything missing
    python scripts/install_scanners.py --print    # just print the plan, install nothing

stdlib only.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from scanners import registry  # noqa: E402


def plan(deep=False):
    """Return (pip_packages, [(name, shell_cmd)]) for every missing tool.
    Heavy tools (GuardDog etc.) are installed only with deep=True."""
    pip_pkgs, others = [], []
    for a in registry.all_adapters():
        if not a.ci_install or a.available():
            continue
        if a.heavy and not deep:
            continue
        cmd = a.ci_install.strip()
        if cmd.startswith("pip install "):
            pip_pkgs += cmd[len("pip install "):].split()
        else:
            others.append((a.name, cmd))
    return pip_pkgs, others


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--print", action="store_true", dest="dry",
                   help="Print the install plan without running it.")
    p.add_argument("--deep", action="store_true",
                   help="Also install heavy scanners (e.g. GuardDog).")
    args = p.parse_args(argv)

    pip_pkgs, others = plan(deep=args.deep)

    if args.dry:
        if pip_pkgs:
            print("pip install " + " ".join(pip_pkgs))
        for name, cmd in others:
            print(f"# {name}\n{cmd}")
        return 0

    if pip_pkgs:
        print(f"::group::pip install {' '.join(pip_pkgs)}")
        subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", *pip_pkgs],
                       check=False)
        print("::endgroup::")
    for name, cmd in others:
        print(f"::group::install {name}")
        subprocess.run(cmd, shell=True, check=False)  # noqa: S602  best-effort CI install
        print("::endgroup::")

    installed = sorted(n for n, ok in registry.detect().items() if ok)
    missing = sorted(n for n, ok in registry.detect().items() if not ok)
    print("Installed scanners:", ", ".join(installed) or "(none)")
    if missing:
        print("Not installed (optional):", ", ".join(missing))
    return 0


if __name__ == "__main__":
    sys.exit(main())
