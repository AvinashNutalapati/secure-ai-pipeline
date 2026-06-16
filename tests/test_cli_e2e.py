"""End-to-end tests for the npm/npx distribution path.

These exercise the channel a developer actually uses — `npx secure-ai-pipeline` —
rather than importing the Python modules directly. They guard the two things that
unit tests can't see:

  1. Packaging: does `npm pack` bundle EVERY Python file the CLI shells out to?
     A drift in package.json's `files` glob silently ships a broken package that
     dies with "scanner missing" on the user's machine. The dry-run pack test
     catches that without a slow install.

  2. The real path: pack → install into a clean consumer → run `scan` on an
     insecure fixture → assert the finding shows up and the bin exits cleanly.

Anything needing the toolchain self-skips when node/npm is absent (e.g. a
Python-only CI matrix), so this file never turns a green suite red for the wrong
reason. The Action composite can't be executed without a GitHub Actions runner;
``test_action_yml_script_refs_are_bundled`` gives the feasible coverage —
verifying every script the composite calls exists and ships in the package.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "cli" / "init.js"


def _which(*names: str):
    """First of `names` found on PATH, also probing the common Homebrew/local
    bins that aren't always on a test runner's PATH."""
    extra = ["/opt/homebrew/bin", "/usr/local/bin"]
    for name in names:
        hit = shutil.which(name)
        if hit:
            return hit
        for d in extra:
            cand = Path(d) / name
            if cand.exists():
                return str(cand)
    return None


NODE = _which("node")
NPM = _which("npm")
PY = _which("python3", "python")

needs_node = pytest.mark.skipif(NODE is None, reason="node not installed")
needs_npm = pytest.mark.skipif(NPM is None, reason="npm not installed")


def _env():
    """Child env with Homebrew/local bins on PATH so the JS CLI can find python3
    (it spawns `python3`/`python` itself) regardless of the runner's PATH."""
    env = dict(os.environ)
    extra = os.pathsep.join(["/opt/homebrew/bin", "/usr/local/bin"])
    env["PATH"] = extra + os.pathsep + env.get("PATH", "")
    return env


def _run(argv, **kw):
    kw.setdefault("env", _env())
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    kw.setdefault("timeout", 240)
    return subprocess.run(argv, **kw)


def _pack_file_list() -> list[str]:
    """The exact set of paths `npm publish` would include (no install, fast)."""
    proc = _run([NPM, "pack", "--dry-run", "--json"], cwd=ROOT)
    assert proc.returncode == 0, f"npm pack --dry-run failed:\n{proc.stderr}"
    data = json.loads(proc.stdout)
    return [f["path"] for f in data[0]["files"]]


# The Python modules scan_all.py imports at startup. If any of these is missing
# from the published tarball, `npx secure-ai-pipeline scan` is dead on arrival.
REQUIRED_RUNTIME = [
    "scripts/scan_all.py",
    "scripts/external_tools.py",
    "scripts/check_packages.py",
    "scripts/run_pipeline.py",
    "scripts/blast_radius.py",
    "scripts/policy.py",
    "scripts/scanners/__init__.py",
    "scripts/scanners/registry.py",
    "scripts/scanners/base.py",
    "cli/init.js",
    "cli/scan.js",
    "package.json",
]


@needs_npm
def test_npm_pack_bundles_all_runtime_files():
    files = set(_pack_file_list())
    missing = [f for f in REQUIRED_RUNTIME if f not in files]
    assert not missing, f"npm package is missing runtime files: {missing}"


@needs_npm
def test_npm_pack_bundles_every_scanner_module():
    """Every adapter under scripts/scanners/ must ship — the registry discovers
    them by walking the package, so a dropped file = a silently absent scanner."""
    on_disk = {
        str(p.relative_to(ROOT))
        for p in (ROOT / "scripts" / "scanners").rglob("*.py")
        if "__pycache__" not in p.parts
    }
    shipped = set(_pack_file_list())
    missing = sorted(on_disk - shipped)
    assert not missing, f"scanner modules not in the npm package: {missing}"


@needs_npm
def test_internal_research_not_shipped():
    """Internal strategy notes under docs/research/ must not bloat the package."""
    shipped = _pack_file_list()
    leaked = [f for f in shipped if "docs/research" in f]
    assert not leaked, f"internal research leaked into the npm package: {leaked}"


@needs_node
def test_cli_help_runs():
    proc = _run([NODE, str(CLI), "--help"])
    assert proc.returncode == 0
    assert "secure-ai-pipeline" in proc.stdout


@needs_node
def test_cli_scan_flags_an_insecure_fixture(tmp_path):
    """Run `scan` (from the package source) against a file with verify=False and
    assert the built-in SAST fallback reports it. Offline so it's deterministic
    (no registry calls)."""
    (tmp_path / "app.py").write_text(
        "import requests\n"
        'requests.get("https://example.com", verify=False)\n',
        encoding="utf-8",
    )
    proc = _run([NODE, str(CLI), "scan", str(tmp_path),
                 "--offline", "--no-input", "--no-color"])
    assert proc.returncode == 0, f"scan failed:\n{proc.stderr}"
    assert "Secure AI Pipeline" in proc.stdout
    assert "verify=False" in proc.stdout


@needs_node
def test_cli_init_is_idempotent(tmp_path):
    """`init` copies the pipeline files in, and a second run leaves them untouched
    (the CLAUDE.md idempotency contract)."""
    first = _run([NODE, str(CLI), "init"], cwd=tmp_path)
    assert first.returncode == 0, f"init failed:\n{first.stderr}"
    copied = tmp_path / ".github" / "workflows" / "security.yml"
    assert copied.exists(), "init did not copy security.yml"
    assert (tmp_path / "scripts" / "scan_all.py").exists()

    second = _run([NODE, str(CLI), "init"], cwd=tmp_path)
    assert second.returncode == 0
    assert "left untouched" in second.stdout  # existing files reported, not overwritten


@needs_npm
@needs_node
def test_npx_install_then_scan(tmp_path):
    """The real npx path: pack the tarball, install it into a clean consumer
    project exactly as a user would, and run the installed bin against an insecure
    fixture. Skips (not fails) if the sandbox install can't complete for
    environmental reasons — packaging correctness is already covered by the
    pack-contents tests above; this asserts the assembled bin actually runs."""
    tarball_dir = tmp_path / "tarball"
    tarball_dir.mkdir()
    pack = _run([NPM, "pack", "--silent", "--pack-destination", str(tarball_dir)],
                cwd=ROOT)
    if pack.returncode != 0:
        pytest.skip(f"npm pack failed in sandbox: {pack.stderr}")
    tgz = next(tarball_dir.glob("*.tgz"), None)
    assert tgz is not None, "npm pack produced no tarball"

    consumer = tmp_path / "consumer"
    consumer.mkdir()
    init = _run([NPM, "init", "-y"], cwd=consumer)
    if init.returncode != 0:
        pytest.skip("npm init failed in sandbox")
    install = _run([NPM, "install", str(tgz),
                    "--no-audit", "--no-fund", "--silent"], cwd=consumer)
    if install.returncode != 0:
        pytest.skip(f"local tarball install failed in sandbox: {install.stderr}")

    bin_js = consumer / "node_modules" / "secure-ai-pipeline" / "cli" / "init.js"
    assert bin_js.exists(), "installed package is missing its bin"

    target = consumer / "target"
    target.mkdir()
    (target / "app.py").write_text(
        'import requests\nrequests.get("https://x", verify=False)\n',
        encoding="utf-8",
    )
    scan = _run([NODE, str(bin_js), "scan", str(target),
                 "--offline", "--no-input", "--no-color"])
    assert scan.returncode == 0, f"installed scan failed:\n{scan.stderr}"
    assert "verify=False" in scan.stdout


@needs_npm
def test_action_yml_script_refs_are_bundled():
    """The composite Action can't run outside a GH runner, but every script it
    invokes must exist on disk AND ship in the package (the Action runs from its
    own checkout). This is the feasible slice of 'test the Action composite'."""
    import re

    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    refs = sorted(set(re.findall(r"scripts/[\w/]+\.py", action)))
    assert refs, "no script references found in action.yml — parser drift?"

    shipped = set(_pack_file_list())
    for ref in refs:
        assert (ROOT / ref).exists(), f"action.yml references missing script: {ref}"
        assert ref in shipped, f"action.yml script not bundled in package: {ref}"
