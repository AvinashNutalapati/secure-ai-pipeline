"use strict";

/**
 * `scan` and `doctor` subcommands.
 *
 * `scan` shells out to scripts/scan_all.py (bundled in the package) to run the
 * full unified scan — Secrets, SCA + malicious packages, SAST, AI blast radius,
 * and optional DAST — passing through flags (--html / --json / --offline /
 * --fail-on / --detail / --dast-url / --only / --tools …). `posture` runs just
 * the AI blast-radius checkup (scripts/blast_radius.py). `doctor` checks prereqs.
 *
 * Node built-ins only — no npm dependencies.
 */

const fs = require("fs");
const path = require("path");
// nosemgrep: javascript.lang.security.detect-child-process.detect-child-process -- this CLI spawns python by design, with fixed argv and no shell.
const { spawnSync } = require("child_process");

const PKG_ROOT = path.join(__dirname, "..");
const SCAN_ALL = path.join(PKG_ROOT, "scripts", "scan_all.py");
const BLAST_RADIUS = path.join(PKG_ROOT, "scripts", "blast_radius.py");

const color = (c, s) => `\x1b[${c}m${s}\x1b[0m`;
const green = (s) => color("32", s);
const red = (s) => color("31", s);
const yellow = (s) => color("33", s);
const dim = (s) => color("2", s);

const MIN_PYTHON = [3, 10];

/**
 * Return `{ cmd, version, tooOld }` for the best interpreter found, preferring
 * the first one that satisfies 3.10+, or null when none exists. Python 2 (or
 * an old 3.x) must be rejected up front — running the scanners on it dies in a
 * SyntaxError instead of a clear prerequisite message.
 */
function findPython() {
  let fallback = null;
  for (const cmd of ["python3", "python"]) {
    const r = spawnSync(cmd, ["--version"], { encoding: "utf8" });
    if (r.error || r.status !== 0) continue;
    const version = `${r.stdout || ""}${r.stderr || ""}`.trim();
    const m = /Python (\d+)\.(\d+)/.exec(version);
    if (!m) continue;
    const major = Number(m[1]);
    const minor = Number(m[2]);
    if (major > MIN_PYTHON[0] || (major === MIN_PYTHON[0] && minor >= MIN_PYTHON[1])) {
      return { cmd, version, tooOld: false };
    }
    fallback = fallback || { cmd, version, tooOld: true };
  }
  return fallback;
}

function runScanWith(scriptPath, args) {
  const py = findPython();
  if (!py || py.tooOld) {
    const found = py ? ` Found ${py.version}.` : "";
    console.error(red("✗ Python 3.10+ not found.") + found + " The scanners need Python 3.10+.");
    console.error(dim("  Install from https://python.org or `brew install python`, then retry."));
    return 1;
  }
  if (!fs.existsSync(scriptPath)) {
    console.error(red(`✗ scanner missing: ${scriptPath}`));
    return 1;
  }
  // Pass args straight through; the scanner defaults ROOT to the cwd.
  const r = spawnSync(py.cmd, [scriptPath, ...args], { stdio: "inherit" });
  if (r.error) {
    console.error(red(`✗ failed to run scanner: ${r.error.message}`));
    return 1;
  }
  return r.status === null ? 1 : r.status;
}

// `scan` → the full unified scan (secrets/SCA/SAST/posture/DAST).
function runScan(args) {
  return runScanWith(SCAN_ALL, args);
}

// `posture` → just the AI blast-radius checkup (the old `scan` behaviour).
function runPosture(args) {
  return runScanWith(BLAST_RADIUS, args);
}

function check(label, ok, hint) {
  const mark = ok ? green("✓") : red("✗");
  console.log(`  ${mark} ${label}`);
  if (!ok && hint) console.log(dim(`      ${hint}`));
  return ok;
}

function runDoctor() {
  console.log("\n🩺 secure-ai-pipeline doctor\n");
  let ok = true;

  const py = findPython();
  if (py && !py.tooOld) {
    ok &= check(`Python: ${py.version} (${py.cmd})`, true);
  } else if (py) {
    ok &= check(`Python 3.10+ — found only ${py.version}`, false,
      "Install Python 3.10 or newer from https://python.org");
  } else {
    ok &= check("Python 3.10+", false, "Install from https://python.org");
  }

  const git = spawnSync("git", ["--version"], { stdio: "ignore" });
  ok &= check("git available", !git.error && git.status === 0,
    "Install git from https://git-scm.com");

  const inRepo = spawnSync("git", ["rev-parse", "--is-inside-work-tree"], { stdio: "ignore" });
  check("inside a git repository", !inRepo.error && inRepo.status === 0,
    "Run inside a repo, or `git init` first (scan still works without git).");

  ok &= check("scanner present", fs.existsSync(SCAN_ALL), "Reinstall the package.");

  if (py && !py.tooOld && fs.existsSync(SCAN_ALL)) {
    const imp = spawnSync(py.cmd, ["-c",
      `import sys; sys.path.insert(0, ${JSON.stringify(path.join(PKG_ROOT, "scripts"))}); import scan_all`],
      { stdio: "ignore" });
    ok &= check("scanners import cleanly", !imp.error && imp.status === 0,
      "The bundled Python scanners failed to import.");
  }

  // Report which optional OSS engines are installed (informational, never fails).
  const engines = ["semgrep", "trivy", "gitleaks", "osv-scanner", "docker"];
  const present = engines.filter((e) =>
    spawnSync(e, ["--version"], { stdio: "ignore" }).status === 0 ||
    spawnSync("sh", ["-c", `command -v ${e}`], { stdio: "ignore" }).status === 0);
  console.log(dim(`      OSS engines installed: ${present.length ? present.join(", ") : "none (built-in fallbacks will run)"}`));

  console.log("");
  if (ok) {
    console.log(green("  All set. Run: ") + "npx secure-ai-pipeline scan .\n");
    return 0;
  }
  console.log(yellow("  Some prerequisites are missing — see hints above.\n"));
  return 1;
}

module.exports = { runScan, runPosture, runDoctor };
