"use strict";

/**
 * `scan` and `doctor` subcommands.
 *
 * `scan` shells out to scripts/blast_radius.py (bundled in the package) to run the
 * AI Agent Blast Radius checkup against the target repo, passing through flags
 * (--html / --json / --offline / --fail-on). `doctor` checks prerequisites.
 *
 * Node built-ins only — no npm dependencies.
 */

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const PKG_ROOT = path.join(__dirname, "..");
const BLAST_RADIUS = path.join(PKG_ROOT, "scripts", "blast_radius.py");

const color = (c, s) => `\x1b[${c}m${s}\x1b[0m`;
const green = (s) => color("32", s);
const red = (s) => color("31", s);
const yellow = (s) => color("33", s);
const dim = (s) => color("2", s);

/** Return the first working Python interpreter, or null. */
function findPython() {
  for (const cmd of ["python3", "python"]) {
    const r = spawnSync(cmd, ["--version"], { stdio: "ignore" });
    if (!r.error && r.status === 0) return cmd;
  }
  return null;
}

function runScan(args) {
  const py = findPython();
  if (!py) {
    console.error(red("✗ python3 not found.") + " The scanners need Python 3.10+.");
    console.error(dim("  Install from https://python.org or `brew install python`, then retry."));
    return 1;
  }
  if (!fs.existsSync(BLAST_RADIUS)) {
    console.error(red(`✗ scanner missing: ${BLAST_RADIUS}`));
    return 1;
  }
  // Pass args straight through; blast_radius.py defaults ROOT to the cwd.
  const r = spawnSync(py, [BLAST_RADIUS, ...args], { stdio: "inherit" });
  if (r.error) {
    console.error(red(`✗ failed to run scanner: ${r.error.message}`));
    return 1;
  }
  return r.status === null ? 1 : r.status;
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
  if (py) {
    const v = spawnSync(py, ["--version"], { encoding: "utf8" });
    ok &= check(`Python: ${(v.stdout || v.stderr || "").trim()} (${py})`, true);
  } else {
    ok &= check("Python 3.10+", false, "Install from https://python.org");
  }

  const git = spawnSync("git", ["--version"], { stdio: "ignore" });
  ok &= check("git available", !git.error && git.status === 0,
    "Install git from https://git-scm.com");

  const inRepo = spawnSync("git", ["rev-parse", "--is-inside-work-tree"], { stdio: "ignore" });
  check("inside a git repository", !inRepo.error && inRepo.status === 0,
    "Run inside a repo, or `git init` first (scan still works without git).");

  ok &= check("blast-radius scanner present", fs.existsSync(BLAST_RADIUS),
    "Reinstall the package.");

  if (py && fs.existsSync(BLAST_RADIUS)) {
    const imp = spawnSync(py, ["-c",
      `import sys; sys.path.insert(0, ${JSON.stringify(path.join(PKG_ROOT, "scripts"))}); import blast_radius`],
      { stdio: "ignore" });
    ok &= check("scanners import cleanly", !imp.error && imp.status === 0,
      "The bundled Python scanners failed to import.");
  }

  console.log("");
  if (ok) {
    console.log(green("  All set. Run: ") + "npx secure-ai-pipeline scan .\n");
    return 0;
  }
  console.log(yellow("  Some prerequisites are missing — see hints above.\n"));
  return 1;
}

module.exports = { runScan, runDoctor };
