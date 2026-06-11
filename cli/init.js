#!/usr/bin/env node
"use strict";

/**
 * Secure AI Pipeline — one-line installer.
 *
 * Usage:
 *   npx secure-ai-pipeline@latest init
 *
 * Drops the pipeline files into the current repo, wires up pre-commit if
 * available, and prints a success summary. Zero npm dependencies — Node
 * built-ins only. Idempotent: existing files are never overwritten.
 */

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

// Package root = parent of this cli/ directory. All bundled files live here.
const PKG_ROOT = path.join(__dirname, "..");
const TARGET = process.cwd();

// Every bundled scanner module is discovered at runtime — no hand-maintained
// list that can drift from the package contents and break installed pipelines.
function scannerFiles() {
  const dir = path.join(PKG_ROOT, "scripts", "scanners");
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".py"))
    .sort()
    .map((f) => path.join("scripts", "scanners", f));
}

// Files to copy, relative to both the package root and the target repo.
const FILES_TO_COPY = [
  path.join(".github", "workflows", "security.yml"),
  path.join("scripts", "check_packages.py"),
  path.join("scripts", "run_pipeline.py"),
  path.join("scripts", "sarif_gate.py"),
  // Unified multi-scanner local scan (secrets/SCA/SAST/posture/DAST)
  path.join("scripts", "scan_all.py"),
  path.join("scripts", "external_tools.py"),
  // AI-posture scanners + Blast Radius Score
  path.join("scripts", "blast_radius.py"),
  path.join("scripts", "report.py"),
  path.join("scripts", "policy.py"),
  ...scannerFiles(),
  path.join(".semgrep", "ai-insecure-defaults.yml"),
  path.join(".zap", "rules.tsv"),
  ".pre-commit-config.yaml",
];

const GITIGNORE_ENTRIES = ["pipeline-results.json", ".secure-ai-pipeline/"];

// ── small ANSI helpers (no dependency) ──────────────────────────────────────
const color = (code, s) => `[${code}m${s}[0m`;
const green = (s) => color("32", s);
const yellow = (s) => color("33", s);
const dim = (s) => color("2", s);
const bold = (s) => color("1", s);

function detectLang() {
  const has = (f) => fs.existsSync(path.join(TARGET, f));
  const isPython = has("requirements.txt") || has("Pipfile") || has("pyproject.toml");
  const isNode = has("package.json");
  if (isPython && isNode) return "both";
  if (isPython) return "python";
  if (isNode) return "node";
  return "unknown";
}

function copyFile(relPath) {
  const src = path.join(PKG_ROOT, relPath);
  const dest = path.join(TARGET, relPath);

  if (!fs.existsSync(src)) {
    console.log(`  ${yellow("skip")}  ${relPath} ${dim("(not bundled — skipped)")}`);
    return "missing";
  }
  if (fs.existsSync(dest)) {
    console.log(`  ${dim("exists")}  ${relPath} ${dim("(left untouched)")}`);
    return "exists";
  }
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(src, dest);
  console.log(`  ${green("added")}  ${relPath}`);
  return "added";
}

function ensureGitignoreEntry() {
  const gi = path.join(TARGET, ".gitignore");
  let contents = fs.existsSync(gi) ? fs.readFileSync(gi, "utf8") : "";
  const present = new Set(contents.split(/\r?\n/).map((l) => l.trim()));
  const missing = GITIGNORE_ENTRIES.filter((e) => !present.has(e));
  if (missing.length === 0) {
    console.log(`  ${dim("exists")}  .gitignore already has the entries`);
    return;
  }
  const sep = contents === "" || contents.endsWith("\n") ? "" : "\n";
  fs.appendFileSync(gi, sep + missing.map((e) => `${e}\n`).join(""));
  console.log(`  ${green("added")}  .gitignore entries: ${missing.join(", ")}`);
}

function commandExists(cmd) {
  // Split into argv and run without a shell (no shell-injection surface). `cmd`
  // is always a fixed internal string (e.g. "pre-commit --version"), never user
  // input, so the variable binary is safe.
  const [bin, ...args] = cmd.split(" ");
  const r = spawnSync(bin, args, { stdio: "ignore" }); // nosemgrep
  return !r.error && r.status === 0;
}

function setupPreCommit() {
  if (commandExists("pre-commit --version")) {
    const r = spawnSync("pre-commit", ["install"], { cwd: TARGET, stdio: "ignore" });
    if (!r.error && r.status === 0) {
      console.log(`  ${green("ok")}     pre-commit hooks installed`);
    } else {
      console.log(
        `  ${yellow("note")}   pre-commit is installed but 'pre-commit install' failed ` +
          `(are you in a git repo?). Run it manually: ${bold("pre-commit install")}`
      );
    }
  } else {
    console.log(
      `  ${yellow("note")}   pre-commit not found. To enable local hooks, run:\n` +
        `         ${bold("pip install pre-commit && pre-commit install")}`
    );
  }
}

function printSuccess() {
  const summary = `
${green("✅ Secure AI Pipeline installed.")}

What just happened:
  • .github/workflows/security.yml  — CI pipeline + AI Blast Radius job
  • scripts/blast_radius.py + scanners/ — AI IDE / Claude / MCP / Actions posture
  • scripts/check_packages.py       — anti-slopsquatting guard
  • .semgrep/ai-insecure-defaults.yml — custom SAST rules for AI code
  • .pre-commit-config.yaml         — local hooks active

${bold("Next step — run the checkup now (local, no CI wait):")}
  npx secure-ai-pipeline scan . --html report.html

Then commit & push:
  git add . && git commit -m "add secure-ai-pipeline" && git push

Optional: set STAGING_URL in GitHub → Settings → Variables → Actions for DAST.
`;
  console.log(summary);
}

function printHelp() {
  console.log(`secure-ai-pipeline — security for AI-assisted development

Usage:
  npx secure-ai-pipeline@latest <command>

Commands:
  scan [DIR]     Full local scan — Secrets, SCA + malicious packages, SAST,
                 AI blast radius, and (optional) DAST. One table per layer.
                   --detail T    expand a layer (secrets|sca|sast|dast|posture|all)
                   --dast-url U  run a ZAP DAST scan against a running app URL
                   --only T,..   run only these layers
                   --tools       show which OSS engines are installed
                   --html FILE   write a clickable HTML report
                   --json FILE   write a JSON report
                   --offline     skip network package checks
                   --no-input    never prompt (CI mode)
                   --fail-on L   exit non-zero at/above severity L
                                 (critical | high | medium — case-insensitive)
  posture [DIR]  Run only the AI Agent Blast Radius checkup
  init           Install the CI pipeline + hooks into the current repo (idempotent)
  doctor         Check prerequisites + which OSS scanner engines are installed
  help           Show this help

  Optional OSS engines (auto-used when installed, built-in fallback otherwise):
    gitleaks (secrets) · semgrep (SAST) · trivy (SCA) · osv-scanner
    (malicious packages) · ZAP/Docker (DAST)`);
}

function runInit() {
  console.log(bold("\n🔒 Secure AI Pipeline — installer\n"));

  const lang = detectLang();
  console.log(`  ${dim(`Detected project type: ${lang}`)}\n`);

  for (const f of FILES_TO_COPY) {
    copyFile(f);
  }
  ensureGitignoreEntry();
  console.log("");
  setupPreCommit();

  printSuccess();
}

function run() {
  const arg = (process.argv[2] || "scan").toLowerCase();
  const rest = process.argv.slice(3);

  if (arg === "--help" || arg === "-h" || arg === "help") {
    printHelp();
    process.exit(0);
  }
  if (arg === "scan") {
    process.exit(require("./scan.js").runScan(rest));
  }
  if (arg === "posture" || arg === "blast-radius") {
    process.exit(require("./scan.js").runPosture(rest));
  }
  if (arg === "doctor") {
    process.exit(require("./scan.js").runDoctor());
  }
  if (arg === "init") {
    runInit();
    process.exit(0);
  }
  console.error(`Unknown command: ${arg}\n`);
  printHelp();
  process.exit(1);
}

if (require.main === module) {
  run();
}

module.exports = { runInit };
