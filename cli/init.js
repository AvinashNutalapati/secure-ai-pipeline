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
const { execSync } = require("child_process");

// Package root = parent of this cli/ directory. All bundled files live here.
const PKG_ROOT = path.join(__dirname, "..");
const TARGET = process.cwd();

// Files to copy, relative to both the package root and the target repo.
const FILES_TO_COPY = [
  path.join(".github", "workflows", "security.yml"),
  path.join("scripts", "check_packages.py"),
  path.join("scripts", "run_pipeline.py"),
  path.join("scripts", "sarif_gate.py"),
  path.join(".semgrep", "ai-insecure-defaults.yml"),
  path.join(".zap", "rules.tsv"),
  ".pre-commit-config.yaml",
];

const GITIGNORE_ENTRY = "pipeline-results.json";

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
  let contents = "";
  if (fs.existsSync(gi)) {
    contents = fs.readFileSync(gi, "utf8");
    const lines = contents.split(/\r?\n/).map((l) => l.trim());
    if (lines.includes(GITIGNORE_ENTRY)) {
      console.log(`  ${dim("exists")}  .gitignore already ignores ${GITIGNORE_ENTRY}`);
      return;
    }
    const sep = contents.endsWith("\n") || contents === "" ? "" : "\n";
    fs.appendFileSync(gi, `${sep}${GITIGNORE_ENTRY}\n`);
  } else {
    fs.writeFileSync(gi, `${GITIGNORE_ENTRY}\n`);
  }
  console.log(`  ${green("added")}  .gitignore entry for ${GITIGNORE_ENTRY}`);
}

function commandExists(cmd) {
  try {
    execSync(cmd, { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function setupPreCommit() {
  if (commandExists("pre-commit --version")) {
    try {
      execSync("pre-commit install", { cwd: TARGET, stdio: "ignore" });
      console.log(`  ${green("ok")}     pre-commit hooks installed`);
    } catch {
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
  • .github/workflows/security.yml  — CI pipeline wired (runs on every push/PR)
  • scripts/check_packages.py       — anti-slopsquatting guard
  • .semgrep/ai-insecure-defaults.yml — 7 custom SAST rules for AI code
  • .pre-commit-config.yaml         — local hooks active

One optional step:
  Set STAGING_URL in GitHub → Settings → Variables → Actions
  to enable DAST scanning against your staging environment.

That's it. Push a commit to see the pipeline run.
`;
  console.log(summary);
}

function printHelp() {
  console.log(`secure-ai-pipeline — security pipeline for AI-generated code

Usage:
  npx secure-ai-pipeline@latest init    Install the pipeline into the current repo

The 'init' command is idempotent — safe to run multiple times.`);
}

function run() {
  const arg = (process.argv[2] || "init").toLowerCase();

  if (arg === "--help" || arg === "-h" || arg === "help") {
    printHelp();
    process.exit(0);
  }
  if (arg !== "init") {
    console.error(`Unknown command: ${arg}\n`);
    printHelp();
    process.exit(1);
  }

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
  process.exit(0);
}

run();
