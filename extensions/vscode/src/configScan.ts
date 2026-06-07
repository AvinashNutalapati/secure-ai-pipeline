import * as vscode from "vscode";
import * as path from "path";

/**
 * In-editor AI-workflow posture rules — the TypeScript mirror of the Python
 * scanners in `scripts/scanners/`. Lights up diagnostics on MCP configs, Claude
 * permissions, AI IDE rules, and GitHub Actions workflows. Pure regex, local,
 * no Python/network.
 */

export type ConfigSeverity = "critical" | "high" | "medium" | "low";
export type ConfigCategory = "mcp" | "claude" | "ai_ide" | "github_actions";

export const SEVERITY_WEIGHT: Record<ConfigSeverity, number> = {
  critical: 30,
  high: 15,
  medium: 7,
  low: 3,
};

interface ConfigRule {
  id: string;
  severity: ConfigSeverity;
  message: string;
  pattern: RegExp;
}

const RULES: Record<ConfigCategory, ConfigRule[]> = {
  mcp: [
    {
      id: "mcp-secret-env",
      severity: "critical",
      message:
        "Long-lived credential handed to an MCP server. A malicious/compromised server can exfiltrate it — use short-lived/OAuth tokens.",
      pattern:
        /"(GITHUB_TOKEN|AWS_[A-Z_]+|OPENAI_[A-Z_]*|ANTHROPIC_[A-Z_]*|[A-Z_]*(TOKEN|SECRET|API_?KEY|ACCESS_?KEY|PASSWORD|PRIVATE_?KEY))"\s*:/i,
    },
    {
      id: "mcp-shell-exec",
      severity: "high",
      message:
        "MCP server launches via a shell (bash/sh) or curl|bash — an RCE / supply-chain risk. Run a pinned binary directly.",
      pattern: /"command"\s*:\s*"(?:\/bin\/)?(?:bash|sh|zsh)"|(?:curl|wget)[^"]*\|\s*(?:bash|sh)/i,
    },
    {
      id: "mcp-broad-fs",
      severity: "high",
      message:
        "MCP server mounts a broad filesystem path (/, ~, $HOME). Scope filesystem servers to the project directory.",
      pattern: /"(\/|~|\$HOME|\/Users(?:\/\*+)?|\/home(?:\/\*+)?)"/,
    },
    {
      id: "mcp-remote-unauth",
      severity: "high",
      message:
        "Remote MCP server over http:// — tool output is untrusted input to your agent. Use https and require auth.",
      pattern: /"(?:url|serverUrl)"\s*:\s*"http:\/\//i,
    },
  ],
  claude: [
    {
      id: "claude-broad-read",
      severity: "critical",
      message:
        "Claude can read outside the workspace. Prompt injection could turn this into data exfiltration. Scope to Read(./**).",
      pattern: /(?:Read|Edit|Write)\(\s*\/*(?:\/Users|\/home|\/etc|\/var|\/root|~|\*\*)/i,
    },
    {
      id: "claude-wildcard-bash",
      severity: "high",
      message: "Claude has wildcard shell access (Bash(*)). Allow only specific commands.",
      pattern: /Bash\(\s*\*\s*\)/,
    },
    {
      id: "claude-destructive-bash",
      severity: "high",
      message: "Claude is pre-authorized for a destructive command (rm -rf/sudo).",
      pattern: /Bash\(\s*(?:rm\s+-rf|sudo)/i,
    },
    {
      id: "claude-bypass-mode",
      severity: "high",
      message:
        "defaultMode bypasses the human approval step for agent actions. Use 'default' (prompt) mode.",
      pattern: /"defaultMode"\s*:\s*"(?:bypassPermissions|acceptEdits)"/i,
    },
  ],
  ai_ide: [
    {
      id: "ai-ide-prompt-injection",
      severity: "critical",
      message:
        "Rules file contains prompt-injection override language. Rules are trusted by the agent — remove it.",
      pattern: /ignore (?:all )?(?:previous|prior) instructions|disregard (?:the )?(?:system|above)/i,
    },
    {
      id: "ai-ide-fetch-execute",
      severity: "high",
      message: "Rules file contains a fetch-and-execute (curl|bash) instruction.",
      pattern: /(?:curl|wget)[^\n]*\|\s*(?:bash|sh)/i,
    },
    {
      id: "ai-ide-auto-execution",
      severity: "high",
      message:
        "Rules file encourages auto-run / skipping confirmation. The agent should ask before privileged actions.",
      pattern:
        /\b(?:yolo|auto-?run|auto-?execute|run automatically)\b|without (?:asking|confirmation|approval)|do(?:n'?t| not) ask|skip (?:the )?confirmation/i,
    },
  ],
  github_actions: [
    {
      id: "gha-pull-request-target",
      severity: "critical",
      message:
        "pull_request_target runs with repository secrets in the context of untrusted PR code. Prefer pull_request.",
      pattern: /pull_request_target/,
    },
    {
      id: "gha-script-injection",
      severity: "high",
      message:
        "Untrusted ${{ github.event.* }} interpolation can inject shell commands. Pass via env: and use \"$VAR\".",
      pattern: /\$\{\{\s*github\.event\.[^}]*\}\}/,
    },
    // gha-unpinned-action is handled specially in scanConfig (needs SHA logic).
  ],
};

const USES_RE = /^\s*(?:-\s*)?uses:\s*['"]?([^'"\s#]+)['"]?/;
const SHA_RE = /@[0-9a-f]{40}$/;

export interface ConfigFinding {
  ruleId: string;
  severity: ConfigSeverity;
  message: string;
  line: number; // 0-based
  startCol: number;
  endCol: number;
}

export function categoryForDocument(doc: vscode.TextDocument): ConfigCategory | undefined {
  return categoryForPath(doc.uri.fsPath);
}

export function categoryForPath(fsPath: string): ConfigCategory | undefined {
  const p = fsPath.replace(/\\/g, "/");
  const base = path.basename(p);

  if (
    base === "mcp.json" ||
    base === ".mcp.json" ||
    base === "claude_desktop_config.json" ||
    /\/\.vscode\/mcp\.json$/.test(p) ||
    /\/\.cursor\/mcp\.json$/.test(p)
  ) {
    return "mcp";
  }
  if (/\/\.claude\/settings(\.local)?\.json$/.test(p)) {
    return "claude";
  }
  if (
    base === ".cursorrules" ||
    base === ".clinerules" ||
    base === ".windsurfrules" ||
    base === "copilot-instructions.md" ||
    base === "AGENTS.md" ||
    /\/\.cursor\/rules\//.test(p) ||
    /\/\.windsurf\/rules\//.test(p)
  ) {
    return "ai_ide";
  }
  if (/\/\.github\/workflows\/[^/]+\.ya?ml$/.test(p)) {
    return "github_actions";
  }
  return undefined;
}

function unpinned(ref: string): boolean {
  if (ref.startsWith("./") || ref.startsWith("docker://")) {
    return false;
  }
  if (!ref.includes("@")) {
    return true;
  }
  return !SHA_RE.test(ref);
}

export function scanConfig(doc: vscode.TextDocument): ConfigFinding[] {
  const category = categoryForDocument(doc);
  if (!category) {
    return [];
  }
  const findings: ConfigFinding[] = [];
  const rules = RULES[category];

  for (let i = 0; i < doc.lineCount; i++) {
    const text = doc.lineAt(i).text;
    if (text.trim().startsWith("#") || text.trim().startsWith("//")) {
      continue;
    }
    for (const rule of rules) {
      const m = rule.pattern.exec(text);
      if (m) {
        findings.push({
          ruleId: rule.id,
          severity: rule.severity,
          message: rule.message,
          line: i,
          startCol: m.index,
          endCol: m.index + m[0].length,
        });
      }
    }
    // Special-case: unpinned GitHub Actions.
    if (category === "github_actions") {
      const um = USES_RE.exec(text);
      if (um && unpinned(um[1])) {
        const owner = um[1].split("/")[0];
        const firstParty = owner === "actions" || owner === "github";
        const idx = text.indexOf(um[1]);
        findings.push({
          ruleId: "gha-unpinned-action",
          severity: firstParty ? "medium" : "high",
          message: `Action '${um[1]}' is pinned by a mutable tag/branch. Pin to a full commit SHA (tj-actions, 2025).`,
          line: i,
          startCol: idx >= 0 ? idx : 0,
          endCol: idx >= 0 ? idx + um[1].length : text.length,
        });
      }
    }
  }
  return findings;
}

export function toVscodeSeverity(s: ConfigSeverity): vscode.DiagnosticSeverity {
  switch (s) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

export function scoreFromWeights(weightSum: number): number {
  return Math.max(0, 100 - weightSum);
}

export function gradeOf(score: number): string {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}
