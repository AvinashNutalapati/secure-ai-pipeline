import * as vscode from "vscode";

export type Lang = "python" | "javascript";
export type RuleSeverity = "error" | "warning";

export interface SecurityRule {
  id: string;
  severity: RuleSeverity;
  message: string;
  /** The line must match this for the rule to fire. */
  trigger: RegExp;
  /** Substring within the line to underline / replace. Defaults to the trigger match. */
  target?: RegExp;
  languages: Lang[];
  /** Optional quick fix: given the matched target text, return a replacement. */
  fix?: (targetText: string) => { title: string; replacement: string };
}

/**
 * The in-editor rule set. Mirrors the Semgrep `.semgrep/ai-insecure-defaults.yml`
 * rules and the regex engine in `scripts/run_pipeline.py`. Everything runs locally
 * in the extension process — no network, no Python, no Semgrep binary.
 */
export const RULES: SecurityRule[] = [
  {
    id: "tls-verify-false",
    severity: "error",
    message:
      "TLS certificate verification disabled (verify=False) — allows man-in-the-middle attacks.",
    trigger: /requests\.\w+\s*\([^)]*\bverify\s*=\s*False\b/,
    target: /\bverify\s*=\s*False\b/,
    languages: ["python"],
    fix: () => ({ title: "Enable TLS verification (verify=True)", replacement: "verify=True" }),
  },
  {
    id: "flask-debug-true",
    severity: "error",
    message:
      "Flask debug=True exposes an interactive debugger that allows arbitrary code execution.",
    trigger: /app\.run\s*\([^)]*\bdebug\s*=\s*True\b/,
    target: /\bdebug\s*=\s*True\b/,
    languages: ["python"],
    fix: () => ({
      title: 'Gate debug on an env var',
      replacement: 'debug=os.getenv("FLASK_DEBUG", "false") == "true"',
    }),
  },
  {
    id: "wildcard-cors",
    severity: "warning",
    message:
      "Wildcard CORS (origins=\"*\") lets any website make credentialed requests. Restrict to trusted origins.",
    trigger: /origins\s*=\s*["']\*["']|Access-Control-Allow-Origin["']?\s*[:=]\s*["']\*["']/,
    target: /["']\*["']/,
    languages: ["python", "javascript"],
    fix: () => ({
      title: "Restrict CORS to an explicit origin",
      replacement: '"https://yourapp.example.com"',
    }),
  },
  {
    id: "subprocess-shell-true",
    severity: "error",
    message:
      "subprocess with shell=True and user input enables command injection. Pass an argument list instead.",
    trigger: /subprocess\.\w+\s*\([^)]*\bshell\s*=\s*True\b/,
    target: /\bshell\s*=\s*True\b/,
    languages: ["python"],
    fix: () => ({ title: "Disable shell (shell=False)", replacement: "shell=False" }),
  },
  {
    id: "sql-injection-fstring",
    severity: "error",
    message:
      "SQL query built from an f-string or concatenation — use parameterised queries (execute(sql, (param,))).",
    trigger:
      /\.execute\s*\(\s*f["']|\.execute\s*\(\s*["'][^"']*["']\s*%\s*\w|\.execute\s*\(\s*["'][^"']*["']\s*\+\s*\w/,
    languages: ["python"],
  },
  {
    id: "hardcoded-api-key",
    severity: "error",
    message:
      "Hardcoded credential in source. Load it from the environment (os.environ[...]) or a secrets manager.",
    trigger:
      /\b(api_key|secret|password|passwd|token|auth_key|access_key)\s*=\s*["'][^"']{4,}["']/i,
    target: /["'][^"']{4,}["']/,
    languages: ["python", "javascript"],
    fix: (_targetText: string) => ({
      title: "Load from environment variable",
      // The matched text is the string literal value; we cannot see the var name
      // here, so emit a generic os.environ lookup the developer renames.
      replacement: 'os.environ["API_KEY"]',
    }),
  },
];

const VALUE_PLACEHOLDERS = ["example", "placeholder", "changeme", "your_", "<", ">"];

export function langForDocument(doc: vscode.TextDocument): Lang | undefined {
  switch (doc.languageId) {
    case "python":
      return "python";
    case "javascript":
    case "javascriptreact":
    case "typescript":
    case "typescriptreact":
      return "javascript";
    default:
      return undefined;
  }
}

function severityRank(s: RuleSeverity): number {
  return s === "error" ? 2 : 1;
}

function toVscodeSeverity(s: RuleSeverity): vscode.DiagnosticSeverity {
  return s === "error"
    ? vscode.DiagnosticSeverity.Error
    : vscode.DiagnosticSeverity.Warning;
}

/**
 * Scan a document and return diagnostics for every rule that fires.
 * `minSeverity` filters out findings below the configured threshold.
 */
export function scanDocument(
  doc: vscode.TextDocument,
  minSeverity: RuleSeverity
): vscode.Diagnostic[] {
  const lang = langForDocument(doc);
  if (!lang) {
    return [];
  }
  const minRank = severityRank(minSeverity);
  const diagnostics: vscode.Diagnostic[] = [];
  const lineCount = doc.lineCount;

  for (let i = 0; i < lineCount; i++) {
    const lineText = doc.lineAt(i).text;
    for (const rule of RULES) {
      if (!rule.languages.includes(lang)) {
        continue;
      }
      if (severityRank(rule.severity) < minRank) {
        continue;
      }
      if (!rule.trigger.test(lineText)) {
        continue;
      }

      // Determine the precise range to underline.
      const targetRe = rule.target ?? rule.trigger;
      const m = targetRe.exec(lineText);
      let startCol = 0;
      let endCol = lineText.length;
      if (m) {
        startCol = m.index;
        endCol = m.index + m[0].length;
        // Skip obvious non-secret placeholder values.
        if (rule.id === "hardcoded-api-key") {
          const lower = m[0].toLowerCase();
          if (VALUE_PLACEHOLDERS.some((p) => lower.includes(p))) {
            continue;
          }
        }
      }

      const range = new vscode.Range(i, startCol, i, endCol);
      const diag = new vscode.Diagnostic(
        range,
        rule.message,
        toVscodeSeverity(rule.severity)
      );
      diag.source = "secure-ai-pipeline";
      diag.code = rule.id;
      diagnostics.push(diag);
    }
  }
  return diagnostics;
}
