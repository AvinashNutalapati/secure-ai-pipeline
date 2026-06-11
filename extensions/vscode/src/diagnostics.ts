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
  /**
   * Optional quick fix: given the matched target text and language, return a
   * replacement. `ensureImport`, if returned, is inserted at the top of the file
   * when it isn't already present.
   */
  fix?: (
    targetText: string,
    lang: Lang
  ) => { title: string; replacement: string; ensureImport?: string };
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
      ensureImport: "import os",
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
      /\b(api_key|secret|password|passwd|token|auth_key|access_key)\s*=\s*["'][^"']{8,}["']/i,
    target: /["'][^"']{8,}["']/,
    languages: ["python", "javascript"],
    fix: (_targetText: string, lang: Lang) => ({
      title: "Load from environment variable",
      // The matched text is the string literal value; we cannot see the var name
      // here, so emit a generic env lookup the developer renames — language-aware.
      replacement: lang === "python" ? 'os.environ["API_KEY"]' : "process.env.API_KEY",
      ensureImport: lang === "python" ? "import os" : undefined,
    }),
  },
  {
    id: "eval-user-input",
    severity: "error",
    message:
      "eval/exec on request data allows arbitrary code execution. Remove it or use a safe parser.",
    trigger: /\b(?:eval|exec)\s*\(\s*request\./,
    languages: ["python"],
  },
];

// A value is a placeholder only when the WHOLE value matches (mirrors
// run_pipeline.py): a real key merely containing "example" must still flag.
const VALUE_PLACEHOLDER_RE =
  /^(?:x{4,}|\*{3,}|\.{3,}|<[^<>]{0,60}>|changeme|change[-_]me|placeholder|dummy|redacted|todo|tbd|none|null|example(?:[-_](?:api[-_]?key|key|token|secret|value|password))?|sample(?:[-_](?:api[-_]?key|key|token|secret|value))?|your[-_][a-z_-]{0,40})$/i;

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
      const trig = rule.trigger.exec(lineText);
      if (!trig) {
        continue;
      }

      // Underline the target WITHIN the trigger match — searching from
      // column 0 could select an innocent earlier substring (e.g. a URL
      // before the real secret) and make the quick fix edit the wrong code.
      const targetRe = rule.target ?? rule.trigger;
      const m = targetRe.exec(lineText.slice(trig.index));
      let startCol = trig.index;
      let endCol = trig.index + trig[0].length;
      if (m) {
        startCol = trig.index + m.index;
        endCol = startCol + m[0].length;
        // Skip values that are entirely placeholders.
        if (rule.id === "hardcoded-api-key") {
          const inner = m[0].replace(/^["']|["']$/g, "");
          if (VALUE_PLACEHOLDER_RE.test(inner)) {
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
