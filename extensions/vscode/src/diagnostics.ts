import * as vscode from "vscode";
import { GENERATED_RULES } from "./rules.generated";

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

type FixFn = (
  targetText: string,
  lang: Lang
) => { title: string; replacement: string; ensureImport?: string };

// Quick-fix functions are CODE, so they stay here keyed by rule id; everything
// else (ids, severity, message, regexes, languages) comes from the generated
// table, which scripts/gen_rules.py emits from the one canonical catalog
// (scripts/scanners/sast/ai_insecure_defaults.py). Edit a rule there + regen.
const FIXES: Record<string, FixFn> = {
  "tls-verify-false": () => ({
    title: "Enable TLS verification (verify=True)",
    replacement: "verify=True",
  }),
  "flask-debug-true": () => ({
    title: "Gate debug on an env var",
    replacement: 'debug=os.getenv("FLASK_DEBUG", "false") == "true"',
    ensureImport: "import os",
  }),
  "wildcard-cors": () => ({
    title: "Restrict CORS to an explicit origin",
    replacement: '"https://yourapp.example.com"',
  }),
  "subprocess-shell-true": () => ({
    title: "Disable shell (shell=False)",
    replacement: "shell=False",
  }),
  "hardcoded-api-key": (_targetText: string, lang: Lang) => ({
    title: "Load from environment variable",
    replacement: lang === "python" ? 'os.environ["API_KEY"]' : "process.env.API_KEY",
    ensureImport: lang === "python" ? "import os" : undefined,
  }),
};

/**
 * The in-editor rule set, assembled from the generated table + the local fix
 * functions. Everything runs locally in the extension — no network, no Python.
 */
export const RULES: SecurityRule[] = GENERATED_RULES.map((r) => ({
  id: r.id,
  severity: r.severity,
  message: r.message,
  trigger: new RegExp(r.trigger, r.flags),
  target: r.target ? new RegExp(r.target, r.flags) : undefined,
  languages: r.languages,
  fix: FIXES[r.id],
}));

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
