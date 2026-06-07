import * as vscode from "vscode";
import { scanDocument, langForDocument, RuleSeverity } from "./diagnostics";
import { SecurityQuickFixProvider } from "./quickfix";
import { StatusBar } from "./statusbar";
import { FindingsProvider } from "./sidebar";
import {
  scanConfig,
  categoryForDocument,
  toVscodeSeverity,
  scoreFromWeights,
  gradeOf,
  SEVERITY_WEIGHT,
  ConfigFinding,
  ConfigSeverity,
} from "./configScan";

// Glob (brace-expanded) covering every AI-workflow config file we scan.
const CONFIG_GLOB =
  "{**/mcp.json,**/.mcp.json,**/claude_desktop_config.json,**/.vscode/mcp.json," +
  "**/.cursor/mcp.json,**/.claude/settings.json,**/.claude/settings.local.json," +
  "**/.cursorrules,**/.clinerules,**/.windsurfrules,**/.cursor/rules/**," +
  "**/.windsurf/rules/**,**/.github/copilot-instructions.md,**/AGENTS.md," +
  "**/.github/workflows/*.yml,**/.github/workflows/*.yaml}";

function configToDiagnostic(f: ConfigFinding): vscode.Diagnostic {
  const range = new vscode.Range(f.line, f.startCol, f.line, f.endCol);
  const diag = new vscode.Diagnostic(range, f.message, toVscodeSeverity(f.severity));
  diag.source = "secure-ai-pipeline";
  diag.code = f.ruleId;
  return diag;
}

let diagnostics: vscode.DiagnosticCollection;
let statusBar: StatusBar;
let findingsProvider: FindingsProvider;

function config() {
  const cfg = vscode.workspace.getConfiguration("securePipeline");
  return {
    enable: cfg.get<boolean>("enable", true),
    severity: cfg.get<RuleSeverity>("severity", "warning"),
    runOnType: cfg.get<boolean>("runOnType", false),
  };
}

function refreshDocument(doc: vscode.TextDocument): void {
  const { enable, severity } = config();
  if (langForDocument(doc)) {
    diagnostics.set(doc.uri, enable ? scanDocument(doc, severity) : []);
    updateAggregate();
    return;
  }
  if (categoryForDocument(doc)) {
    diagnostics.set(doc.uri, enable ? scanConfig(doc).map(configToDiagnostic) : []);
    updateAggregate();
  }
}

/**
 * Scan every AI-workflow config file in the workspace, set diagnostics, and
 * return a Blast Radius Score. Mirrors `scripts/blast_radius.py` (config slice).
 */
async function runBlastRadius(): Promise<void> {
  const uris = await vscode.workspace.findFiles(CONFIG_GLOB, "**/node_modules/**");
  const counts: Record<ConfigSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  let weightSum = 0;

  for (const uri of uris) {
    let doc: vscode.TextDocument;
    try {
      doc = await vscode.workspace.openTextDocument(uri);
    } catch {
      continue;
    }
    const findings = scanConfig(doc);
    diagnostics.set(uri, findings.map(configToDiagnostic));
    for (const f of findings) {
      counts[f.severity] += 1;
      weightSum += SEVERITY_WEIGHT[f.severity];
    }
  }
  updateAggregate();

  const score = scoreFromWeights(weightSum);
  const grade = gradeOf(score);
  const summary =
    `AI Agent Blast Radius: ${score}/100 (grade ${grade}) — ` +
    `${counts.critical} critical, ${counts.high} high, ${counts.medium} medium ` +
    `across ${uris.length} config file(s)`;

  if (score >= 90) {
    void vscode.window.showInformationMessage(summary);
  } else {
    const choice = await vscode.window.showWarningMessage(summary, "Show findings");
    if (choice) {
      void vscode.commands.executeCommand("workbench.actions.view.problems");
    }
  }
}

function updateAggregate(): void {
  let total = 0;
  // Count every finding this extension owns across all open files.
  for (const [, diags] of vscode.languages.getDiagnostics()) {
    total += diags.filter((d) => d.source === "secure-ai-pipeline").length;
  }
  statusBar.update(total);
  findingsProvider.refresh();
}

function scanAllOpen(): void {
  for (const doc of vscode.workspace.textDocuments) {
    refreshDocument(doc);
  }
}

export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection("secure-ai-pipeline");
  statusBar = new StatusBar();
  findingsProvider = new FindingsProvider();

  context.subscriptions.push(
    diagnostics,
    statusBar,
    vscode.window.registerTreeDataProvider("securePipeline.findings", findingsProvider)
  );

  // Quick fixes for Python and JS/TS documents.
  const selector: vscode.DocumentSelector = [
    { language: "python" },
    { language: "javascript" },
    { language: "javascriptreact" },
    { language: "typescript" },
    { language: "typescriptreact" },
  ];
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      selector,
      new SecurityQuickFixProvider(),
      { providedCodeActionKinds: SecurityQuickFixProvider.providedCodeActionKinds }
    )
  );

  // Commands.
  context.subscriptions.push(
    vscode.commands.registerCommand("securePipeline.showProblems", () => {
      void vscode.commands.executeCommand("workbench.actions.view.problems");
    }),
    vscode.commands.registerCommand("securePipeline.scanWorkspace", () => {
      scanAllOpen();
    }),
    vscode.commands.registerCommand("securePipeline.blastRadius", () => {
      void runBlastRadius();
    })
  );

  // Event wiring.
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => refreshDocument(doc)),
    vscode.workspace.onDidOpenTextDocument((doc) => refreshDocument(doc)),
    vscode.workspace.onDidCloseTextDocument((doc) => {
      diagnostics.delete(doc.uri);
      updateAggregate();
    }),
    vscode.workspace.onDidChangeTextDocument((e) => {
      if (config().runOnType) {
        refreshDocument(e.document);
      }
    }),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("securePipeline")) {
        scanAllOpen();
      }
    })
  );

  // Initial scan of already-open files.
  scanAllOpen();
}

export function deactivate(): void {
  if (diagnostics) {
    diagnostics.clear();
    diagnostics.dispose();
  }
  if (statusBar) {
    statusBar.dispose();
  }
}
