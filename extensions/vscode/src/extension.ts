import * as vscode from "vscode";
import { scanDocument, langForDocument, RuleSeverity } from "./diagnostics";
import { SecurityQuickFixProvider } from "./quickfix";
import { StatusBar } from "./statusbar";
import { FindingsProvider } from "./sidebar";

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
  if (!langForDocument(doc)) {
    return;
  }
  const { enable, severity } = config();
  if (!enable) {
    diagnostics.set(doc.uri, []);
  } else {
    diagnostics.set(doc.uri, scanDocument(doc, severity));
  }
  updateAggregate();
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
