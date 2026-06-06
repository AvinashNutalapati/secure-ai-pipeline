import * as vscode from "vscode";
import * as path from "path";

type Node = RuleGroup | FindingItem;

class RuleGroup extends vscode.TreeItem {
  constructor(public readonly ruleId: string, public readonly findings: FindingItem[]) {
    super(`${ruleId}  (${findings.length})`, vscode.TreeItemCollapsibleState.Expanded);
    this.contextValue = "ruleGroup";
    this.iconPath = new vscode.ThemeIcon("shield");
  }
}

class FindingItem extends vscode.TreeItem {
  constructor(
    public readonly uri: vscode.Uri,
    public readonly diag: vscode.Diagnostic,
    public readonly ruleId: string
  ) {
    const fileName = path.basename(uri.fsPath);
    const line = diag.range.start.line + 1;
    super(`${fileName}:${line}`, vscode.TreeItemCollapsibleState.None);
    this.description = diag.message;
    this.tooltip = diag.message;
    this.iconPath = new vscode.ThemeIcon(
      diag.severity === vscode.DiagnosticSeverity.Error ? "error" : "warning"
    );
    this.command = {
      command: "vscode.open",
      title: "Open finding",
      arguments: [
        uri,
        { selection: diag.range } as vscode.TextDocumentShowOptions,
      ],
    };
  }
}

/**
 * Activity-bar tree of every finding in open files, grouped by rule id.
 */
export class FindingsProvider implements vscode.TreeDataProvider<Node> {
  private readonly _onDidChange = new vscode.EventEmitter<Node | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChange.event;

  refresh(): void {
    this._onDidChange.fire();
  }

  getTreeItem(element: Node): vscode.TreeItem {
    return element;
  }

  getChildren(element?: Node): Node[] {
    if (element instanceof RuleGroup) {
      return element.findings;
    }
    if (element instanceof FindingItem) {
      return [];
    }
    return this.buildGroups();
  }

  private buildGroups(): RuleGroup[] {
    const byRule = new Map<string, FindingItem[]>();

    for (const [uri, diags] of vscode.languages.getDiagnostics()) {
      for (const diag of diags) {
        if (diag.source !== "secure-ai-pipeline" || typeof diag.code !== "string") {
          continue;
        }
        const item = new FindingItem(uri, diag, diag.code);
        const list = byRule.get(diag.code) ?? [];
        list.push(item);
        byRule.set(diag.code, list);
      }
    }

    return [...byRule.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([ruleId, findings]) => new RuleGroup(ruleId, findings));
  }
}
