import * as vscode from "vscode";
import { RULES, SecurityRule, langForDocument } from "./diagnostics";

/**
 * Provides Quick Fixes for diagnostics emitted by this extension. Each fix
 * replaces the offending substring with the secure equivalent.
 */
export class SecurityQuickFixProvider implements vscode.CodeActionProvider {
  static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diag of context.diagnostics) {
      if (diag.source !== "secure-ai-pipeline" || typeof diag.code !== "string") {
        continue;
      }
      const rule = RULES.find((r) => r.id === diag.code);
      if (!rule || !rule.fix) {
        continue;
      }
      const action = this.buildAction(document, diag, rule);
      if (action) {
        actions.push(action);
      }
    }
    return actions;
  }

  private buildAction(
    document: vscode.TextDocument,
    diag: vscode.Diagnostic,
    rule: SecurityRule
  ): vscode.CodeAction | undefined {
    const lang = langForDocument(document);
    if (!lang) {
      return undefined;
    }
    const targetText = document.getText(diag.range);
    const fix = rule.fix!(targetText, lang);

    const action = new vscode.CodeAction(fix.title, vscode.CodeActionKind.QuickFix);
    action.diagnostics = [diag];
    action.isPreferred = true;
    action.edit = new vscode.WorkspaceEdit();
    action.edit.replace(document.uri, diag.range, fix.replacement);

    // Insert a required import if it isn't already there — after the shebang,
    // encoding comment, module docstring, and any `from __future__` imports
    // (inserting at 0,0 would corrupt those files).
    if (fix.ensureImport && !this.hasImport(document, fix.ensureImport)) {
      const line = this.importInsertLine(document);
      action.edit.insert(document.uri, new vscode.Position(line, 0), `${fix.ensureImport}\n`);
    }
    return action;
  }

  private hasImport(document: vscode.TextDocument, importLine: string): boolean {
    const needle = importLine.trim();
    for (let i = 0; i < document.lineCount; i++) {
      if (document.lineAt(i).text.trim() === needle) {
        return true;
      }
    }
    return false;
  }

  /** First line where an import can legally be inserted. */
  private importInsertLine(document: vscode.TextDocument): number {
    let line = 0;
    const headerMax = Math.min(document.lineCount, 50);

    // Shebang and PEP 263 encoding comments.
    while (line < headerMax && /^#(?:!|.*coding[:=])/.test(document.lineAt(line).text)) {
      line++;
    }

    // Module docstring (''' or """, possibly multi-line).
    if (line < headerMax) {
      const text = document.lineAt(line).text.trimStart();
      const open = /^[rubf]*("""|''')/i.exec(text);
      if (open) {
        const quote = open[1];
        const afterOpen = text.slice(text.indexOf(quote) + quote.length);
        if (!afterOpen.includes(quote)) {
          line++;
          while (line < document.lineCount && !document.lineAt(line).text.includes(quote)) {
            line++;
          }
        }
        line = Math.min(line + 1, document.lineCount);
      }
    }

    // Blank lines and `from __future__` imports directly after the header.
    while (line < document.lineCount) {
      const t = document.lineAt(line).text.trim();
      if (t === "" || t.startsWith("from __future__ import")) {
        line++;
      } else {
        break;
      }
    }
    return line;
  }
}
