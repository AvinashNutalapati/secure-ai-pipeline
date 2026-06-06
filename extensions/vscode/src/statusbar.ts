import * as vscode from "vscode";

/**
 * Bottom-right status bar item showing the total finding count across all
 * scanned files. Clicking it opens the Problems panel.
 */
export class StatusBar {
  private readonly item: vscode.StatusBarItem;

  constructor() {
    this.item = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Right,
      100
    );
    this.item.command = "securePipeline.showProblems";
    this.update(0);
    this.item.show();
  }

  update(count: number): void {
    if (count === 0) {
      this.item.text = "$(shield) SAP: clean";
      this.item.tooltip = "Secure AI Pipeline — no findings in open files";
      this.item.backgroundColor = undefined;
    } else {
      const noun = count === 1 ? "issue" : "issues";
      this.item.text = `$(shield) SAP: ${count} ${noun}`;
      this.item.tooltip = "Secure AI Pipeline — click to open the Problems panel";
      this.item.backgroundColor = new vscode.ThemeColor(
        "statusBarItem.warningBackground"
      );
    }
  }

  dispose(): void {
    this.item.dispose();
  }
}
