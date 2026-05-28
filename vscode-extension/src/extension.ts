import * as vscode from "vscode";
import { execSync, spawn } from "child_process";

function keyblind(args: string): string {
  try {
    return execSync(`keyblind ${args}`, { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] }).trim();
  } catch {
    return "";
  }
}

function keyblindJson(args: string): any {
  try {
    const out = keyblind(args);
    return JSON.parse(out);
  } catch {
    return null;
  }
}

function isInstalled(): boolean {
  try {
    execSync("which keyblind", { encoding: "utf8", stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

class SecretsProvider implements vscode.TreeDataProvider<SecretItem> {
  private _onDidChange = new vscode.EventEmitter<SecretItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChange.event;

  refresh(): void {
    this._onDidChange.fire(undefined);
  }

  getTreeItem(element: SecretItem): vscode.TreeItem {
    return element;
  }

  async getChildren(): Promise<SecretItem[]> {
    if (!isInstalled()) {
      return [new SecretItem("Keyblind not installed", "Run: npm install -g keyblind", vscode.TreeItemCollapsibleState.None, "error")];
    }

    const data = keyblindJson("export");
    if (!data || !data.secrets || data.secrets.length === 0) {
      return [new SecretItem("No secrets stored", "Click + to add one", vscode.TreeItemCollapsibleState.None, "empty")];
    }

    return data.secrets.map((name: string) => {
      const item = new SecretItem(name, "Click to copy", vscode.TreeItemCollapsibleState.None, "secret");
      item.command = {
        command: "keyblind.resolveSecret",
        title: "Copy Secret",
        arguments: [name],
      };
      item.contextValue = "secret";
      return item;
    });
  }
}

class SecretItem extends vscode.TreeItem {
  constructor(
    label: string,
    description: string,
    collapsibleState: vscode.TreeItemCollapsibleState,
    context: string
  ) {
    super(label, collapsibleState);
    this.description = description;
    this.contextValue = context;

    switch (context) {
      case "secret":
        this.iconPath = new vscode.ThemeIcon("key");
        this.tooltip = `Secret: ${label}`;
        break;
      case "error":
        this.iconPath = new vscode.ThemeIcon("error");
        break;
      case "empty":
        this.iconPath = new vscode.ThemeIcon("info");
        break;
    }
  }
}

export function activate(context: vscode.ExtensionContext) {
  const provider = new SecretsProvider();

  context.subscriptions.push(
    vscode.window.registerTreeDataProvider("keyblind.secrets", provider)
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("keyblind.refresh", () => provider.refresh())
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("keyblind.sandbox", () => {
      const result = keyblind("sandbox");
      vscode.window.showInformationMessage(result || "Sandboxed .env");
      provider.refresh();
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("keyblind.unsandbox", () => {
      const result = keyblind("unsandbox");
      vscode.window.showInformationMessage(result || "Restored .env");
      provider.refresh();
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("keyblind.resolveSecret", async (name: string) => {
      const value = keyblind(`get ${name}`);
      if (value) {
        await vscode.env.clipboard.writeText(value);
        vscode.window.showInformationMessage(`Copied ${name} to clipboard`);
      } else {
        vscode.window.showErrorMessage(`Could not resolve ${name}`);
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("keyblind.storeSecret", async () => {
      const name = await vscode.window.showInputBox({
        prompt: "Secret name (e.g., OPENAI_API_KEY)",
        placeHolder: "OPENAI_API_KEY",
      });
      if (!name) return;

      const value = await vscode.window.showInputBox({
        prompt: `Value for ${name}`,
        password: true,
        placeHolder: "sk-proj-...",
      });
      if (!value) return;

      try {
        const proc = spawn("keyblind", ["set", name], { stdio: ["pipe", "pipe", "pipe"] });
        proc.stdin.write(value);
        proc.stdin.end();
        const stdout = await new Promise<string>((resolve) => {
          let out = "";
          proc.stdout.on("data", (d) => (out += d.toString()));
          proc.on("close", () => resolve(out.trim()));
        });
        vscode.window.showInformationMessage(stdout || `Stored ${name}`);
        provider.refresh();
      } catch {
        vscode.window.showErrorMessage(`Failed to store ${name}`);
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("keyblind.generateSecret", async () => {
      const name = await vscode.window.showInputBox({
        prompt: "Name for the generated secret",
        placeHolder: "SERVICE_API_KEY",
      });
      if (!name) return;

      const generated = keyblind(`generate ${name}`);
      if (generated) {
        await vscode.env.clipboard.writeText(generated);
        vscode.window.showInformationMessage(`Generated ${name} — copied to clipboard`);
        provider.refresh();
      } else {
        vscode.window.showErrorMessage("Generation failed — is keyblind initialized?");
      }
    })
  );

  // Status bar item
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.command = "keyblind.refresh";
  statusBar.text = "$(shield) Keyblind";
  statusBar.tooltip = "Keyblind — encrypted secrets vault";
  statusBar.show();
  context.subscriptions.push(statusBar);

  provider.refresh();
}

export function deactivate() {}
