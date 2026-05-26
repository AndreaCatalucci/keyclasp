import * as vscode from "vscode";
import { execSync, spawn } from "child_process";
import path from "path";

function keyblindPath(): string {
  // Prefer local node_modules/.bin/keyblind, fall back to npx
  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (workspaceRoot) {
    const localBin = path.join(workspaceRoot, "node_modules", ".bin", "keyblind");
    try {
      execSync(`test -x "${localBin}"`);
      return localBin;
    } catch {
      // fall through
    }
  }
  return "keyblind"; // global install or npx
}

function getProjectFlag(): string[] {
  const projectName = vscode.workspace.getConfiguration("keyblind").get<string>("projectName");
  return projectName ? ["--project", projectName] : [];
}

async function runKeyblind(args: string[], showOutput = true): Promise<string> {
  const cmd = keyblindPath();
  const fullArgs = [...args, ...getProjectFlag()];

  return new Promise((resolve, reject) => {
    const child = spawn(cmd, fullArgs, { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (data: Buffer) => {
      stdout += data.toString();
    });
    child.stderr.on("data", (data: Buffer) => {
      stderr += data.toString();
    });

    child.on("close", (code: number | null) => {
      if (code === 0) {
        resolve(stdout.trim());
      } else {
        reject(new Error(stderr.trim() || stdout.trim() || `Exit code ${code}`));
      }
    });
  });
}

function updateStatusBar(statusBar: vscode.StatusBarItem): void {
  try {
    const result = execSync(`${keyblindPath()} list ${getProjectFlag().join(" ")}`, {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    });
    const lines = result.trim().split("\n");
    const count = lines.filter((l) => l.startsWith("  -")).length;
    statusBar.text = `$(shield) Keyblind: ${count} secrets`;
    statusBar.tooltip = `Keyblind vault active\n${count} secrets stored`;
    statusBar.backgroundColor = undefined;
  } catch {
    statusBar.text = `$(shield) Keyblind: not initialized`;
    statusBar.tooltip = "Keyblind vault not initialized. Click to set up.";
  }
}

export function activate(context: vscode.ExtensionContext): void {
  console.log("Keyblind extension activated");

  // Status bar item
  const statusBar = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right,
    100,
  );
  statusBar.command = "keyblind.listSecrets";
  context.subscriptions.push(statusBar);
  updateStatusBar(statusBar);

  // Refresh status bar every 30 seconds and on config change
  const interval = setInterval(() => updateStatusBar(statusBar), 30_000);
  context.subscriptions.push({ dispose: () => clearInterval(interval) });

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("keyblind")) {
        updateStatusBar(statusBar);
      }
    }),
  );

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand("keyblind.init", async () => {
      const passphrase = await vscode.window.showInputBox({
        prompt: "Enter vault passphrase (leave empty for machine-only key)",
        password: true,
        placeHolder: "Optional passphrase",
      });
      if (passphrase === undefined) return; // cancelled

      const terminal = vscode.window.createTerminal("Keyblind Init");
      terminal.show();
      terminal.sendText(`echo -n "${passphrase}" | keyblind init`);
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("keyblind.storeSecret", async () => {
      const name = await vscode.window.showInputBox({
        prompt: "Secret name (e.g., OPENAI_API_KEY)",
        placeHolder: "OPENAI_API_KEY",
      });
      if (!name) return;

      const value = await vscode.window.showInputBox({
        prompt: `Enter value for ${name}`,
        password: true,
      });
      if (!value) return;

      try {
        // Use a pipe to store the secret
        execSync(`echo -n "${value.replace(/"/g, '\\"')}" | ${keyblindPath()} set "${name}" ${getProjectFlag().join(" ")}`, {
          stdio: "pipe",
        });
        vscode.window.showInformationMessage(`Secret "${name}" stored.`);
        updateStatusBar(statusBar);
      } catch (err: any) {
        vscode.window.showErrorMessage(`Failed to store secret: ${err.message}`);
      }
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("keyblind.listSecrets", async () => {
      try {
        const output = await runKeyblind(["list"]);
        const panel = vscode.window.createOutputChannel("Keyblind Secrets");
        panel.clear();
        panel.appendLine("Keyblind Secrets");
        panel.appendLine("================");
        panel.appendLine(output || "(no secrets stored)");
        panel.show();
      } catch (err: any) {
        vscode.window.showErrorMessage(`Keyblind not initialized. Run "Keyblind: Initialize Vault" first.`);
      }
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("keyblind.sandbox", async () => {
      const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
      const envPath = workspaceRoot ? path.join(workspaceRoot, ".env") : undefined;

      try {
        const args = envPath ? ["sandbox", envPath] : ["sandbox"];
        const output = await runKeyblind(args);
        vscode.window.showInformationMessage(output);
        updateStatusBar(statusBar);
      } catch (err: any) {
        vscode.window.showErrorMessage(`Sandbox failed: ${err.message}`);
      }
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("keyblind.unsandbox", async () => {
      const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
      const envPath = workspaceRoot ? path.join(workspaceRoot, ".env") : undefined;

      try {
        const args = envPath ? ["unsandbox", envPath] : ["unsandbox"];
        const output = await runKeyblind(args);
        vscode.window.showInformationMessage(output);
      } catch (err: any) {
        vscode.window.showErrorMessage(`Unsandbox failed: ${err.message}`);
      }
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("keyblind.startServer", () => {
      const terminal = vscode.window.createTerminal("Keyblind MCP Server");
      terminal.show();
      terminal.sendText("keyblind start");
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("keyblind.watchEnv", () => {
      const terminal = vscode.window.createTerminal("Keyblind Watch");
      terminal.show();
      terminal.sendText("keyblind watch");
    }),
  );
}

export function deactivate(): void {
  // Cleanup handled by subscriptions
}
