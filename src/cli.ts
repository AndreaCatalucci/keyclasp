#!/usr/bin/env node
import { initializeVault, getKey, storeSecret, listSecrets, resolveSecret, deleteSecret, isInitialized, closeDb } from "./vault.js";
import { startServer } from "./server.js";
import { sandboxEnvFile, unsandboxEnvFile } from "./sandbox.js";
import { setBackend, getBackend, listAvailableBackends } from "./backends.js";
import { spawn } from "node:child_process";
import readline from "node:readline";
import { stdin, stdout } from "node:process";

function printHelp(): void {
  console.log(`
🔑 Keyblind — Blind AI to your keys

Usage:
  keyblind init                Initialize the encrypted vault
  keyblind set <name>          Store a secret (value read from stdin)
  keyblind set <name> -        Store a secret (prompts securely)
  keyblind get <name>          Resolve and print a secret value
  keyblind list                List all stored secret names
  keyblind delete <name>       Delete a secret
  keyblind start               Start the MCP server (for AI agents)
  keyblind run <command...>    Run a command with secrets as env vars
  keyblind sandbox [.env]      Replace real env values with deterministic fakes
  keyblind unsandbox [.env]    Restore real env values from vault
  keyblind backends            List available secret backends
  keyblind help                Show this help

Examples:
  keyblind init
  echo "sk-abc123" | keyblind set OPENAI_API_KEY
  keyblind set DATABASE_URL -
  keyblind list
  keyblind sandbox             # Fake your .env, backup real values to vault
  keyblind run -- npm start    # Run with real secrets injected
  keyblind unsandbox           # Restore real .env values
  `);
}

async function promptSecret(prompt: string): Promise<string> {
  const rl = readline.createInterface({ input: stdin, output: stdout });

  return new Promise((resolve) => {
    // Output prompt manually so we can use stdout.moveCursor
    stdout.write(prompt);

    let value = "";

    // Track if we're reading
    const onData = (char: Buffer) => {
      const str = char.toString();
      switch (str) {
        case "\n":
        case "\r":
          stdin.removeListener("data", onData);
          stdin.pause();
          stdout.write("\n");
          rl.close();
          resolve(value.trim());
          break;
        case "": // Ctrl+C
          stdin.removeListener("data", onData);
          stdin.pause();
          stdout.write("\n");
          rl.close();
          process.exit(1);
          break;
        case "": // Backspace
          if (value.length > 0) {
            value = value.slice(0, -1);
            stdout.moveCursor(-1, 0);
            stdout.write(" ");
            stdout.moveCursor(-1, 0);
          }
          break;
        default:
          if (str >= " ") {
            value += str;
            stdout.write("*");
          }
          break;
      }
    };

    stdin.setRawMode?.(true);
    stdin.resume();
    stdin.on("data", onData);
  });
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === "help" || command === "--help" || command === "-h") {
    printHelp();
    return;
  }

  try {
    switch (command) {
      case "init": {
        if (isInitialized()) {
          console.log("Keyblind is already initialized. To reset, delete ~/.keyblind/");
          return;
        }
        console.log("🔑 Initializing Keyblind vault...");
        const passphrase = await promptSecret("Enter vault passphrase (or empty for machine-only key): ");
        initializeVault(passphrase);
        getKey(); // Verify key works
        console.log("Keyblind vault created at ~/.keyblind/");
        console.log("Add this to your Claude Code config (~/.claude/settings.json):");
        console.log(`
  {
    "mcpServers": {
      "keyblind": {
        "command": "npx",
        "args": ["keyblind", "start"]
      }
    }
  }`);
        break;
      }

      case "set": {
        if (!isInitialized()) {
          console.error("Keyblind not initialized. Run: keyblind init");
          process.exit(1);
        }
        const name = args[1];
        if (!name) {
          console.error("Usage: keyblind set <name>  OR  echo <value> | keyblind set <name>");
          process.exit(1);
        }

        let value: string;
        if (args[2] === "-") {
          value = await promptSecret(`Enter value for ${name}: `);
        } else if (!stdin.isTTY) {
          // Read from pipe
          const chunks: Buffer[] = [];
          for await (const chunk of stdin) {
            chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
          }
          value = Buffer.concat(chunks).toString().trim();
        } else {
          value = await promptSecret(`Enter value for ${name}: `);
        }

        if (!value) {
          console.error("No value provided.");
          process.exit(1);
        }

        storeSecret(name, value);
        console.log(`Stored "${name}"`);
        break;
      }

      case "get": {
        if (!isInitialized()) {
          console.error("Keyblind not initialized. Run: keyblind init");
          process.exit(1);
        }
        const secretName = args[1];
        if (!secretName) {
          console.error("Usage: keyblind get <name>");
          process.exit(1);
        }
        const val = resolveSecret(secretName);
        if (val === null) {
          console.error(`Secret "${secretName}" not found.`);
          process.exit(1);
        }
        console.log(val);
        break;
      }

      case "list": {
        if (!isInitialized()) {
          console.error("Keyblind not initialized. Run: keyblind init");
          process.exit(1);
        }
        const names = listSecrets();
        if (names.length === 0) {
          console.log("(no secrets stored)");
        } else {
          names.forEach((n) => console.log(`  - ${n}`));
        }
        break;
      }

      case "delete": {
        if (!isInitialized()) {
          console.error("Keyblind not initialized. Run: keyblind init");
          process.exit(1);
        }
        const delName = args[1];
        if (!delName) {
          console.error("Usage: keyblind delete <name>");
          process.exit(1);
        }
        const deleted = deleteSecret(delName);
        console.log(deleted ? `Deleted "${delName}"` : `"${delName}" not found.`);
        break;
      }

      case "sandbox": {
        if (!isInitialized()) {
          console.error("Keyblind not initialized. Run: keyblind init");
          process.exit(1);
        }
        const envFile = args[1];
        const result = sandboxEnvFile(envFile);
        console.log(`Sandboxed ${result.sandboxed.length} value(s) in ${envFile || ".env"}:`);
        for (const key of result.sandboxed) {
          console.log(`  - ${key} → fake (real value backed up to vault)`);
        }
        break;
      }

      case "unsandbox": {
        if (!isInitialized()) {
          console.error("Keyblind not initialized. Run: keyblind init");
          process.exit(1);
        }
        const envFile = args[1];
        const restored = unsandboxEnvFile(envFile);
        console.log(`Restored ${restored.length} value(s) in ${envFile || ".env"}:`);
        for (const key of restored) {
          console.log(`  - ${key} → real`);
        }
        break;
      }

      case "backends": {
        const backends = listAvailableBackends();
        console.log("Available backends:");
        for (const b of backends) {
          const status = b.available ? "✓" : "✗ (not installed)";
          console.log(`  ${status} ${b.name}`);
        }
        break;
      }

      case "backend": {
        const backendName = args[1];
        if (!backendName) {
          console.error("Usage: keyblind backend <name>");
          console.error("Available:", listAvailableBackends().filter(b => b.available).map(b => b.name).join(", "));
          process.exit(1);
        }
        setBackend(backendName);
        console.log(`Switched to backend: ${backendName}`);
        break;
      }

      case "start": {
        if (!isInitialized()) {
          console.error("Keyblind not initialized. Run: keyblind init");
          process.exit(1);
        }
        // Verify key works before starting
        getKey();
        await startServer();
        break;
      }

      case "run": {
        if (!isInitialized()) {
          console.error("Keyblind not initialized. Run: keyblind init");
          process.exit(1);
        }
        const cmdArgs = args.slice(1).filter((a) => a !== "--");
        if (cmdArgs.length === 0) {
          console.error("Usage: keyblind run <command...>");
          process.exit(1);
        }

        const env = { ...process.env };
        for (const name of listSecrets()) {
          const value = resolveSecret(name);
          if (value !== null) {
            env[name] = value;
          }
        }

        const [cmd, ...rest] = cmdArgs;
        const child = spawn(cmd, rest, {
          stdio: "inherit",
          env,
        });

        child.on("exit", (code) => {
          process.exit(code ?? 0);
        });
        break;
      }

      default:
        console.error(`Unknown command: ${command}`);
        printHelp();
        process.exit(1);
    }
  } finally {
    closeDb();
  }
}

main().catch((err) => {
  console.error("Error:", err.message);
  closeDb();
  process.exit(1);
});
