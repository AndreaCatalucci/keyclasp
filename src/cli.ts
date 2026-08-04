#!/usr/bin/env node
import { initializeVault, getKey, getVaultLocation, storeSecret, listSecrets, resolveSecret, deleteSecret, isInitialized, closeDb, checkVaultDecryptability } from "./vault.js";
import { parseRunArgs, runCommandWithSecrets } from "./run.js";
import { getDisplayVersion } from "./version.js";
import readline from "node:readline";
import { stdin, stdout } from "node:process";

async function readPassphrase(prompt: string): Promise<string> {
  if (!stdin.isTTY) {
    const chunks: Buffer[] = [];
    for await (const chunk of stdin) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    return Buffer.concat(chunks).toString().trim();
  }
  return promptSecret(prompt);
}

function printHelp(): void {
  console.log(`
🔑 Keyclasp — Local encrypted credential vault for coding agents

Usage:
  keyclasp init                Initialize the encrypted vault
  keyclasp set <name>          Store a secret (value read from stdin)
  keyclasp set <name> -        Store a secret (prompts securely)
  keyclasp get <name>          Resolve and print a secret value
  keyclasp list                List all stored secret names
  keyclasp delete <name>       Delete a secret
  keyclasp run [--allow-unsafe] [--env SOURCE[:TARGET]] <command...>
                              Run a guarded command with secrets as env vars
  keyclasp status               Show vault status
  keyclasp version              Show Keyclasp version
  keyclasp help                 Show this help

Global flags:
  --version, -v               Show Keyclasp version

Examples:
  keyclasp init
  echo "sk-abc123" | keyclasp set OPENAI_API_KEY
  keyclasp set DATABASE_URL -
  keyclasp list
  keyclasp run -- npm test
  keyclasp run --env OPENAI_API_KEY:AI_KEY -- npm start
                              # Run with a one-off env mapping and leak-guarded output
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
        case "": // Ctrl+C
          stdin.removeListener("data", onData);
          stdin.pause();
          stdout.write("\n");
          rl.close();
          process.exit(1);
          break;
        case "": // Backspace
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

  if (command === "version" || command === "--version" || command === "-v") {
    console.log(getDisplayVersion());
    return;
  }

  if (!command || command === "help" || command === "--help" || command === "-h") {
    printHelp();
    return;
  }

  try {
    switch (command) {
      case "init": {
        if (isInitialized()) {
          console.log(`Keyclasp is already initialized. To reset, delete ${getVaultLocation()}`);
          return;
        }
        console.log(`🔑 Initializing Keyclasp vault...`);
        const passphrase = await readPassphrase("Enter vault passphrase (or empty for machine-only key): ");
        initializeVault(passphrase);
        getKey(); // Verify key works
        console.log(`Keyclasp vault created at ${getVaultLocation()}`);
        console.log("Next: store a secret with `keyclasp set <name>`, then use it with `keyclasp run`.");
        break;
      }

      case "set": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const name = args[1];
        if (!name) {
          console.error("Usage: keyclasp set <name>  OR  echo <value> | keyclasp set <name>");
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
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const secretName = args[1];
        if (!secretName) {
          console.error("Usage: keyclasp get <name>");
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
          console.error("Keyclasp not initialized. Run: keyclasp init");
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
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const delName = args[1];
        if (!delName) {
          console.error("Usage: keyclasp delete <name>");
          process.exit(1);
        }
        const deleted = deleteSecret(delName);
        console.log(deleted ? `Deleted "${delName}"` : `"${delName}" not found.`);
        break;
      }

      case "status": {
        if (!isInitialized()) {
          console.log("Keyclasp: not initialized");
          console.log("Run 'keyclasp init' to get started.");
          process.exit(1);
        }
        const names = listSecrets();
        console.log("Keyclasp Status");
        console.log("───────────────");
        console.log(`  Secrets:    ${names.length}`);
        console.log(`  Vault:      ${getVaultLocation()}`);
        try {
          const decryptability = checkVaultDecryptability();
          if (decryptability.checked === 0) {
            console.log("  Values:     no stored values to verify");
          } else if (decryptability.failures.length === 0) {
            console.log(`  Values:     verified (${decryptability.checked} decryptable)`);
          } else {
            console.log(`  Values:     FAILED (${decryptability.failures.length}/${decryptability.checked} undecryptable)`);
            process.exit(1);
          }
        } catch (err: any) {
          console.log(`  Values:     FAILED (${err?.message ?? "decryptability check failed"})`);
          process.exit(1);
        }
        break;
      }

      case "run": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const cmdArgs = args.slice(1);
        if (parseRunArgs(cmdArgs).commandArgs.length === 0) {
          console.error("Usage: keyclasp run [--allow-unsafe] [--env SOURCE[:TARGET]] <command...>");
          process.exit(1);
        }

        const result = await runCommandWithSecrets({
          args: cmdArgs,
          baseEnv: process.env,
          secretNames: listSecrets(),
          resolveSecret: (name) => resolveSecret(name),
          stdout: (chunk) => process.stdout.write(chunk),
          stderr: (chunk) => process.stderr.write(chunk),
        });
        process.exit(result.exitCode);
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
