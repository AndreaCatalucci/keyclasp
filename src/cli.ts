#!/usr/bin/env node
import { initializeVault, getKey, getVaultLocation, storeSecret, listSecrets, resolveSecret, deleteSecret, isInitialized, closeDb, checkVaultDecryptability } from "./vault.js";
import { parseRunArgs, runCommandWithSecrets } from "./run.js";
import { getDisplayVersion } from "./version.js";
import { resolveSecretForOperator } from "./biometric.js";
import { extractScopeFlags, resolveScope } from "./scope.js";
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
  keyclasp set [scope] <name>  Store a secret (value read from stdin)
  keyclasp set [scope] <name> -
                              Store a secret (prompts securely)
  keyclasp get [scope] <name>  Print a secret after macOS Touch ID approval
  keyclasp list [scope]        List secret names in the selected scope
  keyclasp delete [scope] <name>
                              Delete a secret in the selected scope
  keyclasp run [scope] [--allow-unsafe] [--env SOURCE[:TARGET]] <command...>
                              Run a guarded command with secrets as env vars
  keyclasp status [scope]       Show vault status
  keyclasp version              Show Keyclasp version
  keyclasp help                 Show this help

Scope flags (after command):
  --project, -p <name>        Select project (default: default)
  --environment, -E <name>    Select environment (default: default)

Version flag:
  --version, -v               Show Keyclasp version

Examples:
  keyclasp init
  echo "sk-abc123" | keyclasp set --project app --environment dev OPENAI_API_KEY
  keyclasp set --project app --environment prod DATABASE_URL -
  keyclasp list --project app --environment prod
  keyclasp run --project app --environment prod -- npm test
                              # Whole-scope injection requires Touch ID
  keyclasp run --project app --environment prod --env OPENAI_API_KEY:AI_KEY -- npm start
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
        console.log("Next: store a scoped secret with `keyclasp set --project <name> --environment <name> <secret>`, then use it with `keyclasp run`.");
        break;
      }

      case "set": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const extracted = extractScopeFlags(args.slice(1));
        const scope = resolveScope(extracted.project, extracted.environment);
        const name = extracted.rest[0];
        if (!name) {
          console.error("Usage: keyclasp set [--project NAME] [--environment NAME] <name>");
          process.exit(1);
        }

        let value: string;
        if (extracted.rest[1] === "-") {
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

        storeSecret(scope.project, scope.environment, name, value);
        console.log(`Stored "${name}" in ${scope.project}/${scope.environment}`);
        break;
      }

      case "get": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const extracted = extractScopeFlags(args.slice(1));
        const scope = resolveScope(extracted.project, extracted.environment);
        const secretName = extracted.rest[0];
        if (!secretName) {
          console.error("Usage: keyclasp get [--project NAME] [--environment NAME] <name>");
          process.exit(1);
        }
        const val = resolveSecretForOperator(
          `${scope.project}/${scope.environment}/${secretName}`,
          () => resolveSecret(scope.project, scope.environment, secretName),
        );
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
        const extracted = extractScopeFlags(args.slice(1));
        const scope = resolveScope(extracted.project, extracted.environment);
        const names = listSecrets(scope.project, scope.environment);
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
        const extracted = extractScopeFlags(args.slice(1));
        const scope = resolveScope(extracted.project, extracted.environment);
        const delName = extracted.rest[0];
        if (!delName) {
          console.error("Usage: keyclasp delete [--project NAME] [--environment NAME] <name>");
          process.exit(1);
        }
        const deleted = deleteSecret(scope.project, scope.environment, delName);
        console.log(deleted ? `Deleted "${delName}"` : `"${delName}" not found.`);
        break;
      }

      case "status": {
        if (!isInitialized()) {
          console.log("Keyclasp: not initialized");
          console.log("Run 'keyclasp init' to get started.");
          process.exit(1);
        }
        const extracted = extractScopeFlags(args.slice(1));
        const scope = resolveScope(extracted.project, extracted.environment);
        const names = listSecrets(scope.project, scope.environment);
        console.log("Keyclasp Status");
        console.log("───────────────");
        console.log(`  Scope:      ${scope.project}/${scope.environment}`);
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
        const parsed = parseRunArgs(cmdArgs);
        const scope = resolveScope(parsed.project, parsed.environment);
        if (parsed.commandArgs.length === 0) {
          console.error("Usage: keyclasp run [--project NAME] [--environment NAME] [--allow-unsafe] [--env SOURCE[:TARGET]] <command...>");
          process.exit(1);
        }

        const result = await runCommandWithSecrets({
          args: cmdArgs,
          baseEnv: process.env,
          secretNames: listSecrets(scope.project, scope.environment),
          resolveSecret: (name) => resolveSecret(scope.project, scope.environment, name),
          stdout: (chunk) => process.stdout.write(chunk),
          stderr: (chunk) => process.stderr.write(chunk),
          scopeLabel: `${scope.project}/${scope.environment}`,
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
