#!/usr/bin/env node
import { initializeVault, getKey, getVaultLocation, storeSecret, listSecrets, resolveSecret, resolveSecretWithAlias, createAlias, deleteAlias, listAliases, deleteSecret, isInitialized, closeDb, setProjectName, getProjectName, getAuditLog, checkExpired, setExpiry, checkVaultDecryptability } from "./vault.js";
import { sandboxEnvFile, unsandboxEnvFile } from "./sandbox.js";
import { setBackend, getBackend, listAvailableBackends } from "./backends.js";
import { installHook, checkAndReport, getStagedFiles, scanFiles } from "./hook.js";
import { watchEnvFile } from "./watch.js";
import { readConfig, mergeConfig, generateSecret, parseEnvFile, formatEnvFile } from "./config.js";
import { runDoctor } from "./doctor.js";
import { generateBash, generateZsh, generateFish, detectShell, getInstallInstructions } from "./completions.js";
import { saveHistory, getSecretHistory, rollbackSecret, ensureHistoryTable, getExpiringSoon, createSyncBundle, applySyncBundle, migrateSecrets, rotateLocalSecret } from "./sync.js";
import { storeTOTP, getTOTP, listTOTP, deleteTOTP, generateTOTPCode, parseOTPAuthURI } from "./totp.js";
import { createShareLink, receiveShare } from "./share.js";
import { parseRunArgs, runCommandWithSecrets } from "./run.js";
import { getDisplayVersion } from "./version.js";
import fs from "node:fs";
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
🔑 Keyclasp — Runtime secrets for coding agents

Usage:
  keyclasp init                Initialize the encrypted vault
  keyclasp set <name>          Store a secret (value read from stdin)
  keyclasp set <name> -        Store a secret (prompts securely)
  keyclasp get <name>          Resolve and print a secret value
  keyclasp list                List all stored secret names
  keyclasp alias <target> <alias>  Create an alias that points to a stored secret
  keyclasp aliases             List secret aliases
  keyclasp unalias <alias>     Delete a secret alias
  keyclasp delete <name>       Delete a secret
  keyclasp run [--allow-unsafe] [--env SOURCE[:TARGET]] <command...>
                              Run a guarded command with secrets as env vars
  keyclasp sandbox [.env]      Replace real env values with deterministic fakes
  keyclasp unsandbox [.env]    Restore real env values from vault
  keyclasp backends            List available secret backends
  keyclasp install-hook        Install pre-commit hook to detect secrets
  keyclasp check-secrets       Scan staged files for secrets (used by hook)
  keyclasp scan-secrets <file...>  Scan specific files for secrets
  keyclasp backend <name>      Switch active secret backend
  keyclasp audit               Show secret resolution audit log
  keyclasp check --expired     List secrets past their expiry date
  keyclasp rotate <name>       Update a secret (prompts for new value)
  keyclasp watch [.env]        Watch .env and auto-sandbox on change
  keyclasp status              Show vault status
  keyclasp generate <name>     Generate a strong random secret
  keyclasp generate <name> --len 64    Generate with custom length
  keyclasp generate <name> --no-symbols   Alphanumeric only
  keyclasp import [.env]        Bulk import secrets from a .env file
  keyclasp export               Export all secrets (use --json for raw JSON)
  keyclasp export --env         Export as .env format
  keyclasp config               Show project config (.keyclasp)
  keyclasp config <key> <val>   Set a config option (backend, projectName, expiryDays, autoSandbox)
  keyclasp doctor               Run vault health and security check
  keyclasp completions [bash|zsh|fish]  Generate shell completion script
  keyclasp history <name>    Show version history for a secret
  keyclasp rollback <name>   Restore previous version of a secret
  keyclasp expiring          List secrets expiring within 30 days
  keyclasp sync export       Create encrypted sync bundle
  keyclasp sync import <file> Apply a sync bundle from another machine
  keyclasp migrate <from> <to> Migrate secrets between backends
  keyclasp totp set <name>   Store a TOTP 2FA config (from otpauth:// URI)
  keyclasp totp code <name>  Generate current TOTP code with countdown
  keyclasp totp list          List all TOTP configurations
  keyclasp totp delete <name> Delete a TOTP config
  keyclasp share <name>       Create encrypted expiring share link
  keyclasp share <name> --ttl 7d --max-views 3   Custom TTL and view limit
  keyclasp receive <url>      Receive and store a shared secret
  keyclasp version            Show Keyclasp version
  keyclasp help                Show this help

Global flags:
  --version, -v               Show Keyclasp version
  --project <name>            Use a project-specific vault (isolated per project)

Examples:
  keyclasp init
  echo "sk-abc123" | keyclasp set OPENAI_API_KEY
  keyclasp set DATABASE_URL -
  keyclasp list
  keyclasp alias OPENAI_API_KEY AI_KEY
  keyclasp sandbox             # Fake your .env, backup real values to vault
  keyclasp run --env OPENAI_API_KEY:AI_KEY -- npm start
                              # Run with one-off env mapping and leak-guarded output
  keyclasp unsandbox           # Restore real .env values
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
  const rawArgs = process.argv.slice(2);

  // Parse --project flag
  const projectIdx = rawArgs.indexOf("--project");
  if (projectIdx !== -1 && projectIdx + 1 < rawArgs.length) {
    const projectName = rawArgs[projectIdx + 1];
    setProjectName(projectName);
    rawArgs.splice(projectIdx, 2); // Remove --project and its value
  }

  const args = rawArgs;
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
    const projectLabel = getProjectName() ? ` [project: ${getProjectName()}]` : "";

    switch (command) {
      case "init": {
        if (isInitialized()) {
          console.log(`Keyclasp is already initialized${projectLabel}. To reset, delete ${getVaultLocation()}`);
          return;
        }
        console.log(`🔑 Initializing Keyclasp vault${projectLabel}...`);
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
        const val = resolveSecretWithAlias(secretName).value;
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

      case "alias": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const target = args[1];
        const alias = args[2];
        if (!target || !alias) {
          console.error("Usage: keyclasp alias <target> <alias>");
          process.exit(1);
        }
        createAlias(alias, target);
        console.log(`Alias "${alias}" -> "${target}"`);
        break;
      }

      case "aliases": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const aliases = listAliases();
        if (aliases.length === 0) {
          console.log("(no aliases stored)");
        } else {
          aliases.forEach((entry) => console.log(`  - ${entry.alias} -> ${entry.target}`));
        }
        break;
      }

      case "unalias": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const alias = args[1];
        if (!alias) {
          console.error("Usage: keyclasp unalias <alias>");
          process.exit(1);
        }
        const deleted = deleteAlias(alias);
        console.log(deleted ? `Deleted alias "${alias}"` : `Alias "${alias}" not found.`);
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

      case "sandbox": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
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

      case "watch": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        watchEnvFile(args[1]);
        break;
      }

      case "unsandbox": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
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

      case "install-hook": {
        try {
          const hookPath = installHook();
          console.log(`Pre-commit hook installed at ${hookPath}`);
          console.log("The hook will scan staged files for secrets before each commit.");
        } catch (err: any) {
          console.error(err.message);
          process.exit(1);
        }
        break;
      }

      case "check-secrets": {
        const result = checkAndReport();
        if (result.found > 0) {
          console.log(result.output);
          process.exit(1);
        }
        break;
      }

      case "scan-secrets": {
        const files = args.slice(1);
        if (files.length === 0) {
          console.error("Usage: keyclasp scan-secrets <file...>");
          process.exit(1);
        }
        const findings = scanFiles(files);
        if (findings.length === 0) {
          console.log("No secrets found.");
        } else {
          for (const f of findings) {
            console.log(`${f.file}:${f.line} [${f.pattern}] ${f.match}`);
          }
        }
        break;
      }

      case "backend": {
        const backendName = args[1];
        if (!backendName) {
          console.error("Usage: keyclasp backend <name>");
          console.error("Available:", listAvailableBackends().filter(b => b.available).map(b => b.name).join(", "));
          process.exit(1);
        }
        setBackend(backendName);
        console.log(`Switched to backend: ${backendName}`);
        break;
      }

      case "audit": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const entries = getAuditLog(50);
        if (entries.length === 0) {
          console.log("(no audit entries yet)");
        } else {
          for (const e of entries) {
            console.log(`  ${e.timestamp}  ${e.action.padEnd(8)} ${e.secretName}`);
          }
        }
        break;
      }

      case "check": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        if (args[1] === "--expired") {
          const expired = checkExpired();
          if (expired.length === 0) {
            console.log("No expired secrets.");
          } else {
            console.log(`${expired.length} expired secret(s):`);
            for (const name of expired) {
              console.log(`  - ${name}`);
            }
          }
        } else {
          console.error("Usage: keyclasp check --expired");
          process.exit(1);
        }
        break;
      }

      case "rotate": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const rotateName = args[1];
        if (!rotateName) {
          console.error("Usage: keyclasp rotate <name>");
          process.exit(1);
        }
        const newValue = await readPassphrase(`Enter new value for ${rotateName}: `);
        if (!newValue) {
          console.error("No value provided.");
          process.exit(1);
        }
        if (!rotateLocalSecret(rotateName, newValue)) {
          console.error(`Secret "${rotateName}" not found.`);
          process.exit(1);
        }
        console.log(`Rotated "${rotateName}"`);
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
        const backend = getBackend();
        console.log(`  Backend:    ${backend.name}`);
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
          secretNames: [...listSecrets(), ...listAliases().map((entry) => entry.alias)],
          resolveSecret: (name) => resolveSecretWithAlias(name).value,
          stdout: (chunk) => process.stdout.write(chunk),
          stderr: (chunk) => process.stderr.write(chunk),
        });
        process.exit(result.exitCode);
        break;
      }

      case "generate": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const genName = args[1];
        if (!genName) {
          console.error("Usage: keyclasp generate <name> [--len 32] [--no-symbols]");
          process.exit(1);
        }
        const lenIdx = args.indexOf("--len");
        const length = lenIdx !== -1 ? parseInt(args[lenIdx + 1], 10) || 32 : 32;
        const noSymbols = args.includes("--no-symbols");
        const generated = generateSecret(length, !noSymbols);
        storeSecret(genName, generated);
        console.log(generated);
        break;
      }

      case "import": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const importFile = args[1] || ".env";
        if (!fs.existsSync(importFile)) {
          console.error(`File not found: ${importFile}`);
          process.exit(1);
        }
        const content = fs.readFileSync(importFile, "utf8");
        const envVars = parseEnvFile(content);
        if (Object.keys(envVars).length === 0) {
          console.log("No KEY=value pairs found in file.");
          process.exit(0);
        }
        let imported = 0;
        for (const [key, value] of Object.entries(envVars)) {
          try {
            storeSecret(key, value);
            imported++;
          } catch (err: any) {
            console.error(`  Skipped ${key}: ${err.message}`);
          }
        }
        console.log(`Imported ${imported}/${Object.keys(envVars).length} secret(s) from ${importFile}`);
        break;
      }

      case "export": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const names = listSecrets();
        if (args.includes("--env")) {
          // Export as .env format
          const envObj: Record<string, string> = {};
          for (const name of names) {
            const val = resolveSecret(name);
            if (val !== null) envObj[name] = val;
          }
          process.stdout.write(formatEnvFile(envObj));
        } else if (args.includes("--json")) {
          // Export as raw JSON (unencrypted)
          const jsonObj: Record<string, string> = {};
          for (const name of names) {
            const val = resolveSecret(name);
            if (val !== null) jsonObj[name] = val;
          }
          process.stdout.write(JSON.stringify(jsonObj, null, 2) + "\n");
        } else {
          // Default: names only (safe)
          console.log(JSON.stringify({ secrets: names }, null, 2));
        }
        break;
      }

      case "config": {
        const configKey = args[1];
        const configVal = args[2] || (configKey && !args[2] ? args.slice(1).join(" ") : undefined);

        if (!configKey) {
          // Show current config
          const cfg = readConfig();
          if (cfg) {
            console.log("Project config (.keyclasp):");
            const validKeys: (keyof typeof cfg)[] = ["projectName", "backend", "expiryDays", "autoSandbox", "watchPath"];
            for (const key of validKeys) {
              if (cfg[key] !== undefined) {
                console.log(`  ${key}: ${cfg[key]}`);
              }
            }
          } else {
            console.log("No project config found. Create one with:");
            console.log("  keyclasp config backend local");
            console.log("  keyclasp config expiryDays 90");
          }
          break;
        }

        if (!configVal) {
          // Show single value
          const cfg = readConfig();
          if (cfg && (cfg as any)[configKey] !== undefined) {
            console.log(`${(cfg as any)[configKey]}`);
          } else {
            process.exit(1);
          }
          break;
        }

        // Set value
        const update: Record<string, any> = {};
        if (configKey === "expiryDays" || configKey === "expiry") {
          update.expiryDays = parseInt(configVal, 10);
        } else if (configKey === "autoSandbox") {
          update.autoSandbox = configVal === "true" || configVal === "1";
        } else if (configKey === "projectName" || configKey === "backend" || configKey === "watchPath") {
          update[configKey] = configVal;
        } else {
          console.error(`Unknown config key: ${configKey}`);
          console.error("Available: backend, projectName, expiryDays, autoSandbox, watchPath");
          process.exit(1);
        }
        mergeConfig(update);
        break;
      }

      case "doctor": {
        const checks = runDoctor();
        let ok = 0, warn = 0, err = 0;
        for (const c of checks) {
          const icon = c.status === "ok" ? "✓" : c.status === "warn" ? "⚠" : "✗";
          console.log(`  ${icon} ${c.name.padEnd(20)} ${c.detail}`);
          if (c.status === "ok") ok++;
          else if (c.status === "warn") warn++;
          else err++;
        }
        console.log(`\n${ok} ok, ${warn} warnings, ${err} errors`);
        if (err > 0) process.exit(1);
        break;
      }

      case "completions": {
        const shell = args[1] || detectShell();
        if (!shell) {
          console.error("Could not detect shell. Specify: keyclasp completions <bash|zsh|fish>");
          process.exit(1);
        }
        switch (shell) {
          case "bash":
            console.log(generateBash());
            break;
          case "zsh":
            console.log(generateZsh());
            break;
          case "fish":
            console.log(generateFish());
            break;
          default:
            console.error(`Unknown shell: ${shell}. Use bash, zsh, or fish.`);
            process.exit(1);
        }
        console.error(`\n# ${getInstallInstructions(shell)}`);
        break;
      }

      case "history": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const histName = args[1];
        if (!histName) {
          console.error("Usage: keyclasp history <name>");
          process.exit(1);
        }
        const versions = getSecretHistory(histName);
        if (versions.length === 0) {
          console.log(`No history for "${histName}"`);
        } else {
          for (const v of versions) {
            console.log(`  v${v.version}  ${v.createdAt}  **** (${v.value.length} chars)`);
          }
        }
        break;
      }

      case "rollback": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const rbName = args[1];
        if (!rbName) {
          console.error("Usage: keyclasp rollback <name> [version]");
          process.exit(1);
        }
        const rbVersion = args[2] ? parseInt(args[2], 10) : undefined;
        const ok = rollbackSecret(rbName, rbVersion);
        if (ok) {
          console.log(`Rolled back "${rbName}"${rbVersion ? ` to v${rbVersion}` : " to previous version"}`);
        } else {
          console.error(`No history found for "${rbName}"`);
          process.exit(1);
        }
        break;
      }

      case "expiring": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const daysThreshold = parseInt(args[1], 10) || 30;
        const warnings = getExpiringSoon(daysThreshold);
        if (warnings.length === 0) {
          console.log(`No secrets expiring within ${daysThreshold} days.`);
        } else {
          console.log(`${warnings.length} secret(s) expiring within ${daysThreshold} days:`);
          for (const w of warnings) {
            const urgency = w.daysLeft <= 7 ? "URGENT" : w.daysLeft <= 14 ? "SOON" : "UPCOMING";
            console.log(`  ${urgency.padEnd(9)} ${w.name.padEnd(30)} ${w.daysLeft}d left (expires ${w.expiresAt})`);
          }
        }
        break;
      }

      case "sync": {
        const syncSub = args[1];
        if (!syncSub) {
          console.error("Usage: keyclasp sync <export|import>");
          process.exit(1);
        }
        if (syncSub === "export") {
          const bundle = createSyncBundle();
          console.log(bundle);
          console.error("\n# Share this file to sync vaults between machines.");
          console.error("# The bundle is encrypted — only machines with the same vault key can decrypt it.");
        } else if (syncSub === "import") {
          const syncFile = args[2];
          let bundleJson: string;
          try {
            bundleJson = syncFile
              ? fs.readFileSync(syncFile, "utf8")
              : await readPassphrase("Paste sync bundle: ");
          } catch {
            console.error("Could not read sync bundle.");
            process.exit(1);
          }
          try {
            const result = applySyncBundle(bundleJson);
            console.log(`Synced: ${result.imported} imported, ${result.skipped} skipped (up-to-date)`);
          } catch (err: any) {
            console.error(`Sync failed: ${err.message}`);
            process.exit(1);
          }
        } else {
          console.error(`Unknown sync command: ${syncSub}. Use export or import.`);
          process.exit(1);
        }
        break;
      }

      case "migrate": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const from = args[1];
        const to = args[2];
        if (!from || !to) {
          console.error("Usage: keyclasp migrate <from-backend> <to-backend>");
          console.error("Available:", listAvailableBackends().filter(b => b.available).map(b => b.name).join(", "));
          process.exit(1);
        }
        try {
          const result = migrateSecrets(from, to);
          console.log(`Migrated ${result.migrated} secret(s) from ${from} to ${to}`);
          if (result.failed.length > 0) {
            console.log(`Failed: ${result.failed.join(", ")}`);
          }
        } catch (err: any) {
          console.error(`Migration failed: ${err.message}`);
          process.exit(1);
        }
        break;
      }

      case "totp": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const totpSub = args[1];
        if (!totpSub) {
          console.error("Usage: keyclasp totp <set|code|list|delete|qr>");
          process.exit(1);
        }

        switch (totpSub) {
          case "set": {
            const totpName = args[2];
            if (!totpName) {
              console.error("Usage: keyclasp totp set <name> [otpauth-uri]");
              process.exit(1);
            }
            let uri = args[3];
            if (!uri) {
              if (!stdin.isTTY) {
                const chunks: Buffer[] = [];
                for await (const chunk of stdin) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
                uri = Buffer.concat(chunks).toString().trim();
              }
              if (!uri) {
                uri = await readPassphrase("Paste otpauth:// URI: ");
              }
            }
            if (!uri) {
              console.error("No URI provided.");
              process.exit(1);
            }
            try {
              storeTOTP(totpName, uri);
              const config = parseOTPAuthURI(uri);
              console.log(`Stored TOTP "${totpName}" — ${config.issuer || ""} ${config.account || ""}`.trim());
            } catch (err: any) {
              console.error(`Invalid OTP URI: ${err.message}`);
              process.exit(1);
            }
            break;
          }
          case "code": {
            const codeName = args[2];
            if (!codeName) {
              console.error("Usage: keyclasp totp code <name>");
              process.exit(1);
            }
            const result = generateTOTPCode(codeName);
            if (!result) {
              console.error(`TOTP "${codeName}" not found.`);
              process.exit(1);
            }
            console.log(`${result.code}  (rotates in ${result.remaining}s)`);
            break;
          }
          case "list": {
            const names = listTOTP();
            if (names.length === 0) {
              console.log("(no TOTP configurations)");
            } else {
              for (const n of names) {
                const cfg = getTOTP(n);
                console.log(`  ${n}  ${cfg ? `${cfg.issuer || ""} ${cfg.account || ""}` : ""}`.trim());
              }
            }
            break;
          }
          case "delete": {
            const delName = args[2];
            if (!delName) {
              console.error("Usage: keyclasp totp delete <name>");
              process.exit(1);
            }
            const deleted = deleteTOTP(delName);
            console.log(deleted ? `Deleted TOTP "${delName}"` : `TOTP "${delName}" not found.`);
            break;
          }
          case "qr": {
            const qrName = args[2];
            if (!qrName) {
              console.error("Usage: keyclasp totp qr <name>");
              process.exit(1);
            }
            const cfg = getTOTP(qrName);
            if (!cfg) {
              console.error(`TOTP "${qrName}" not found.`);
              process.exit(1);
            }
            console.log(cfg.uri);
            console.log("Scan this URI with your authenticator app, or use: keyclasp totp code " + qrName);
            break;
          }
          default:
            console.error("Usage: keyclasp totp <set|code|list|delete|qr>");
            process.exit(1);
        }
        break;
      }

      case "share": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const shareName = args[1];
        if (!shareName) {
          console.error("Usage: keyclasp share <name> [--ttl 24h] [--max-views 1]");
          process.exit(1);
        }
        const ttlIdx = args.indexOf("--ttl");
        const ttl = ttlIdx !== -1 ? args[ttlIdx + 1] : "24h";
        const viewsIdx = args.indexOf("--max-views");
        const maxViews = viewsIdx !== -1 ? parseInt(args[viewsIdx + 1], 10) : 1;
        try {
          const { url } = createShareLink(shareName, { ttl, maxViews });
          console.log(`Share link for "${shareName}" (expires in ${ttl}, ${maxViews} view(s)):`);
          console.log(url);
          console.log("\nThe secret is encrypted into the URL fragment — never sent to any server.");
          console.log("Share this link. Recipient runs: keyclasp receive <url>");
        } catch (err: any) {
          console.error(`Share failed: ${err.message}`);
          process.exit(1);
        }
        break;
      }

      case "receive": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        let fragment = args[1];
        if (!fragment) {
          fragment = await readPassphrase("Paste share URL or fragment: ");
        }
        if (!fragment) {
          console.error("No share URL/fragment provided.");
          process.exit(1);
        }
        const targetName = args[2];
        try {
          const result = receiveShare(fragment, targetName);
          console.log(`Received "${result.name}" — stored in vault.`);
        } catch (err: any) {
          console.error(`Receive failed: ${err.message}`);
          process.exit(1);
        }
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
