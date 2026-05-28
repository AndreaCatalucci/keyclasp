#!/usr/bin/env node
import { initializeVault, getKey, storeSecret, listSecrets, resolveSecret, deleteSecret, isInitialized, closeDb, setRequireSession, setProjectName, getProjectName, getAuditLog, checkExpired, setExpiry, setClientInfo } from "./vault.js";
import { startServer, startHttpServer } from "./server.js";
import { sandboxEnvFile, unsandboxEnvFile } from "./sandbox.js";
import { setBackend, getBackend, listAvailableBackends } from "./backends.js";
import { authenticateWithBiometric, biometricAvailable, createSession, sessionActive, clearSession } from "./auth.js";
import { installHook, checkAndReport, getStagedFiles, scanFiles } from "./hook.js";
import { watchEnvFile } from "./watch.js";
import { teamInit, teamPush, teamPull, teamList, teamDelete } from "./team.js";
import { activateLicense, deactivateLicense, getLicenseInfo, isPro, featuresEnabled } from "./license.js";
import { readConfig, mergeConfig, generateSecret, parseEnvFile, formatEnvFile } from "./config.js";
import { runDoctor } from "./doctor.js";
import { generateBash, generateZsh, generateFish, detectShell, getInstallInstructions } from "./completions.js";
import fs from "node:fs";
import { spawn } from "node:child_process";
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
🔑 Keyblind — Blind AI to your keys

Usage:
  keyblind init                Initialize the encrypted vault
  keyblind set <name>          Store a secret (value read from stdin)
  keyblind set <name> -        Store a secret (prompts securely)
  keyblind get <name>          Resolve and print a secret value
  keyblind list                List all stored secret names
  keyblind delete <name>       Delete a secret
  keyblind start               Start the MCP server (stdio)
  keyblind start --http        Start MCP HTTP server (for Smithery, remote)
  keyblind start --biometric   Start MCP server with biometric requirement
  keyblind unlock              Authenticate with biometric (cross-platform)
  keyblind run <command...>    Run a command with secrets as env vars
  keyblind sandbox [.env]      Replace real env values with deterministic fakes
  keyblind unsandbox [.env]    Restore real env values from vault
  keyblind backends            List available secret backends
  keyblind install-hook        Install pre-commit hook to detect secrets
  keyblind check-secrets       Scan staged files for secrets (used by hook)
  keyblind audit               Show secret resolution audit log
  keyblind check --expired     List secrets past their expiry date
  keyblind rotate <name>       Update a secret (prompts for new value)
  keyblind watch [.env]        Watch .env and auto-sandbox on change
  keyblind activate <key>      Activate a Keyblind Pro/Team license
  keyblind deactivate          Deactivate and remove current license
  keyblind status              Show license and vault status
  keyblind team init [path]    Create a shared team vault (git-safe)
  keyblind team push <name>     Push a local secret to the team vault
  keyblind team pull            Import all team secrets to local vault
  keyblind team list            List secrets in the team vault
  keyblind generate <name>     Generate a strong random secret
  keyblind generate <name> --len 64    Generate with custom length
  keyblind generate <name> --no-symbols   Alphanumeric only
  keyblind import [.env]        Bulk import secrets from a .env file
  keyblind export               Export all secrets (use --json for raw JSON)
  keyblind export --env         Export as .env format
  keyblind config               Show project config (.keyblind)
  keyblind config <key> <val>   Set a config option (backend, projectName, expiryDays, autoSandbox)
  keyblind doctor               Run vault health and security check
  keyblind completions [bash|zsh|fish]  Generate shell completion script
  keyblind help                Show this help

Global flags:
  --project <name>            Use a project-specific vault (isolated per project)

Examples:
  keyblind init
  echo "sk-abc123" | keyblind set OPENAI_API_KEY
  keyblind set DATABASE_URL -
  keyblind list
  keyblind sandbox             # Fake your .env, backup real values to vault
  keyblind run -- npm start    # Run with real secrets injected
  keyblind unsandbox           # Restore real .env values
  keyblind unlock              # Touch ID auth to unlock vault
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

function requirePro(): void {
  if (!isPro()) {
    console.error("This feature requires a Keyblind Pro or Team license.");
    console.error("Get a license at: https://keyblind.dev/pricing");
    console.error("Then run: keyblind activate <your-license-key>");
    process.exit(1);
  }
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

  if (!command || command === "help" || command === "--help" || command === "-h") {
    printHelp();
    return;
  }

  try {
    const projectLabel = getProjectName() ? ` [project: ${getProjectName()}]` : "";

    switch (command) {
      case "init": {
        if (isInitialized()) {
          console.log(`Keyblind is already initialized${projectLabel}. To reset, delete ~/.keyblind/${getProjectName() ? `projects/${getProjectName()}/` : ""}`);
          return;
        }
        console.log(`🔑 Initializing Keyblind vault${projectLabel}...`);
        const passphrase = await readPassphrase("Enter vault passphrase (or empty for machine-only key): ");
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

      case "watch": {
        if (!isInitialized()) {
          console.error("Keyblind not initialized. Run: keyblind init");
          process.exit(1);
        }
        watchEnvFile(args[1]);
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
          console.error("Usage: keyblind scan-secrets <file...>");
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
          console.error("Usage: keyblind backend <name>");
          console.error("Available:", listAvailableBackends().filter(b => b.available).map(b => b.name).join(", "));
          process.exit(1);
        }
        // Cloud backends require Pro
        if (["aws", "gcp", "azure"].includes(backendName)) {
          requirePro();
        }
        setBackend(backendName);
        console.log(`Switched to backend: ${backendName}`);
        break;
      }

      case "team": {
        requirePro();
        if (!isInitialized()) {
          console.error("Keyblind not initialized. Run: keyblind init");
          process.exit(1);
        }
        const teamCmd = args[1];
        if (!teamCmd) {
          console.error("Usage: keyblind team <init|push|pull|list|delete>");
          process.exit(1);
        }

        switch (teamCmd) {
          case "init": {
            const vaultPath = args[2];
            const passphrase = await readPassphrase("Enter team passphrase: ");
            if (!passphrase) {
              console.error("Passphrase is required for team vault.");
              process.exit(1);
            }
            const confirm = stdin.isTTY ? await promptSecret("Confirm passphrase: ") : passphrase;
            if (passphrase !== confirm) {
              console.error("Passphrases do not match.");
              process.exit(1);
            }
            try {
              const created = teamInit(passphrase, vaultPath);
              console.log(`Team vault created at ${created}`);
              console.log("This file is encrypted and safe to commit to git.");
              console.log("Team members can join with: keyblind team pull");
            } catch (err: any) {
              console.error(err.message);
              process.exit(1);
            }
            break;
          }

          case "push": {
            const pushName = args[2];
            if (!pushName) {
              console.error("Usage: keyblind team push <name>");
              process.exit(1);
            }
            const localValue = resolveSecret(pushName);
            if (localValue === null) {
              console.error(`Secret "${pushName}" not found in local vault.`);
              process.exit(1);
            }
            const passphrase = await readPassphrase("Enter team passphrase: ");
            if (!passphrase) {
              console.error("Passphrase is required.");
              process.exit(1);
            }
            try {
              teamPush(pushName, localValue, passphrase);
              console.log(`Pushed "${pushName}" to team vault.`);
            } catch (err: any) {
              console.error(err.message);
              process.exit(1);
            }
            break;
          }

          case "pull": {
            const passphrase = await readPassphrase("Enter team passphrase: ");
            if (!passphrase) {
              console.error("Passphrase is required.");
              process.exit(1);
            }
            const pullFile = args[2];
            try {
              const imported = teamPull(passphrase, pullFile);
              if (imported.length === 0) {
                console.log("No secrets in team vault.");
              } else {
                console.log(`Imported ${imported.length} secret(s) from team vault:`);
                for (const name of imported) {
                  console.log(`  - ${name}`);
                }
              }
            } catch (err: any) {
              console.error(err.message);
              process.exit(1);
            }
            break;
          }

          case "list": {
            const passphrase = await readPassphrase("Enter team passphrase: ");
            if (!passphrase) {
              console.error("Passphrase is required.");
              process.exit(1);
            }
            try {
              const secrets = teamList(passphrase);
              if (secrets.length === 0) {
                console.log("(no secrets in team vault)");
              } else {
                secrets.forEach((n) => console.log(`  - ${n}`));
              }
            } catch (err: any) {
              console.error(err.message);
              process.exit(1);
            }
            break;
          }

          case "delete": {
            const delName = args[2];
            if (!delName) {
              console.error("Usage: keyblind team delete <name>");
              process.exit(1);
            }
            const passphrase = await readPassphrase("Enter team passphrase: ");
            if (!passphrase) {
              console.error("Passphrase is required.");
              process.exit(1);
            }
            try {
              const deleted = teamDelete(delName, passphrase);
              console.log(deleted ? `Deleted "${delName}" from team vault.` : `"${delName}" not found in team vault.`);
            } catch (err: any) {
              console.error(err.message);
              process.exit(1);
            }
            break;
          }

          default:
            console.error(`Unknown team command: ${teamCmd}`);
            console.error("Available: init, push, pull, list, delete");
            process.exit(1);
        }
        break;
      }

      case "audit": {
        requirePro();
        if (!isInitialized()) {
          console.error("Keyblind not initialized. Run: keyblind init");
          process.exit(1);
        }
        const entries = getAuditLog(50);
        if (entries.length === 0) {
          console.log("(no audit entries yet)");
        } else {
          for (const e of entries) {
            const client = e.clientInfo || "cli";
            console.log(`  ${e.timestamp}  ${(e.action || "").padEnd(8)} ${(e.secretName || "").padEnd(30)} ${client}`);
          }
        }
        break;
      }

      case "check": {
        requirePro();
        if (!isInitialized()) {
          console.error("Keyblind not initialized. Run: keyblind init");
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
          console.error("Usage: keyblind check --expired");
          process.exit(1);
        }
        break;
      }

      case "rotate": {
        requirePro();
        if (!isInitialized()) {
          console.error("Keyblind not initialized. Run: keyblind init");
          process.exit(1);
        }
        const rotateName = args[1];
        if (!rotateName) {
          console.error("Usage: keyblind rotate <name>");
          process.exit(1);
        }
        const oldValue = resolveSecret(rotateName);
        if (oldValue === null) {
          console.error(`Secret "${rotateName}" not found.`);
          process.exit(1);
        }
        const newValue = await readPassphrase(`Enter new value for ${rotateName}: `);
        if (!newValue) {
          console.error("No value provided.");
          process.exit(1);
        }
        storeSecret(rotateName, newValue);
        console.log(`Rotated "${rotateName}"`);
        break;
      }

      case "activate": {
        const key = args[1];
        if (!key) {
          console.error("Usage: keyblind activate <license-key>");
          console.error("Get a license at: https://keyblind.dev/pricing (coming soon)");
          process.exit(1);
        }
        const result = activateLicense(key);
        console.log(result.message);
        if (result.success && result.info) {
          const feats = featuresEnabled();
          console.log("");
          console.log("Features unlocked:");
          console.log(`  Unlimited secrets:    ${feats.unlimitedSecrets ? "✓" : "✗ (5 max)"}`);
          console.log(`  Team vaults:          ${feats.teamVaults ? "✓" : "✗"}`);
          console.log(`  Audit log:            ${feats.auditLog ? "✓" : "✗"}`);
          console.log(`  Secret rotation:      ${feats.secretRotation ? "✓" : "✗"}`);
          console.log(`  CI/CD integration:    ${feats.ciAction ? "✓" : "✗"}`);
          console.log(`  Biometric gate:       ${feats.biometricGate ? "✓" : "✗"}`);
          console.log(`  Cloud backends:       ${feats.cloudBackends ? "✓" : "✗"}`);
        }
        if (!result.success) process.exit(1);
        break;
      }

      case "deactivate": {
        const result = deactivateLicense();
        console.log(result.message);
        if (!result.success) process.exit(1);
        break;
      }

      case "status": {
        if (!isInitialized()) {
          console.log("Keyblind: not initialized");
          console.log("Run 'keyblind init' to get started.");
          process.exit(1);
        }
        const info = getLicenseInfo();
        const feats = featuresEnabled();
        const names = listSecrets();
        const limit = feats.unlimitedSecrets ? "unlimited" : "5";
        console.log("Keyblind Status");
        console.log("───────────────");
        console.log(`  Secrets:    ${names.length}/${limit}`);
        if (info) {
          const tierLabel = info.tier === "team" ? "Team" : info.tier === "pro" ? "Pro" : "Free";
          console.log(`  License:    ${tierLabel}`);
          console.log(`  Email:      ${info.email}`);
          console.log(`  Expires:    ${info.exp}`);
        } else {
          console.log(`  License:    Free (no license activated)`);
          console.log(`  Upgrade:    https://keyblind.dev/pricing (coming soon)`);
        }
        console.log(`  Vault:      ~/.keyblind/`);
        const backend = getBackend();
        console.log(`  Backend:    ${backend.name}`);
        break;
      }

      case "start": {
        // Auto-initialize vault for Docker/Glama when KEYBLIND_AUTO_INIT is set
        if (!isInitialized() && process.env.KEYBLIND_AUTO_INIT === "true") {
          initializeVault("");
          console.log("Vault auto-initialized for demo/container.");
        }
        if (!isInitialized()) {
          console.error("Keyblind not initialized. Run: keyblind init");
          process.exit(1);
        }
        const biometric = args.includes("--biometric");
        const httpMode = args.includes("--http");
        if (biometric) {
          requirePro();
          if (!biometricAvailable()) {
            console.error("Biometric auth is not available on this system.");
            process.exit(1);
          }
          if (!sessionActive()) {
            console.error("Biometric session required. Run 'keyblind unlock' first.");
            process.exit(1);
          }
          setRequireSession(true);
          console.log("Biometric gate enabled — session expires in 15 minutes.");
        }
        getKey();
        if (httpMode) {
          const portIdx = args.indexOf("--port");
          const port = portIdx !== -1 ? parseInt(args[portIdx + 1], 10) : 3100;
          await startHttpServer(port);
        } else {
          await startServer();
        }
        break;
      }

      case "unlock": {
        if (!isInitialized()) {
          console.error("Keyblind not initialized. Run: keyblind init");
          process.exit(1);
        }
        if (!biometricAvailable()) {
          console.error("Touch ID is not available on this system. Only supported on macOS with Touch ID.");
          process.exit(1);
        }
        console.log("🔐 Authenticate with Touch ID to unlock the vault...");
        const ok = authenticateWithBiometric("Keyblind vault unlock");
        if (!ok) {
          console.error("Authentication failed or was cancelled.");
          process.exit(1);
        }
        createSession();
        console.log("Vault unlocked. Session active for 15 minutes.");
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

      case "generate": {
        if (!isInitialized()) {
          console.error("Keyblind not initialized. Run: keyblind init");
          process.exit(1);
        }
        const genName = args[1];
        if (!genName) {
          console.error("Usage: keyblind generate <name> [--len 32] [--no-symbols]");
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
          console.error("Keyblind not initialized. Run: keyblind init");
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
          console.error("Keyblind not initialized. Run: keyblind init");
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
            console.log("Project config (.keyblind):");
            const validKeys: (keyof typeof cfg)[] = ["projectName", "backend", "expiryDays", "autoSandbox", "watchPath"];
            for (const key of validKeys) {
              if (cfg[key] !== undefined) {
                console.log(`  ${key}: ${cfg[key]}`);
              }
            }
          } else {
            console.log("No project config found. Create one with:");
            console.log("  keyblind config backend local");
            console.log("  keyblind config expiryDays 90");
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
        break;
      }

      case "completions": {
        const shell = args[1] || detectShell();
        if (!shell) {
          console.error("Could not detect shell. Specify: keyblind completions <bash|zsh|fish>");
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
