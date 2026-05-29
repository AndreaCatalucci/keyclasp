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
import { saveHistory, getSecretHistory, rollbackSecret, ensureHistoryTable, getExpiringSoon, createSyncBundle, applySyncBundle, migrateSecrets } from "./sync.js";
import { configureAlerts, loadAlertsFromConfig, fireAlert } from "./alerts.js";
import { storeTOTP, getTOTP, listTOTP, deleteTOTP, generateTOTPCode, parseOTPAuthURI } from "./totp.js";
import { createShareLink, receiveShare } from "./share.js";
import { setupDeadman, checkin, getDeadmanStatus, disableDeadman, checkDeadmanTrigger } from "./deadman.js";
import { configureSSO, ssoLogin, ssoLogout, getSSOToken } from "./sso.js";
import { setupAll } from "./setup-mcp.js";
import { generatePairingToken } from "./pairing.js";
import fs from "node:fs";
import { spawn, execSync } from "node:child_process";
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
  keyblind setup-mcp           Configure MCP server for Claude Code & other editors
  keyblind dashboard-login     Generate one-time sign-in link for the web dashboard
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
  keyblind history <name>    Show version history for a secret
  keyblind rollback <name>   Restore previous version of a secret
  keyblind expiring          List secrets expiring within 30 days
  keyblind sync export       Create encrypted sync bundle
  keyblind sync import <file> Apply a sync bundle from another machine
  keyblind migrate <from> <to> Migrate secrets between backends
  keyblind alerts <url>      Configure Slack/Discord webhook alerts
  keyblind totp set <name>   Store a TOTP 2FA config (from otpauth:// URI)
  keyblind totp code <name>  Generate current TOTP code with countdown
  keyblind totp list          List all TOTP configurations
  keyblind totp delete <name> Delete a TOTP config
  keyblind share <name>       Create encrypted expiring share link
  keyblind share <name> --ttl 7d --max-views 3   Custom TTL and view limit
  keyblind receive <url>      Receive and store a shared secret
  keyblind deadman setup      Configure dead man's switch vault release
  keyblind deadman checkin    Reset the dead man's switch timer
  keyblind deadman status     Show dead man's switch status
  keyblind deadman disable    Disable dead man's switch
  keyblind sso configure      Set up SSO/OIDC for team vault access
  keyblind sso login          Authenticate via browser SSO flow
  keyblind sso logout         Clear SSO session
  keyblind sso status         Show SSO authentication status
  keyblind start --http --https --domain example.com   HTTPS with Let's Encrypt
  keyblind start --http --https --domain example.com --staging   Test with staging
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

      case "setup-mcp": {
        const results = setupAll();
        for (const r of results) {
          if (r.action === "configured") {
            console.log(`${r.editor}: MCP server configured successfully.`);
          } else if (r.action === "already_configured") {
            console.log(`${r.editor}: Already configured.`);
          } else {
            console.error(`${r.editor}: Failed — ${r.error}`);
          }
        }
        console.log("\nRestart Claude Code, then try: 'list my keyblind secrets'");
        break;
      }

      case "dashboard-login": {
        const port = parseInt(args[1] || "3100", 10);
        console.error("Generating sign-in link...");
        const { url } = await generatePairingToken(port);
        const openCmd = process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open";
        execSync(`${openCmd} "${url}"`);
        console.log("Browser opened. Sign in to continue.");
        console.log("If the browser doesn't open, visit:");
        console.log(`  ${url}`);
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
        const httpsMode = args.includes("--https");
        const domainIdx = args.indexOf("--domain");
        const domain = domainIdx !== -1 ? args[domainIdx + 1] : undefined;
        const emailIdx = args.indexOf("--email");
        const email = emailIdx !== -1 ? args[emailIdx + 1] : undefined;
        const staging = args.includes("--staging");
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
        if (httpsMode) {
          requirePro();
          if (!domain) {
            console.error("HTTPS mode requires --domain <your-domain.com>");
            console.error("Example: keyblind start --http --https --domain keyblind.example.com --email admin@example.com");
            process.exit(1);
          }
          const portIdx = args.indexOf("--port");
          const port = portIdx !== -1 ? parseInt(args[portIdx + 1], 10) : 443;
          await startHttpServer(port, { domain, email, staging, port });
        } else if (httpMode) {
          const portIdx = args.indexOf("--port");
          const port = portIdx !== -1 ? parseInt(args[portIdx + 1], 10) : 3100;
          await startHttpServer(port);
        } else {
          // MCP stdio transport uses stdout — startup messages MUST go to stderr
          console.error("Keyblind MCP server started (stdio transport).");
          console.error("For HTTP/HTTPS (browser dashboard), use: keyblind start --http");
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

      case "history": {
        if (!isInitialized()) {
          console.error("Keyblind not initialized. Run: keyblind init");
          process.exit(1);
        }
        const histName = args[1];
        if (!histName) {
          console.error("Usage: keyblind history <name>");
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
          console.error("Keyblind not initialized. Run: keyblind init");
          process.exit(1);
        }
        const rbName = args[1];
        if (!rbName) {
          console.error("Usage: keyblind rollback <name> [version]");
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
          console.error("Keyblind not initialized. Run: keyblind init");
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
          console.error("Usage: keyblind sync <export|import>");
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
        requirePro();
        if (!isInitialized()) {
          console.error("Keyblind not initialized. Run: keyblind init");
          process.exit(1);
        }
        const from = args[1];
        const to = args[2];
        if (!from || !to) {
          console.error("Usage: keyblind migrate <from-backend> <to-backend>");
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

      case "alerts": {
        requirePro();
        const alertUrl = args[1];
        const alertEvents = args.slice(2).filter(a => !a.startsWith("--"));

        if (!alertUrl) {
          const cfg = readConfig();
          if (cfg && (cfg as any).alertWebhooks) {
            const hooks = (cfg as any).alertWebhooks;
            console.log(`${hooks.length} webhook(s) configured:`);
            for (const h of hooks) {
              console.log(`  ${h.url} → events: ${h.events.join(", ")}`);
            }
          } else {
            console.log("No alert webhooks configured.");
            console.log("Usage: keyblind alerts <webhook-url> [resolve,store,delete,rotate,expiry]");
            console.log("Example: keyblind alerts https://hooks.slack.com/... resolve rotate expiry");
          }
          break;
        }

        const events = alertEvents.length > 0
          ? alertEvents as ("resolve" | "store" | "delete" | "rotate" | "expiry")[]
          : ["resolve", "store", "delete", "rotate", "expiry"];

        const cfg = readConfig() || {};
        const hooks = (cfg as any).alertWebhooks || [];
        hooks.push({ url: alertUrl, events });
        (cfg as any).alertWebhooks = hooks;
        mergeConfig(cfg as any);
        loadAlertsFromConfig();
        console.log(`Alert webhook configured: ${alertUrl}`);
        console.log(`Events: ${events.join(", ")}`);
        break;
      }

      case "totp": {
        requirePro();
        if (!isInitialized()) {
          console.error("Keyblind not initialized. Run: keyblind init");
          process.exit(1);
        }
        const totpSub = args[1];
        if (!totpSub) {
          console.error("Usage: keyblind totp <set|code|list|delete|qr>");
          process.exit(1);
        }

        switch (totpSub) {
          case "set": {
            const totpName = args[2];
            if (!totpName) {
              console.error("Usage: keyblind totp set <name> [otpauth-uri]");
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
              console.error("Usage: keyblind totp code <name>");
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
              console.error("Usage: keyblind totp delete <name>");
              process.exit(1);
            }
            const deleted = deleteTOTP(delName);
            console.log(deleted ? `Deleted TOTP "${delName}"` : `TOTP "${delName}" not found.`);
            break;
          }
          case "qr": {
            const qrName = args[2];
            if (!qrName) {
              console.error("Usage: keyblind totp qr <name>");
              process.exit(1);
            }
            const cfg = getTOTP(qrName);
            if (!cfg) {
              console.error(`TOTP "${qrName}" not found.`);
              process.exit(1);
            }
            console.log(cfg.uri);
            console.log("Scan this URI with your authenticator app, or use: keyblind totp code " + qrName);
            break;
          }
          default:
            console.error("Usage: keyblind totp <set|code|list|delete|qr>");
            process.exit(1);
        }
        break;
      }

      case "share": {
        requirePro();
        if (!isInitialized()) {
          console.error("Keyblind not initialized. Run: keyblind init");
          process.exit(1);
        }
        const shareName = args[1];
        if (!shareName) {
          console.error("Usage: keyblind share <name> [--ttl 24h] [--max-views 1]");
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
          console.log("Share this link. Recipient runs: keyblind receive <url>");
        } catch (err: any) {
          console.error(`Share failed: ${err.message}`);
          process.exit(1);
        }
        break;
      }

      case "receive": {
        requirePro();
        if (!isInitialized()) {
          console.error("Keyblind not initialized. Run: keyblind init");
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

      case "deadman": {
        requirePro();
        if (!isInitialized()) {
          console.error("Keyblind not initialized. Run: keyblind init");
          process.exit(1);
        }
        const dmSub = args[1];
        if (!dmSub) {
          console.error("Usage: keyblind deadman <setup|checkin|status|disable>");
          process.exit(1);
        }

        switch (dmSub) {
          case "setup": {
            const daysIdx = args.indexOf("--days");
            const days = daysIdx !== -1 ? parseInt(args[daysIdx + 1], 10) : 30;
            const contactIdx = args.indexOf("--contact");
            const contactEmail = contactIdx !== -1 ? args[contactIdx + 1] : null;
            const keyIdx = args.indexOf("--key");
            const publicKeyPath = keyIdx !== -1 ? args[keyIdx + 1] : undefined;
            const msgIdx = args.indexOf("--message");
            const message = msgIdx !== -1 ? args[msgIdx + 1] : undefined;

            if (!contactEmail) {
              console.error("Usage: keyblind deadman setup --days 30 --contact email@example.com [--key public.pem] [--message \"...\"]");
              process.exit(1);
            }

            let publicKey: string | undefined;
            if (publicKeyPath) {
              try {
                publicKey = fs.readFileSync(publicKeyPath, "utf8");
              } catch {
                console.error(`Could not read public key: ${publicKeyPath}`);
                process.exit(1);
              }
            }

            setupDeadman({ days, contactEmail, contactPublicKey: publicKey, message });
            console.log(`Dead man's switch configured: ${days} days, contact ${contactEmail}`);
            if (!publicKey) console.log("Warning: No public key provided. Key shard will not be encrypted for delivery.");
            break;
          }

          case "checkin": {
            checkin();
            const status = getDeadmanStatus();
            console.log(`Check-in recorded. ${status.daysRemaining} days remaining.`);
            break;
          }

          case "status": {
            const status = getDeadmanStatus();
            if (!status.enabled) {
              console.log("Dead man's switch is not configured.");
              console.log("Set up with: keyblind deadman setup --days 30 --contact email@example.com");
              return;
            }
            console.log("Dead Man's Switch Status");
            console.log("───────────────────────");
            console.log(`  Enabled:         ${status.enabled ? "Yes" : "No"}`);
            console.log(`  Threshold:       ${status.daysConfigured} days`);
            console.log(`  Last check-in:   ${status.lastCheckin || "Never"}`);
            console.log(`  Days remaining:  ${status.daysRemaining}`);
            console.log(`  Contact:         ${status.contactEmail}`);
            console.log(`  Triggered:       ${status.triggered ? "YES" : "No"}`);
            break;
          }

          case "disable": {
            disableDeadman();
            console.log("Dead man's switch disabled.");
            break;
          }

          default:
            console.error("Usage: keyblind deadman <setup|checkin|status|disable>");
            process.exit(1);
        }
        break;
      }

      case "sso": {
        requirePro();
        if (!isInitialized()) {
          console.error("Keyblind not initialized. Run: keyblind init");
          process.exit(1);
        }
        const ssoSub = args[1];
        if (!ssoSub) {
          console.error("Usage: keyblind sso <configure|login|logout|status>");
          process.exit(1);
        }

        switch (ssoSub) {
          case "configure": {
            const provider = args[2];
            const clientIdx = args.indexOf("--client-id");
            const clientId = clientIdx !== -1 ? args[clientIdx + 1] : null;
            const domainIdx = args.indexOf("--domain");
            const domain = domainIdx !== -1 ? args[domainIdx + 1] : undefined;

            if (!provider || !clientId) {
              console.error("Usage: keyblind sso configure <google|okta|azure> --client-id <id> [--domain <domain>]");
              process.exit(1);
            }

            try {
              await configureSSO({ provider, clientId, domain });
              console.log(`SSO configured for ${provider}. Run 'keyblind sso login' to authenticate.`);
            } catch (err: any) {
              console.error(`SSO configure failed: ${err.message}`);
              process.exit(1);
            }
            break;
          }

          case "login": {
            try {
              console.log("Opening browser for SSO login...");
              console.log("Complete authentication in your browser, then return here.");
              const token = await ssoLogin();
              console.log(`Authenticated as ${token.claims.email}`);
              if (token.claims.hd) console.log(`Domain: ${token.claims.hd}`);
              console.log(`Token expires: ${new Date(token.expiresAt * 1000).toLocaleString()}`);
            } catch (err: any) {
              console.error(`SSO login failed: ${err.message}`);
              process.exit(1);
            }
            break;
          }

          case "logout": {
            ssoLogout();
            console.log("SSO session cleared.");
            break;
          }

          case "status": {
            const token = getSSOToken();
            if (token && token.expiresAt * 1000 > Date.now()) {
              console.log(`Authenticated: ${token.claims.email}`);
              console.log(`Expires: ${new Date(token.expiresAt * 1000).toLocaleString()}`);
            } else {
              console.log("Not authenticated. Run: keyblind sso login");
            }
            break;
          }

          default:
            console.error("Usage: keyblind sso <configure|login|logout|status>");
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
