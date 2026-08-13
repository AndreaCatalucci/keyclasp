#!/usr/bin/env node
import {
  initializeVault,
  getKey,
  getVaultLocation,
  storeSecret,
  listSecrets,
  resolveSecret,
  deleteSecret,
  isInitialized,
  closeDb,
  checkVaultDecryptability,
  isNewProjectEnvironment,
  projects,
  environments,
  snapshotBulkDelete,
  deleteBulkIfUnchanged,
  renameProject,
  renameEnvironmentInProject,
  renameEnvironmentAcrossAllProjects,
  renameScope,
  validateScopeName,
  type ScopedSecret,
} from "./vault.js";
import { parseRunArgs, runCommandWithSecrets } from "./run.js";
import { getDisplayVersion } from "./version.js";
import { extractGlobalFlags, resolveContext, writeContext, clearContext } from "./context.js";
import { resolveSecretForOperator } from "./biometric.js";
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
  keyclasp get <name>          Print a secret after Touch ID or vault passphrase
  keyclasp list [--all]        List stored secret names
  keyclasp delete <name>       Delete a secret
  keyclasp delete --bulk ...   Delete every secret in a project/environment
  keyclasp use <project> <environment>
                              Persist a project/environment for interactive use
  keyclasp use --clear         Clear the persisted project/environment
  keyclasp projects            List distinct project names in use
  keyclasp environments        List distinct environment names in use
  keyclasp rename ...          Move secrets to a different project/environment
  keyclasp run [--allow-unsafe] [--env SOURCE[:TARGET]] <command...>
                              Run a guarded command with secrets as env vars
  keyclasp status               Show vault status
  keyclasp version              Show Keyclasp version
  keyclasp help                 Show this help

Global flags (get/set/list/delete/run/status):
  --project, -p <name>        Scope to a project (default: "default")
  --environment, -E <name>    Scope to an environment (default: "default")

Bulk delete (keyclasp delete --bulk ...), requires interactive confirmation:
  keyclasp delete --bulk --project P
  keyclasp delete --bulk --project P --environment E
  keyclasp delete --bulk --environment E --all-projects

Rename (no confirmation prompt; aborts on any name collision):
  keyclasp rename --project OLD --to-project NEW
  keyclasp rename --project P --environment OLD --to-environment NEW
  keyclasp rename --all-projects --environment OLD --to-environment NEW
  keyclasp rename --project P --environment E --to-project NEW_P --to-environment NEW_E

Global flags:
  --version, -v               Show Keyclasp version

Examples:
  keyclasp init
  keyclasp set DATABASE_URL - --project myapp --environment staging
  keyclasp list --project myapp --environment staging
  keyclasp run --project myapp --environment prod --env SECRET_API_KEY -- npm test
  keyclasp run --project myapp --environment prod --env SECRET_API_KEY:API_TOKEN -- npm start
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

function promptPlainLine(prompt: string): Promise<string> {
  const rl = readline.createInterface({ input: stdin, output: stdout });
  return new Promise((resolve) => {
    rl.question(prompt, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

async function confirmBulkDelete(opts: { description: string; typedValue: string; count: number }): Promise<void> {
  if (!stdin.isTTY) {
    console.error(`Refusing to run a non-interactive bulk delete of ${opts.description}. Re-run in an interactive terminal to confirm.`);
    process.exit(1);
  }
  console.log(`This will permanently delete ${opts.count} secret(s) in ${opts.description}.`);
  const typed = await promptPlainLine(`Type "${opts.typedValue}" to confirm: `);
  if (typed !== opts.typedValue) {
    console.error("Confirmation did not match. Aborted — nothing was deleted.");
    process.exit(1);
  }
}

async function runBulkDelete(opts: { project?: string; environment?: string; allProjects: boolean }): Promise<void> {
  const { project, environment, allProjects } = opts;

  if (allProjects) {
    if (project !== undefined) {
      console.error("--all-projects cannot be combined with --project.");
      process.exit(1);
    }
    if (environment === undefined) {
      console.error("--all-projects requires --environment.");
      process.exit(1);
    }
    validateScopeName(environment, "environment");
    const rows = snapshotBulkDelete(undefined, environment);
    if (rows.length === 0) {
      console.log(`No secrets found for environment "${environment}" in any project.`);
      return;
    }
    const affectedProjects = new Set(rows.map((r) => r.project)).size;
    await confirmBulkDelete({
      description: `environment "${environment}" across ${affectedProjects} project(s)`,
      typedValue: environment,
      count: rows.length,
    });
    const result = deleteBulkIfUnchanged(undefined, environment, rows);
    console.log(`Deleted ${result.deleted} secret(s) from environment "${environment}" across ${affectedProjects} project(s).`);
    return;
  }

  if (project === undefined) {
    console.error("keyclasp delete --bulk requires --project (whole project or one environment in it) or --environment with --all-projects.");
    process.exit(1);
  }
  validateScopeName(project, "project");

  if (environment === undefined) {
    const rows = snapshotBulkDelete(project);
    if (rows.length === 0) {
      console.log(`No secrets found for project "${project}".`);
      return;
    }
    await confirmBulkDelete({ description: `project "${project}" (all environments)`, typedValue: project, count: rows.length });
    const result = deleteBulkIfUnchanged(project, undefined, rows);
    console.log(`Deleted ${result.deleted} secret(s) from project "${project}".`);
    return;
  }

  validateScopeName(environment, "environment");
  const rows = snapshotBulkDelete(project, environment);
  if (rows.length === 0) {
    console.log(`No secrets found for project "${project}" environment "${environment}".`);
    return;
  }
  await confirmBulkDelete({ description: `project "${project}" environment "${environment}"`, typedValue: environment, count: rows.length });
  const result = deleteBulkIfUnchanged(project, environment, rows);
  console.log(`Deleted ${result.deleted} secret(s) from project "${project}" environment "${environment}".`);
}

interface RenameFlags {
  project?: string;
  environment?: string;
  toProject?: string;
  toEnvironment?: string;
  allProjects: boolean;
}

function requireFlagValue(args: string[], index: number, flagName: string): string {
  const value = args[index + 1];
  if (value === undefined) throw new Error(`Missing value for ${flagName}.`);
  return value;
}

function parseRenameFlags(args: string[]): RenameFlags {
  const flags: RenameFlags = { allProjects: false };
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    switch (arg) {
      case "--project":
        flags.project = requireFlagValue(args, i, "--project");
        i += 1;
        break;
      case "--environment":
        flags.environment = requireFlagValue(args, i, "--environment");
        i += 1;
        break;
      case "--to-project":
        flags.toProject = requireFlagValue(args, i, "--to-project");
        i += 1;
        break;
      case "--to-environment":
        flags.toEnvironment = requireFlagValue(args, i, "--to-environment");
        i += 1;
        break;
      case "--all-projects":
        flags.allProjects = true;
        break;
      default:
        throw new Error(`Unknown option "${arg}" for keyclasp rename.`);
    }
  }
  return flags;
}

const RENAME_USAGE = [
  "Usage:",
  "  keyclasp rename --project OLD --to-project NEW",
  "  keyclasp rename --project P --environment OLD --to-environment NEW",
  "  keyclasp rename --all-projects --environment OLD --to-environment NEW",
  "  keyclasp rename --project P --environment E --to-project NEW_P --to-environment NEW_E",
].join("\n");

function runRename(flags: RenameFlags): void {
  const { project, environment, toProject, toEnvironment, allProjects } = flags;

  if (allProjects) {
    if (project !== undefined || toProject !== undefined) {
      console.error(`--all-projects cannot be combined with --project or --to-project.\n${RENAME_USAGE}`);
      process.exit(1);
    }
    if (environment === undefined || toEnvironment === undefined) {
      console.error(`--all-projects requires --environment and --to-environment.\n${RENAME_USAGE}`);
      process.exit(1);
    }
    const result = renameEnvironmentAcrossAllProjects(environment, toEnvironment);
    console.log(`Renamed environment "${environment}" to "${toEnvironment}" across ${result.projectsAffected} project(s) (${result.moved} secret(s) moved).`);
    return;
  }

  if (project !== undefined && toProject !== undefined && environment === undefined && toEnvironment === undefined) {
    const result = renameProject(project, toProject);
    console.log(`Renamed project "${project}" to "${toProject}" (${result.moved} secret(s) moved).`);
    return;
  }

  if (project !== undefined && environment !== undefined && toEnvironment !== undefined && toProject === undefined) {
    const result = renameEnvironmentInProject(project, environment, toEnvironment);
    console.log(`Renamed environment "${environment}" to "${toEnvironment}" in project "${project}" (${result.moved} secret(s) moved).`);
    return;
  }

  if (project !== undefined && environment !== undefined && toProject !== undefined && toEnvironment !== undefined) {
    const result = renameScope(project, environment, toProject, toEnvironment);
    console.log(`Renamed "${project}/${environment}" to "${toProject}/${toEnvironment}" (${result.moved} secret(s) moved).`);
    return;
  }

  console.error(RENAME_USAGE);
  process.exit(1);
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
        const { project: pFlag, environment: eFlag, rest } = extractGlobalFlags(args.slice(1), "scan-all");
        const name = rest[0];
        if (!name) {
          console.error("Usage: keyclasp set <name>  OR  echo <value> | keyclasp set <name>");
          process.exit(1);
        }
        const { project, environment } = resolveContext(pFlag, eFlag);

        let value: string;
        if (rest[1] === "-") {
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

        if (isNewProjectEnvironment(project, environment)) {
          console.log(`Note: "${project}/${environment}" is a new project/environment combo.`);
        }
        storeSecret(project, environment, name, value);
        console.log(`Stored "${name}" (${project}/${environment})`);
        break;
      }

      case "get": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const { project: pFlag, environment: eFlag, rest } = extractGlobalFlags(args.slice(1), "scan-all");
        const secretName = rest[0];
        if (!secretName) {
          console.error("Usage: keyclasp get <name>");
          process.exit(1);
        }
        const { project, environment } = resolveContext(pFlag, eFlag);
        const val = await resolveSecretForOperator(
          `${project}/${environment}/${secretName}`,
          () => resolveSecret(project, environment, secretName),
        );
        if (val === null) {
          console.error(`Secret "${secretName}" not found in project "${project}" environment "${environment}".`);
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
        const { project: pFlag, environment: eFlag, rest } = extractGlobalFlags(args.slice(1), "scan-all");
        const all = rest.includes("--all");

        if (all) {
          const rows = listSecrets() as ScopedSecret[];
          if (rows.length === 0) console.log("(no secrets stored)");
          else rows.forEach((r) => console.log(`  - ${r.project}/${r.environment}/${r.name}`));
        } else if (pFlag !== undefined && eFlag === undefined) {
          const rows = listSecrets(pFlag) as ScopedSecret[];
          if (rows.length === 0) console.log("(no secrets stored)");
          else rows.forEach((r) => console.log(`  - ${r.environment}/${r.name}`));
        } else if (eFlag !== undefined && pFlag === undefined) {
          const rows = listSecrets(undefined, eFlag) as ScopedSecret[];
          if (rows.length === 0) console.log("(no secrets stored)");
          else rows.forEach((r) => console.log(`  - ${r.project}/${r.name}`));
        } else {
          const { project, environment } = resolveContext(pFlag, eFlag);
          const names = listSecrets(project, environment) as string[];
          if (names.length === 0) console.log("(no secrets stored)");
          else names.forEach((n) => console.log(`  - ${n}`));
        }
        break;
      }

      case "delete": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const { project: pFlag, environment: eFlag, rest } = extractGlobalFlags(args.slice(1), "scan-all");
        const bulk = rest.includes("--bulk");
        const allProjects = rest.includes("--all-projects");
        const positionals = rest.filter((a) => a !== "--bulk" && a !== "--all-projects");

        if (bulk) {
          if (positionals.length > 0) {
            console.error("keyclasp delete --bulk does not take a secret name. Use --project/--environment/--all-projects to select the scope to delete.");
            process.exit(1);
          }
          await runBulkDelete({ project: pFlag, environment: eFlag, allProjects });
        } else {
          const delName = positionals[0];
          if (!delName) {
            console.error("Usage: keyclasp delete <name>  OR  keyclasp delete --bulk ...");
            process.exit(1);
          }
          const { project, environment } = resolveContext(pFlag, eFlag);
          const deleted = deleteSecret(project, environment, delName);
          console.log(deleted ? `Deleted "${delName}" (${project}/${environment})` : `"${delName}" not found in ${project}/${environment}.`);
        }
        break;
      }

      case "status": {
        if (!isInitialized()) {
          console.log("Keyclasp: not initialized");
          console.log("Run 'keyclasp init' to get started.");
          process.exit(1);
        }
        const { project: pFlag, environment: eFlag } = extractGlobalFlags(args.slice(1), "scan-all");
        const { project, environment, projectSource, environmentSource } = resolveContext(pFlag, eFlag);
        const scopedCount = (listSecrets(project, environment) as string[]).length;

        console.log("Keyclasp Status");
        console.log("───────────────");
        console.log(`  Scope:      ${project}/${environment}  (project: ${projectSource}, environment: ${environmentSource})`);
        console.log(`  Vault:      ${getVaultLocation()}`);
        try {
          const decryptability = checkVaultDecryptability();
          console.log(`  Secrets:    ${scopedCount} in scope, ${decryptability.checked} vault-wide`);
          if (decryptability.checked === 0) {
            console.log("  Values:     no stored values to verify");
          } else if (decryptability.failures.length === 0) {
            console.log(`  Values:     verified (${decryptability.checked} decryptable)`);
          } else {
            console.log(`  Values:     FAILED (${decryptability.failures.length}/${decryptability.checked} undecryptable)`);
            process.exit(1);
          }
        } catch (err: any) {
          console.log(`  Secrets:    ${scopedCount} in scope`);
          console.log(`  Values:     FAILED (${err?.message ?? "decryptability check failed"})`);
          process.exit(1);
        }
        break;
      }

      case "use": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const rest = args.slice(1);
        if (rest[0] === "--clear") {
          clearContext();
          console.log("Cleared persisted project/environment context.");
          break;
        }
        const [useProject, useEnvironment] = rest;
        if (!useProject || !useEnvironment) {
          console.error("Usage: keyclasp use <project> <environment>  OR  keyclasp use --clear");
          process.exit(1);
        }
        writeContext(useProject, useEnvironment);
        console.log(`Context set to ${useProject}/${useEnvironment}.`);
        console.log("This is a convenience for interactive use only — scripts and agents should always pass --project/--environment explicitly.");
        break;
      }

      case "projects": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const names = projects();
        if (names.length === 0) console.log("(no projects stored)");
        else names.forEach((n) => console.log(`  - ${n}`));
        break;
      }

      case "environments": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const names = environments();
        if (names.length === 0) console.log("(no environments stored)");
        else names.forEach((n) => console.log(`  - ${n}`));
        break;
      }

      case "rename": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const flags = parseRenameFlags(args.slice(1));
        runRename(flags);
        break;
      }

      case "run": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const cmdArgs = args.slice(1);
        const parsed = parseRunArgs(cmdArgs);
        if (parsed.commandArgs.length === 0) {
          console.error("Usage: keyclasp run [--project NAME] [--environment NAME] [--allow-unsafe] [--env SOURCE[:TARGET]] <command...>");
          process.exit(1);
        }

        const { project, environment } = resolveContext(parsed.project, parsed.environment);
        const scopedNames = listSecrets(project, environment) as string[];
        if (scopedNames.length === 0) {
          console.error(`Note: no secrets stored yet for project "${project}" environment "${environment}"; running with zero secrets injected.`);
        }

        const result = await runCommandWithSecrets({
          args: cmdArgs,
          baseEnv: process.env,
          secretNames: scopedNames,
          resolveSecret: (name) => resolveSecret(project, environment, name),
          stdout: (chunk) => process.stdout.write(chunk),
          stderr: (chunk) => process.stderr.write(chunk),
          scopeLabel: `${project}/${environment}`,
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
