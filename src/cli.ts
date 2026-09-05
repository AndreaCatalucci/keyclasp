#!/usr/bin/env node
import {
  initializeVault,
  getKey,
  unlockVault,
  KEY_LOCKED_ERROR,
  vaultHasPassphrase,
  getVaultDescriptor,
  getVaultLocation,
  storeSecret,
  listSecrets,
  resolveSecret,
  resolveSecretsForRun,
  deleteSecret,
  isInitialized,
  closeDb,
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
  enrollInteractivePassphrase,
  rotateInteractivePassphrase,
  isInteractiveKeyUnlocked,
  readSecretKeyClass,
  transitionRecordCustody,
  needsDualKeyMigration,
  inspectLegacyVaultMode,
  migrateLegacyVaultToDualKey,
  recoverInterruptedCustodyTransition,
  completePendingCustodySanitization,
  custodySanitizationRequiresUnlock,
  hasPendingCustodySanitization,
  hasInterruptedCustodyTransition,
  hasInterruptedDualKeyMigration,
  recoverInterruptedDualKeyMigration,
  summarizeKeyClasses,
  listRecordCustody,
  authorizationDefaultSeedRequiresUnlock,
  type ScopedSecret,
} from "./vault.js";
import { parseRunArgs } from "./run.js";
import { createSoftwareRunRuntime } from "./software/runtime.js";
import { getDisplayVersion } from "./version.js";
import { extractGlobalFlags, resolveContext, writeContext, clearContext } from "./context.js";
import { processPassphraseInput, requireOperatorAuthentication } from "./biometric.js";
import { formatHardwareDoctor, inspectHardwareMode } from "./hardware/status.js";
import {
  appendAuthorizationPolicyAudit,
  authorizationPolicyNeedsDefaultMigration,
  authorizationPolicyUsesDefaultSeed,
  authorizationSelectorFromCommand,
  evaluateAuthorizationRules,
  hasInterruptedAuthorizationPolicy,
  initializeAuthorizationPolicy,
  migrateAuthorizationPolicyDefault,
  mutateAuthorizationDefaultAuthorized,
  mutateAuthorizationRuleAuthorized,
  previewAuthorizationDefault,
  readAuthorizationDefault,
  readAuthorizationState,
  recoverInterruptedAuthorizationPolicy,
  summarizeAuthorizationState,
  validateLiveAuthorizationPolicy,
} from "./policy.js";
import { createManagedBackupAuthorized, hasInterruptedManagedRestore, recoverInterruptedManagedRestore, restoreManagedBackupAuthorized, verifyManagedBackupPassphrase } from "./recovery.js";
import { acquireVaultLifecycleLock, lifecycleModeForCommand, type VaultLifecycleLock } from "./lifecycle-lock.js";
import readline from "node:readline";
import { StringDecoder } from "node:string_decoder";
import path from "node:path";
import { stdin, stdout } from "node:process";
import { assertSoftwarePlatformSupported } from "./platform.js";
import { revealSecretReason } from "./runtime.js";

async function ensureVaultUnlocked(authorizedPassphrase?: string): Promise<string | undefined> {
  if (!vaultHasPassphrase()) throw new Error("Interactive custody is not enrolled. Run: keyclasp passphrase set");
  if (isInteractiveKeyUnlocked()) return authorizedPassphrase;
  if (authorizedPassphrase !== undefined) {
    unlockVault(authorizedPassphrase);
    return authorizedPassphrase;
  }
  if (!stdin.isTTY) {
    console.error(KEY_LOCKED_ERROR);
    process.exit(1);
  }
  const passphrase = await promptSecret("Enter vault passphrase: ");
  try {
    unlockVault(passphrase);
    return passphrase;
  } catch (err: any) {
    console.error(err.message);
    process.exit(1);
  }
}

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
🔑 Keyclasp: Local encrypted credential vault for coding agents

Software beta: macOS arm64 and glibc Linux arm64 or x64, Node.js 24 or 26. Hardware mode is unavailable.

Usage:
  keyclasp init                Initialize the encrypted vault
  keyclasp init --machine-only Initialize explicitly for unattended machine custody
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
  keyclasp lock [--project P] [--environment E] [SECRET]
  keyclasp unlock [--project P] [--environment E] [SECRET]
  keyclasp inherit [--project P] [--environment E] [SECRET]
                              Change authenticated policy and record custody
  keyclasp lock|unlock --default
                              Choose interactive or machine custody for unmatched records
  keyclasp passphrase set|rotate
                              Enroll or rotate interactive custody
  keyclasp backup create|restore <directory>
                              Create or restore a managed vault backup
  keyclasp status               Show vault status
  keyclasp doctor               Inspect the status-only hardware boundary
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
  const wasRaw = stdin.isRaw === true;
  return new Promise((resolve, reject) => {
    stdout.write(prompt);
    let value = "";
    let settled = false;
    const decoder = new StringDecoder("utf8");
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      stdin.removeListener("data", onData);
      stdin.removeListener("end", onEnd);
      stdin.removeListener("close", onClose);
      stdin.removeListener("error", onError);
      try { stdin.setRawMode?.(wasRaw); } catch { /* preserve the primary result */ }
      stdin.pause();
      stdout.write("\n");
      if (error) reject(error);
      else resolve(value.trim());
    };
    const onData = (chunk: Buffer) => {
      const processed = processPassphraseInput(value, decoder.write(chunk));
      value = processed.value;
      for (const action of processed.actions) {
        if (action === "mask") stdout.write("*");
        else {
          try {
            stdout.moveCursor(-1, 0);
            stdout.write(" ");
            stdout.moveCursor(-1, 0);
          } catch { /* terminal cleanup is best effort */ }
        }
      }
      if (processed.cancelled) finish(new Error("Secret entry was cancelled."));
      else if (processed.submitted) finish();
    };
    const onEnd = () => finish(new Error("Secret entry ended before a value was submitted."));
    const onClose = () => finish(new Error("Secret input closed before a value was submitted."));
    const onError = () => finish(new Error("Could not read the secret."));
    try {
      stdin.setRawMode?.(true);
      stdin.resume();
      stdin.on("data", onData);
      stdin.once("end", onEnd);
      stdin.once("close", onClose);
      stdin.once("error", onError);
    } catch (error) {
      finish(error instanceof Error ? error : new Error("Could not read the secret."));
    }
  });
}

async function promptConfirmedPassphrase(prompt: string): Promise<string> {
  if (!stdin.isTTY) throw new Error("Interactive passphrase enrollment requires a terminal.");
  const first = await promptSecret(prompt);
  if (!first) throw new Error("Interactive passphrase must be non-empty.");
  const second = await promptSecret("Confirm new interactive passphrase: ");
  if (first !== second) throw new Error("Passphrase confirmation did not match. Nothing was changed.");
  return first;
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
    console.error("Confirmation did not match. Aborted, nothing was deleted.");
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

  const preserveAuthorization = (rows: ScopedSecret[], destination: (row: ScopedSecret) => ScopedSecret): void => {
    const changed = rows.filter((row) => {
      const target = destination(row);
      return readAuthorizationState(row.project, row.environment, row.name) !==
        readAuthorizationState(target.project, target.environment, target.name);
    });
    if (changed.length > 0) {
      const names = changed.map((row) => `${row.project}/${row.environment}/${row.name}`).join(", ");
      throw new Error(`Rename would change the effective authorization state for secret(s): ${names}. Add an explicit destination rule before renaming.`);
    }
  };

  if (allProjects) {
    if (project !== undefined || toProject !== undefined) {
      console.error(`--all-projects cannot be combined with --project or --to-project.\n${RENAME_USAGE}`);
      process.exit(1);
    }
    if (environment === undefined || toEnvironment === undefined) {
      console.error(`--all-projects requires --environment and --to-environment.\n${RENAME_USAGE}`);
      process.exit(1);
    }
    const sourceRows = listSecrets(undefined, environment) as ScopedSecret[];
    preserveAuthorization(sourceRows, (row) => ({ ...row, environment: toEnvironment }));
    const result = renameEnvironmentAcrossAllProjects(environment, toEnvironment);
    console.log(`Renamed environment "${environment}" to "${toEnvironment}" across ${result.projectsAffected} project(s) (${result.moved} secret(s) moved).`);
    return;
  }

  if (project !== undefined && toProject !== undefined && environment === undefined && toEnvironment === undefined) {
    const sourceRows = listSecrets(project) as ScopedSecret[];
    preserveAuthorization(sourceRows, (row) => ({ ...row, project: toProject }));
    const result = renameProject(project, toProject);
    console.log(`Renamed project "${project}" to "${toProject}" (${result.moved} secret(s) moved).`);
    return;
  }

  if (project !== undefined && environment !== undefined && toEnvironment !== undefined && toProject === undefined) {
    const sourceRows = (listSecrets(project, environment) as string[]).map((name) => ({ project, environment, name }));
    preserveAuthorization(sourceRows, (row) => ({ ...row, environment: toEnvironment }));
    const result = renameEnvironmentInProject(project, environment, toEnvironment);
    console.log(`Renamed environment "${environment}" to "${toEnvironment}" in project "${project}" (${result.moved} secret(s) moved).`);
    return;
  }

  if (project !== undefined && environment !== undefined && toProject !== undefined && toEnvironment !== undefined) {
    const sourceRows = (listSecrets(project, environment) as string[]).map((name) => ({ project, environment, name }));
    preserveAuthorization(sourceRows, (row) => ({ ...row, project: toProject, environment: toEnvironment }));
    const result = renameScope(project, environment, toProject, toEnvironment);
    console.log(`Renamed "${project}/${environment}" to "${toProject}/${toEnvironment}" (${result.moved} secret(s) moved).`);
    return;
  }

  console.error(RENAME_USAGE);
  process.exit(1);
}

async function migrateLegacyIfNeeded(): Promise<string | undefined> {
  if (!isInitialized() || !needsDualKeyMigration()) return undefined;
  validateLivePolicyBeforeMigration();
  const mode = inspectLegacyVaultMode();
  if (mode === "passphrase") {
    const currentPassphrase = await promptSecret("Enter current vault passphrase to migrate: ");
    migrateLegacyVaultToDualKey(readAuthorizationState, { currentPassphrase });
    return currentPassphrase;
  }
  const rows = listSecrets() as ScopedSecret[];
  const hasLockedRecord = rows.some((row) => readAuthorizationState(row.project, row.environment, row.name) === "locked");
  if (!hasLockedRecord) {
    migrateLegacyVaultToDualKey(readAuthorizationState);
    return undefined;
  }
  if (process.platform === "darwin") {
    await requireOperatorAuthentication("Enroll interactive custody while migrating locked Keyclasp records");
  } else if (process.platform !== "linux") {
    throw new Error("Interactive custody migration is not supported on this platform.");
  }
  const newInteractivePassphrase = await promptConfirmedPassphrase("Enter new interactive passphrase: ");
  migrateLegacyVaultToDualKey(readAuthorizationState, { newInteractivePassphrase });
  return newInteractivePassphrase;
}

function validateLivePolicyBeforeMigration(): void {
  validateLiveAuthorizationPolicy();
}

function hasPendingExclusiveVaultWork(): boolean {
  return hasInterruptedManagedRestore() ||
    needsDualKeyMigration() ||
    hasInterruptedCustodyTransition() ||
    hasInterruptedDualKeyMigration() ||
    hasInterruptedAuthorizationPolicy() ||
    hasPendingCustodySanitization() ||
    (isInitialized() && authorizationPolicyNeedsDefaultMigration());
}

async function recoverAndMigrateVault(): Promise<void> {
  recoverInterruptedManagedRestore();
  recoverInterruptedDualKeyMigration();
  recoverInterruptedCustodyTransition();
  recoverInterruptedAuthorizationPolicy();
  const migrationPassphrase = await migrateLegacyIfNeeded();
  if (isInitialized() && authorizationPolicyNeedsDefaultMigration()) {
    if (authorizationPolicyUsesDefaultSeed() && authorizationDefaultSeedRequiresUnlock()) {
      await ensureVaultUnlocked();
    }
    migrateAuthorizationPolicyDefault();
  }
  if (isInitialized() && hasPendingCustodySanitization()) {
    const passphrase = custodySanitizationRequiresUnlock()
      ? migrationPassphrase ?? await ensureVaultUnlocked()
      : undefined;
    completePendingCustodySanitization(passphrase);
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const command = args[0];
  const liveIndependentRestore = command === "backup" && args[1] === "restore" && Boolean(args[2]) && args.length === 3;

  if (command === "version" || command === "--version" || command === "-v") {
    console.log(getDisplayVersion());
    return;
  }

  if (!command || command === "help" || command === "--help" || command === "-h") {
    printHelp();
    return;
  }

  if (command !== "doctor") assertSoftwarePlatformSupported();

  let lifecycleLock: VaultLifecycleLock | null = null;
  if (command !== "doctor") {
    const lifecycleMode = liveIndependentRestore
      ? "exclusive"
      : hasPendingExclusiveVaultWork()
      ? "exclusive"
      : lifecycleModeForCommand(command);
    lifecycleLock = acquireVaultLifecycleLock(lifecycleMode);
    if (lifecycleMode === "exclusive" && !liveIndependentRestore) {
      await recoverAndMigrateVault();
    } else if (!liveIndependentRestore && hasPendingExclusiveVaultWork()) {
      lifecycleLock.release();
      lifecycleLock = acquireVaultLifecycleLock("exclusive");
      await recoverAndMigrateVault();
    }
  }

  try {
    switch (command) {
      case "init": {
        if (isInitialized()) {
          console.error(`Keyclasp is already initialized at ${getVaultLocation()}.`);
          process.exit(1);
        }
        const machineOnly = args[1] === "--machine-only" && args.length === 2;
        if ((!machineOnly && args.length !== 1) || (args[1] === "--machine-only" && args.length !== 2)) {
          console.error("Usage: keyclasp init [--machine-only]");
          process.exit(1);
        }
        console.log(`🔑 Initializing Keyclasp vault...`);
        const passphrase = machineOnly ? "" : await readPassphrase("Enter new vault passphrase: ");
        if (!machineOnly && !passphrase) {
          throw new Error("A non-empty passphrase is required. Use keyclasp init --machine-only for unattended machine custody.");
        }
        initializeVault(passphrase);
        initializeAuthorizationPolicy(machineOnly ? "machine" : "interactive");
        getKey(); // Verify key works
        console.log(`Keyclasp vault created at ${getVaultLocation()}`);
        console.log("Next: store a secret with `keyclasp set <name>`, then use it with `keyclasp run`.");
        break;
      }

      case "doctor": {
        const report = inspectHardwareMode();
        console.log(formatHardwareDoctor(report));
        if (report.hardwareMode !== "ready") process.exitCode = 1;
        break;
      }

      case "lock":
      case "unlock":
      case "inherit": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const { project, environment, rest } = extractGlobalFlags(args.slice(1), "scan-all");
        if (rest.length === 1 && rest[0] === "--default" && project === undefined && environment === undefined) {
          if (command === "inherit") {
            console.error("Usage: keyclasp lock|unlock --default");
            process.exit(1);
          }
          const preview = previewAuthorizationDefault(command, listRecordCustody());
          let transitionPassphrase: string | undefined;
          let transition = { changed: 0, tightened: 0, machineRemaining: 0 };
          const result = await mutateAuthorizationDefaultAuthorized(command, preview, {
            authorize: requireOperatorAuthentication,
            ensureUnlocked: async (authorizedPassphrase) => {
              transitionPassphrase = await ensureVaultUnlocked(authorizedPassphrase);
              return transitionPassphrase;
            },
            databaseMutation: (db, nextRules, _generation, defaultCustody) => {
              transition = transitionRecordCustody(db, nextRules, evaluateAuthorizationRules, defaultCustody);
            },
          });
          const cleanup = transition.tightened > 0
            ? completePendingCustodySanitization(transitionPassphrase)
            : { completed: false, machineKeyRetired: false };
          try {
            appendAuthorizationPolicyAudit({}, `${command}-default`, "success");
          } catch (auditError) {
            console.error(`WARNING: authorization default changed, but its audit entry could not be written: ${auditError instanceof Error ? auditError.message : "unknown error"}`);
          }
          console.log(`Default custody: ${result.defaultCustody}.`);
          console.log(`Transitioned ${transition.changed} record(s); ${preview.machineToInteractive} machine to interactive, ${preview.interactiveToMachine} interactive to machine.`);
          if (cleanup.machineKeyRetired) console.log("Retired the obsolete machine data key.");
          break;
        }
        let selector;
        try {
          selector = authorizationSelectorFromCommand(project, environment, rest);
        } catch {
          console.error(`Usage: keyclasp ${command} [--project NAME] [--environment NAME] [SECRET]`);
          process.exit(1);
        }
        const secret = selector.secret;
        let changed = false;
        let transitionPassphrase: string | undefined;
        let transition = { changed: 0, tightened: 0, machineRemaining: 0 };
        try {
          const effective = await mutateAuthorizationRuleAuthorized(selector, command, {
            authorize: requireOperatorAuthentication,
            ensureUnlocked: async (authorizedPassphrase) => {
              transitionPassphrase = await ensureVaultUnlocked(authorizedPassphrase);
            },
            databaseMutation: (db, nextRules, _generation, defaultCustody) => {
              transition = transitionRecordCustody(db, nextRules, evaluateAuthorizationRules, defaultCustody);
            },
          });
          changed = true;
          if (transition.tightened > 0) completePendingCustodySanitization(transitionPassphrase);
          try {
            appendAuthorizationPolicyAudit(selector, command, "success");
          } catch (auditError) {
            console.error(`WARNING: authorization policy changed, but its audit entry could not be written: ${auditError instanceof Error ? auditError.message : "unknown error"}`);
          }
          const target = [project ?? "*", environment ?? "*", secret].filter((part) => part !== undefined).join("/");
          console.log(`Authorization ${effective} for ${target}.`);
          if (transition.tightened > 0 && transition.machineRemaining === 0) console.log("Retired the obsolete machine data key.");
        } catch (error) {
          if (!changed) {
            try {
              appendAuthorizationPolicyAudit(selector, command, "failure");
            } catch (auditError) {
              console.error(`WARNING: authorization-policy failure could not be audited: ${auditError instanceof Error ? auditError.message : "unknown error"}`);
            }
          }
          throw error;
        }
        break;
      }

      case "passphrase": {
        if (!isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        const action = args[1];
        if ((action !== "set" && action !== "rotate") || args.length !== 2) {
          console.error("Usage: keyclasp passphrase set|rotate");
          process.exit(1);
        }
        if (action === "set") {
          if (vaultHasPassphrase()) throw new Error("Interactive passphrase is already set. Use passphrase rotate.");
          if (process.platform === "darwin") {
            await requireOperatorAuthentication("Enroll Keyclasp interactive custody", {
              vaultHasPassphrase: () => false,
            });
          } else if (process.platform !== "linux") {
            throw new Error("Interactive passphrase enrollment is not supported on this platform.");
          }
          const next = await promptConfirmedPassphrase("Enter new interactive passphrase: ");
          enrollInteractivePassphrase(next);
          console.log("Interactive custody enrolled.");
        } else {
          const authorization = await requireOperatorAuthentication("Rotate Keyclasp interactive passphrase");
          const current = authorization.method === "passphrase"
            ? authorization.passphrase
            : await promptSecret("Enter current interactive passphrase: ");
          const next = await promptConfirmedPassphrase("Enter new interactive passphrase: ");
          rotateInteractivePassphrase(current, next);
          console.log("Interactive passphrase rotated without rewriting secret ciphertext.");
        }
        break;
      }

      case "backup": {
        const action = args[1];
        const directory = args[2];
        if ((action !== "create" && action !== "restore") || !directory || args.length !== 3) {
          console.error("Usage: keyclasp backup create|restore <directory>");
          process.exit(1);
        }
        if (action === "create" && !isInitialized()) {
          console.error("Keyclasp not initialized. Run: keyclasp init");
          process.exit(1);
        }
        if (action === "create") {
          const manifest = await createManagedBackupAuthorized(path.resolve(directory), {
            authorize: requireOperatorAuthentication,
            ensureUnlocked: async () => { await ensureVaultUnlocked(); },
          });
          console.log(`Managed ${manifest.custody} backup created at ${path.resolve(directory)}.`);
        } else {
          const source = path.resolve(directory);
          const result = await restoreManagedBackupAuthorized(source, {
            authorize: (reason, mode) => requireOperatorAuthentication(reason, {
              vaultHasPassphrase: () => mode === "passphrase",
              verifyPassphrase: (passphrase) => verifyManagedBackupPassphrase(source, passphrase),
            }),
            promptPassphrase: () => promptSecret("Enter managed backup passphrase: "),
          });
          console.log(`Managed ${result.manifest.custody} backup restored from ${path.resolve(directory)}. Verify it with keyclasp status.`);
          if (result.rollbackEvidencePath) {
            console.error(`NOTICE: damaged live files were preserved at ${result.rollbackEvidencePath}. Retain them for incident review or remove them after an explicit retention decision.`);
          }
          for (const warning of result.cleanupWarnings) console.error(`WARNING: ${warning}`);
        }
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
        const keyClass = readAuthorizationState(project, environment, name) === "locked" ? "interactive" : "machine";
        if (!stdin.isTTY && rest[1] !== "-") {
          if (keyClass === "interactive" && !isInteractiveKeyUnlocked()) {
            console.error(KEY_LOCKED_ERROR);
            process.exit(1);
          }
        } else if (keyClass === "interactive") {
          await ensureVaultUnlocked();
        }

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
        storeSecret(project, environment, name, value, keyClass);
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
        await requireOperatorAuthentication(revealSecretReason([project, environment, secretName]));
        if (readSecretKeyClass(project, environment, secretName) === "interactive") await ensureVaultUnlocked();
        const val = resolveSecret(project, environment, secretName);
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
          getKey();
          await runBulkDelete({ project: pFlag, environment: eFlag, allProjects });
        } else {
          const delName = positionals[0];
          if (!delName) {
            console.error("Usage: keyclasp delete <name>  OR  keyclasp delete --bulk ...");
            process.exit(1);
          }
          getKey();
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
        const descriptor = getVaultDescriptor();
        const names = listSecrets(project, environment) as string[];
        const authorization = summarizeAuthorizationState(project, environment, names);
        const authorizationDefault = readAuthorizationDefault();

        console.log("Keyclasp Status");
        console.log("───────────────");
        console.log(`  Scope:      ${project}/${environment}  (project: ${projectSource}, environment: ${environmentSource})`);
        console.log(`  Vault:      ${getVaultLocation()}`);
        console.log(`  Mode:       software-${descriptor.custody}`);
        console.log(`  Authorization: ${authorization.state} (${authorization.locked} locked, ${authorization.unlocked} unlocked; future ${authorization.scopeDefault})`);
        console.log(`  Default:    ${authorizationDefault === "legacy-machine" ? "legacy machine default (explicit choice required)" : `${authorizationDefault} custody`}`);
        console.log(`  Secrets:    ${scopedCount} in scope`);
        console.log("  Values:     not displayed by status");
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
        console.log("This is a convenience for interactive use only. Scripts and agents should always pass --project/--environment explicitly.");
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
        if (vaultHasPassphrase() && summarizeKeyClasses().interactive > 0) await ensureVaultUnlocked();
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
        const runtime = createSoftwareRunRuntime({
          ensureUnlocked: async () => { await ensureVaultUnlocked(); },
          listSecretNames: (selectedProject, selectedEnvironment) =>
            listSecrets(selectedProject, selectedEnvironment) as string[],
          resolveSecret,
          resolveSecrets: resolveSecretsForRun,
          baseEnv: () => process.env,
          stdout: (chunk) => process.stdout.write(chunk),
          stderr: (chunk) => process.stderr.write(chunk),
          readAuthorizationState,
          readKeyClass: readSecretKeyClass,
          authorize: requireOperatorAuthentication,
        });
        const result = await runtime.run({
          allowUnsafe: parsed.allowUnsafe,
          envSpecs: parsed.envSpecs,
          commandArgs: parsed.commandArgs,
          scope: { project, environment },
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
    lifecycleLock?.release();
  }
}

main().catch((err) => {
  console.error("Error:", err.message);
  closeDb();
  process.exit(1);
});
