import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import { StringDecoder } from "node:string_decoder";
import path from "node:path";
import { validateScopeName } from "./vault.js";
import type { OperatorAuthorizer, RunEnvSpec, RunResult, RunResultKind, ScopedRunRequest } from "./runtime.js";

export type { RunEnvSpec } from "./runtime.js";

export const REDACTION = "[KEYCLASP_REDACTED]";
export const MIN_LEAK_VALUE_LENGTH = 8;

export interface ParsedRunArgs {
  allowUnsafe: boolean;
  envSpecs: RunEnvSpec[];
  commandArgs: string[];
  project?: string;
  environment?: string;
}

export interface UnsafeCommand {
  reason: string;
}

export interface RunEnvironmentInput {
  baseEnv: NodeJS.ProcessEnv;
  secretNames: string[];
  envSpecs?: RunEnvSpec[];
  resolveSecret: (name: string) => string | null;
  resolveSecrets?: (names: readonly string[]) => ReadonlyMap<string, string>;
}

export interface RunEnvironment {
  env: NodeJS.ProcessEnv;
  leakValues: string[];
}

export type RunOutcomeKind = RunResultKind;

export interface RunOutcome extends RunResult {
  error?: Error;
}

export interface RunCommandOptions {
  args: string[];
  baseEnv: NodeJS.ProcessEnv;
  secretNames: string[];
  envSpecs?: RunEnvSpec[];
  resolveSecret: (name: string) => string | null;
  resolveSecrets?: (names: readonly string[]) => ReadonlyMap<string, string>;
  stdout: (chunk: string) => void;
  stderr: (chunk: string) => void;
  scopeLabel?: string;
  ensureUnlocked?: () => Promise<void>;
  authorizationRequired?: boolean;
  authorizationReason?: string;
  authorize?: OperatorAuthorizer;
}

export interface PreparedRunCommandOptions extends Omit<RunCommandOptions, "args" | "envSpecs" | "scopeLabel"> {
  request: ScopedRunRequest;
}

interface RedactorResult {
  output: string;
  leaked: boolean;
}

const BLOCKED_NAMES = new Set([
  "env",
  "printenv",
  "export",
  "declare",
  "typeset",
  "compgen",
]);

const SHELL_NAMES = new Set(["sh", "bash", "zsh"]);
const SHELL_DUMP_PATTERN = /\b(env|printenv|export|declare|typeset|compgen)\b/;

export function parseRunArgs(args: string[]): ParsedRunArgs {
  const commandArgs: string[] = [];
  const envSpecs: RunEnvSpec[] = [];
  let allowUnsafe = false;
  let project: string | undefined;
  let environment: string | undefined;
  let parsingKeyclaspOptions = true;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (parsingKeyclaspOptions && arg === "--allow-unsafe") {
      allowUnsafe = true;
      continue;
    }
    if (parsingKeyclaspOptions && arg === "--env") {
      const spec = args[index + 1];
      if (!spec) throw new Error("Missing value for --env. Expected SOURCE or SOURCE:TARGET.");
      envSpecs.push(parseEnvSpec(spec));
      index += 1;
      continue;
    }
    if (parsingKeyclaspOptions && arg.startsWith("--env=")) {
      envSpecs.push(parseEnvSpec(arg.slice("--env=".length)));
      continue;
    }
    if (parsingKeyclaspOptions && (arg === "--project" || arg === "-p")) {
      const value = args[index + 1];
      if (value === undefined) throw new Error("Missing value for --project.");
      validateScopeName(value, "project");
      project = value;
      index += 1;
      continue;
    }
    if (parsingKeyclaspOptions && arg.startsWith("--project=")) {
      project = arg.slice("--project=".length);
      validateScopeName(project, "project");
      continue;
    }
    if (parsingKeyclaspOptions && (arg === "--environment" || arg === "-E")) {
      const value = args[index + 1];
      if (value === undefined) throw new Error("Missing value for --environment.");
      validateScopeName(value, "environment");
      environment = value;
      index += 1;
      continue;
    }
    if (parsingKeyclaspOptions && arg.startsWith("--environment=")) {
      environment = arg.slice("--environment=".length);
      validateScopeName(environment, "environment");
      continue;
    }
    if (parsingKeyclaspOptions && arg === "--") {
      parsingKeyclaspOptions = false;
      continue;
    }
    parsingKeyclaspOptions = false;
    commandArgs.push(arg);
  }

  return {
    allowUnsafe,
    envSpecs,
    commandArgs,
    ...(project === undefined ? {} : { project }),
    ...(environment === undefined ? {} : { environment }),
  };
}

function parseEnvSpec(spec: string): RunEnvSpec {
  const separator = spec.indexOf(":");
  const sourceName = separator === -1 ? spec : spec.slice(0, separator);
  const targetName = separator === -1 ? spec : spec.slice(separator + 1);
  validateRunEnvName(sourceName, "source");
  validateRunEnvName(targetName, "target");
  return { sourceName, targetName };
}

function validateRunEnvName(name: string, label: "source" | "target"): void {
  if (name.length === 0 || name.includes("\0")) {
    throw new Error(`Invalid ${label} environment name.`);
  }
  if (label === "target" && !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
    throw new Error(`Invalid target environment name "${name}".`);
  }
}

function validateRunSelection(input: RunEnvironmentInput): RunEnvSpec[] {
  const explicit = input.envSpecs !== undefined && input.envSpecs.length > 0;
  const specs = explicit
    ? input.envSpecs!.map((spec) => ({ ...spec }))
    : input.secretNames.map((name) => ({ sourceName: name, targetName: name }));
  const available = new Set(input.secretNames);
  const seenTargets = new Set<string>();

  for (const spec of specs) {
    validateRunEnvName(spec.sourceName, "source");
    validateRunEnvName(spec.targetName, "target");
    if (seenTargets.has(spec.targetName)) {
      throw new Error(`Duplicate target environment name "${spec.targetName}".`);
    }
    seenTargets.add(spec.targetName);
  }
  for (const spec of specs) {
    if (explicit && !available.has(spec.sourceName)) {
      throw new Error(`Secret "${spec.sourceName}" not found.`);
    }
  }

  return specs;
}

export function checkUnsafeCommand(commandArgs: string[]): UnsafeCommand | null {
  const command = commandArgs[0];
  if (!command) return { reason: "no command provided" };

  const commandName = path.basename(command);
  if (BLOCKED_NAMES.has(commandName)) {
    return { reason: `'${commandName}' can leak injected secrets by dumping environment variables` };
  }

  if (SHELL_NAMES.has(commandName)) {
    const commandString = shellCommandString(commandArgs);
    if (commandString && SHELL_DUMP_PATTERN.test(commandString)) {
      return { reason: `'${commandName}' can leak injected secrets by dumping environment variables` };
    }
  }

  return null;
}

export function buildRunEnvironment(input: RunEnvironmentInput): RunEnvironment {
  return buildValidatedRunEnvironment(input, validateRunSelection(input));
}

function buildValidatedRunEnvironment(input: RunEnvironmentInput, specs: readonly RunEnvSpec[]): RunEnvironment {
  const env: NodeJS.ProcessEnv = { ...input.baseEnv };
  const leakValues: string[] = [];
  const seenLeakValues = new Set<string>();
  const requestedNames = [...new Set(specs.map((spec) => spec.sourceName))];
  const resolvedByName = input.resolveSecrets
    ? input.resolveSecrets(requestedNames)
    : new Map(requestedNames.map((name) => [name, input.resolveSecret(name)]));
  for (const name of requestedNames) {
    if (!resolvedByName.has(name) || resolvedByName.get(name) === null) {
      throw new Error(`Secret "${name}" disappeared before it could be injected.`);
    }
  }
  const resolved = specs.map((spec) => ({ spec, value: resolvedByName.get(spec.sourceName)! }));

  for (const item of resolved) {
    const { spec, value } = item;
    if (value.includes("\0")) {
      throw new Error(`Secret "${spec.sourceName}" contains a null byte and cannot be injected.`);
    }
    if (Buffer.from(value, "utf8").toString("utf8") !== value) {
      throw new Error(`Secret "${spec.sourceName}" is not well-formed Unicode and cannot be injected.`);
    }

    env[spec.targetName] = value;
    if (value.length >= MIN_LEAK_VALUE_LENGTH && !seenLeakValues.has(value)) {
      leakValues.push(value);
      seenLeakValues.add(value);
    }
  }

  return { env, leakValues };
}

export function createSecretRedactor(secretValues: string[]) {
  const values = [...new Set(secretValues.filter((value) => value.length > 0))]
    .sort((a, b) => b.length - a.length || a.localeCompare(b));
  const maxSecretLength = values.reduce((max, value) => Math.max(max, value.length), 0);
  let carry = "";
  let stopped = false;

  function firstCompleteMatch(input: string): { index: number; value: string } | null {
    let match: { index: number; value: string } | null = null;
    for (const value of values) {
      const index = input.indexOf(value);
      if (index === -1) continue;
      if (!match || index < match.index || (index === match.index && value.length > match.value.length)) {
        match = { index, value };
      }
    }
    return match;
  }

  return {
    write(chunk: string): RedactorResult {
      if (stopped) return { output: "", leaked: false };
      if (values.length === 0) return { output: chunk, leaked: false };

      const combined = carry + chunk;
      const match = firstCompleteMatch(combined);
      if (match) {
        stopped = true;
        carry = "";
        return {
          output: `${combined.slice(0, match.index)}${REDACTION}`,
          leaked: true,
        };
      }

      const keepLength = prefixCarryLength(combined, values, maxSecretLength);
      const flushLength = combined.length - keepLength;

      carry = combined.slice(flushLength);
      return { output: combined.slice(0, flushLength), leaked: false };
    },

    end(): RedactorResult {
      if (stopped) return { output: "", leaked: false };
      const match = firstCompleteMatch(carry);
      const output = match
        ? `${carry.slice(0, match.index)}${REDACTION}`
        : carry;
      carry = "";
      stopped = match !== null;
      return { output, leaked: match !== null };
    },
  };
}

function prefixCarryLength(input: string, values: string[], maxSecretLength: number): number {
  for (let length = Math.min(input.length, maxSecretLength - 1); length > 0; length -= 1) {
    const suffix = input.slice(-length);
    if (values.some((value) => value.startsWith(suffix))) return length;
  }
  return 0;
}

export async function runCommandWithSecrets(options: RunCommandOptions): Promise<RunOutcome> {
  let parsed: ParsedRunArgs;
  try {
    parsed = parseRunArgs(options.args);
  } catch (err: any) {
    options.stderr(`${err.message}\n`);
    return { kind: "error", exitCode: 1 };
  }

  return executePreparedRun({
    allowUnsafe: parsed.allowUnsafe,
    envSpecs: parsed.envSpecs.length > 0 ? parsed.envSpecs : options.envSpecs,
    commandArgs: parsed.commandArgs,
    scopeLabel: options.scopeLabel,
  }, options);
}

export async function runPreparedCommandWithSecrets(
  options: PreparedRunCommandOptions,
): Promise<RunOutcome> {
  return executePreparedRun({
    allowUnsafe: options.request.allowUnsafe,
    envSpecs: [...options.request.envSpecs],
    commandArgs: [...options.request.commandArgs],
    scopeLabel: `${options.request.scope.project}/${options.request.scope.environment}`,
  }, options);
}

interface PreparedRun {
  allowUnsafe: boolean;
  envSpecs?: RunEnvSpec[];
  commandArgs: string[];
  scopeLabel?: string;
}

async function executePreparedRun(
  prepared: PreparedRun,
  options: Omit<RunCommandOptions, "args" | "envSpecs" | "scopeLabel">,
): Promise<RunOutcome> {
  if (prepared.commandArgs.length === 0) {
    options.stderr("Usage: keyclasp run [--project NAME] [--environment NAME] [--allow-unsafe] [--env SOURCE[:TARGET]] <command...>\n");
    return { kind: "error", exitCode: 1 };
  }

  const selectionInput: RunEnvironmentInput = {
    baseEnv: options.baseEnv,
    secretNames: options.secretNames,
    envSpecs: prepared.envSpecs,
    resolveSecret: options.resolveSecret,
    resolveSecrets: options.resolveSecrets,
  };
  let validatedSpecs: RunEnvSpec[];
  try {
    validatedSpecs = validateRunSelection(selectionInput);
  } catch (err: any) {
    options.stderr(`${err.message}\n`);
    return { kind: "error", exitCode: 1 };
  }

  const unsafe = checkUnsafeCommand(prepared.commandArgs);
  if (!prepared.allowUnsafe && unsafe) {
    options.stderr(`BLOCKED: ${unsafe.reason}.\n`);
    options.stderr("Operator override: keyclasp run --allow-unsafe -- <command...>\n");
    return { kind: "blocked", exitCode: 2 };
  }

  const envSpecs = prepared.envSpecs;
  const wholeScope = !envSpecs || envSpecs.length === 0;
  if (wholeScope || options.authorizationRequired) {
    try {
      const reason = options.authorizationReason ??
        (wholeScope
          ? `Inject every Keyclasp secret in ${prepared.scopeLabel ?? "the selected scope"}`
          : `Run locked named Keyclasp secrets in ${prepared.scopeLabel ?? "the selected scope"}`);
      if (!options.authorize) throw new Error("Operator authorization is not configured.");
      await options.authorize(reason);
    } catch (err: any) {
      options.stderr(`BLOCKED: ${err.message}\n`);
      return { kind: "blocked", exitCode: 2 };
    }
  }

  try {
    await options.ensureUnlocked?.();
  } catch (err: any) {
    options.stderr(`${err.message}\n`);
    return { kind: "error", exitCode: 1 };
  }

  let env: NodeJS.ProcessEnv;
  let leakValues: string[];
  try {
    ({ env, leakValues } = buildValidatedRunEnvironment(selectionInput, validatedSpecs));
  } catch (err: any) {
    options.stderr(`${err.message}\n`);
    return { kind: "error", exitCode: 1 };
  }

  if (prepared.allowUnsafe) {
    options.stderr("WARNING: keyclasp run exfiltration protection disabled by --allow-unsafe.\n");
    const outcome = await spawnRaw(prepared.commandArgs, env);
    reportSpawnError(outcome, options.stderr);
    return outcome;
  }

  const outcome = await spawnGuarded(prepared.commandArgs, env, leakValues, options.stdout, options.stderr);
  reportSpawnError(outcome, options.stderr);
  return outcome;
}

function reportSpawnError(outcome: RunOutcome, writeStderr: (chunk: string) => void): void {
  if (outcome.kind !== "error" || !outcome.error) return;
  const code = (outcome.error as NodeJS.ErrnoException).code;
  if (typeof code === "string") {
    writeStderr(`Failed to start child command (${code}).\n`);
  } else {
    writeStderr(`Child command supervision failed: ${outcome.error.message}\n`);
  }
}

function shellCommandString(commandArgs: string[]): string | null {
  for (let i = 1; i < commandArgs.length; i += 1) {
    const arg = commandArgs[i];
    if (isShellCommandFlag(arg)) {
      return commandArgs[i + 1] ?? "";
    }
  }
  return null;
}

function isShellCommandFlag(arg: string): boolean {
  return /^-[A-Za-z]*c[A-Za-z]*$/.test(arg);
}

function spawnRaw(commandArgs: string[], env: NodeJS.ProcessEnv): Promise<RunOutcome> {
  const [command, ...rest] = commandArgs;
  return new Promise((resolve) => {
    const child = spawn(command, rest, { stdio: "inherit", env, detached: process.platform !== "win32" });
    const relay = installTerminationRelay(child);
    child.on("error", (error) => {
      relay.cleanup();
      resolve({ kind: "error", exitCode: 1, error });
    });
    child.on("close", async (code, signal) => {
      const relayedSignal = relay.signal;
      try {
        await relay.waitForTermination();
      } catch (error) {
        relay.cleanup();
        resolve({ kind: "error", exitCode: 1, error: error as Error });
        return;
      }
      relay.cleanup();
      resolve({ kind: "exit", exitCode: exitCodeForClose(code, relayedSignal ?? signal) });
    });
  });
}

function spawnGuarded(
  commandArgs: string[],
  env: NodeJS.ProcessEnv,
  leakValues: string[],
  writeStdout: (chunk: string) => void,
  writeStderr: (chunk: string) => void,
): Promise<RunOutcome> {
  const [command, ...rest] = commandArgs;
  const stdoutRedactor = createSecretRedactor(leakValues);
  const stderrRedactor = createSecretRedactor(leakValues);
  const stdoutDecoder = new StringDecoder("utf8");
  const stderrDecoder = new StringDecoder("utf8");
  let leakDetected = false;
  let outputForwardingStopped = false;
  let settled = false;
  let leakTermination: Promise<void> | null = null;

  return new Promise((resolve) => {
    const resolveOnce = (outcome: RunOutcome) => {
      if (settled) return;
      settled = true;
      resolve(outcome);
    };

    const child = spawn(command, rest, {
      stdio: ["inherit", "pipe", "pipe"],
      env,
      detached: process.platform !== "win32",
    });
    const relay = installTerminationRelay(child);

    const handleLeak = () => {
      if (leakDetected) return;
      leakDetected = true;
      outputForwardingStopped = true;
      writeStderr("\nBLOCKED: command output contained an injected secret; terminated.\n");
      leakTermination = terminateChildGroup(child, "SIGTERM", 250);
      void leakTermination.catch(() => {});
    };

    child.stdout?.on("data", (chunk: Buffer) => {
      if (outputForwardingStopped) return;
      const result = stdoutRedactor.write(stdoutDecoder.write(chunk));
      if (result.output) writeStdout(result.output);
      if (result.leaked) handleLeak();
    });

    child.stderr?.on("data", (chunk: Buffer) => {
      if (outputForwardingStopped) return;
      const result = stderrRedactor.write(stderrDecoder.write(chunk));
      if (result.output) writeStderr(result.output);
      if (result.leaked) handleLeak();
    });

    child.on("error", (error) => {
      relay.cleanup();
      resolveOnce({ kind: "error", exitCode: 1, error });
    });
    child.on("close", async (code, signal) => {
      const relayedSignal = relay.signal;

      const lastStdout = stdoutDecoder.end();
      if (!outputForwardingStopped && lastStdout) {
        const result = stdoutRedactor.write(lastStdout);
        if (result.output) writeStdout(result.output);
        if (result.leaked) handleLeak();
      }
      const lastStderr = stderrDecoder.end();
      if (!outputForwardingStopped && lastStderr) {
        const result = stderrRedactor.write(lastStderr);
        if (result.output) writeStderr(result.output);
        if (result.leaked) handleLeak();
      }

      if (!outputForwardingStopped) {
        const finalStdout = stdoutRedactor.end();
        if (finalStdout.output) writeStdout(finalStdout.output);
        if (finalStdout.leaked) handleLeak();
      }
      if (!outputForwardingStopped) {
        const finalStderr = stderrRedactor.end();
        if (finalStderr.output) writeStderr(finalStderr.output);
        if (finalStderr.leaked) handleLeak();
      }

      let terminationError: Error | null = null;
      try {
        await Promise.all([relay.waitForTermination(), leakTermination ?? Promise.resolve()]);
      } catch (error) {
        terminationError = error as Error;
      }
      relay.cleanup();

      if (leakDetected) {
        if (terminationError) {
          writeStderr("ERROR: could not confirm that every supervised descendant terminated.\n");
        }
        resolveOnce({ kind: "leak", exitCode: 2 });
      } else if (terminationError) {
        resolveOnce({ kind: "error", exitCode: 1, error: terminationError });
      } else {
        resolveOnce({ kind: "exit", exitCode: exitCodeForClose(code, relayedSignal ?? signal) });
      }
    });
  });
}

function signalChildTree(child: ReturnType<typeof spawn>, signal: NodeJS.Signals): void {
  if (process.platform !== "win32" && child.pid !== undefined) {
    try {
      process.kill(-child.pid, signal);
      return;
    } catch {
      // The child may have exited between the state check and group signal.
    }
  }
  try {
    child.kill(signal);
  } catch {
    // Close/error handlers own process completion.
  }
}

async function terminateChildGroup(
  child: ReturnType<typeof spawn>,
  signal: NodeJS.Signals,
  graceMilliseconds: number,
): Promise<void> {
  signalChildTree(child, signal);
  if (process.platform === "win32" || child.pid === undefined) return;
  const groupId = child.pid;
  const forceAt = Date.now() + graceMilliseconds;
  const failAt = forceAt + 2_000;
  let forced = false;
  while (true) {
    if (!processGroupHasLiveMembers(groupId)) return;
    if (!forced && Date.now() >= forceAt) {
      forced = true;
      signalChildTree(child, "SIGKILL");
    }
    if (forced && Date.now() >= failAt) {
      throw new Error("Could not confirm that every supervised descendant terminated after SIGKILL.");
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

function processGroupHasLiveMembers(groupId: number): boolean {
  try {
    process.kill(-groupId, 0);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ESRCH") return false;
    if (code === "EPERM") {
      throw new Error("The supervised process group still exists but cannot be signalled by this user.");
    }
    throw error;
  }

  if (process.platform !== "linux") return true;
  const procState = inspectLinuxProcessGroup(groupId);
  return procState ?? true;
}

function inspectLinuxProcessGroup(groupId: number): boolean | null {
  let foundMember = false;
  let inspectionIncomplete = false;
  try {
    for (const entry of fs.readdirSync("/proc", { withFileTypes: true })) {
      if (!entry.isDirectory() || !/^\d+$/.test(entry.name)) continue;
      let stat: string;
      try {
        stat = fs.readFileSync(`/proc/${entry.name}/stat`, "utf8");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") inspectionIncomplete = true;
        continue;
      }
      const commandEnd = stat.lastIndexOf(")");
      if (commandEnd === -1) continue;
      const fields = stat.slice(commandEnd + 1).trim().split(/\s+/);
      const state = fields[0];
      const processGroup = Number(fields[2]);
      if (processGroup !== groupId) continue;
      foundMember = true;
      if (state !== "Z" && state !== "X") return true;
    }
  } catch {
    return null;
  }
  return foundMember && !inspectionIncomplete ? false : null;
}

function installTerminationRelay(child: ReturnType<typeof spawn>): {
  readonly signal: NodeJS.Signals | null;
  waitForTermination: () => Promise<void>;
  cleanup: () => void;
} {
  let relayedSignal: NodeJS.Signals | null = null;
  let termination: Promise<void> | null = null;
  const signals: NodeJS.Signals[] = ["SIGHUP", "SIGINT", "SIGTERM"];
  const handlers = new Map<NodeJS.Signals, () => void>();
  for (const signal of signals) {
    const handler = () => {
      if (relayedSignal) return;
      relayedSignal = signal;
      termination = terminateChildGroup(child, signal, 1_000);
      void termination.catch(() => {});
    };
    handlers.set(signal, handler);
    process.on(signal, handler);
  }
  return {
    get signal() { return relayedSignal; },
    waitForTermination: () => termination ?? Promise.resolve(),
    cleanup() {
      for (const [signal, handler] of handlers) process.off(signal, handler);
    },
  };
}

function exitCodeForClose(code: number | null, signal: NodeJS.Signals | null): number {
  if (code !== null) return code;
  if (!signal) return 1;
  const signalNumber = os.constants.signals[signal];
  return 128 + (signalNumber ?? 0);
}
