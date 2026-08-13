import { spawn } from "node:child_process";
import os from "node:os";
import { StringDecoder } from "node:string_decoder";
import path from "node:path";
import { requireOperatorAuthentication } from "./biometric.js";
import { validateScopeName } from "./vault.js";

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
}

export interface RunEnvironment {
  env: NodeJS.ProcessEnv;
  leakValues: string[];
}

export interface RunEnvSpec {
  sourceName: string;
  targetName: string;
}

export type RunOutcomeKind = "blocked" | "exit" | "leak" | "error";

export interface RunOutcome {
  kind: RunOutcomeKind;
  exitCode: number;
  error?: Error;
}

export interface RunCommandOptions {
  args: string[];
  baseEnv: NodeJS.ProcessEnv;
  secretNames: string[];
  envSpecs?: RunEnvSpec[];
  resolveSecret: (name: string) => string | null;
  stdout: (chunk: string) => void;
  stderr: (chunk: string) => void;
  scopeLabel?: string;
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
  const env: NodeJS.ProcessEnv = { ...input.baseEnv };
  const leakValues: string[] = [];
  const seenLeakValues = new Set<string>();
  const explicitSpecs = input.envSpecs !== undefined && input.envSpecs.length > 0;
  const specs = explicitSpecs
    ? input.envSpecs!
    : input.secretNames.map((name) => ({ sourceName: name, targetName: name }));
  const seenTargets = new Set<string>();

  for (const spec of specs) {
    try {
      validateRunEnvName(spec.sourceName, "source");
      validateRunEnvName(spec.targetName, "target");
    } catch (err) {
      if (explicitSpecs) throw err;
      continue;
    }
    if (seenTargets.has(spec.targetName)) {
      throw new Error(`Duplicate target environment name "${spec.targetName}".`);
    }
    seenTargets.add(spec.targetName);

    const value = input.resolveSecret(spec.sourceName);
    if (value === null) {
      if (explicitSpecs) throw new Error(`Secret "${spec.sourceName}" not found.`);
      continue;
    }
    if (value.includes("\0")) {
      if (explicitSpecs) throw new Error(`Secret "${spec.sourceName}" contains a null byte and cannot be injected.`);
      continue;
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
    .sort((a, b) => b.length - a.length);
  const maxSecretLength = values.reduce((max, value) => Math.max(max, value.length), 0);
  let carry = "";

  function redact(input: string): RedactorResult {
    let output = input;
    let leaked = false;

    for (const value of values) {
      if (!output.includes(value)) continue;
      leaked = true;
      output = output.split(value).join(REDACTION);
    }

    return { output, leaked };
  }

  return {
    write(chunk: string): RedactorResult {
      if (values.length === 0) return { output: chunk, leaked: false };

      const combined = carry + chunk;
      const keepLength = prefixCarryLength(combined, values, maxSecretLength);
      const flushLength = combined.length - keepLength;

      carry = combined.slice(flushLength);
      const redacted = redact(combined.slice(0, flushLength));
      return redacted;
    },

    end(): RedactorResult {
      const redacted = redact(carry);
      carry = "";
      return redacted;
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
  if (parsed.commandArgs.length === 0) {
    options.stderr("Usage: keyclasp run [--project NAME] [--environment NAME] [--allow-unsafe] [--env SOURCE[:TARGET]] <command...>\n");
    return { kind: "error", exitCode: 1 };
  }

  const unsafe = checkUnsafeCommand(parsed.commandArgs);
  if (!parsed.allowUnsafe && unsafe) {
    options.stderr(`BLOCKED: ${unsafe.reason}.\n`);
    options.stderr("Operator override: keyclasp run --allow-unsafe -- <command...>\n");
    return { kind: "blocked", exitCode: 2 };
  }

  const envSpecs = parsed.envSpecs.length > 0 ? parsed.envSpecs : options.envSpecs;
  if ((!envSpecs || envSpecs.length === 0) && options.secretNames.length > 0) {
    try {
      await requireOperatorAuthentication(`Inject every Keyclasp secret in ${options.scopeLabel ?? "the selected scope"}`);
    } catch (err: any) {
      options.stderr(`BLOCKED: ${err.message}\n`);
      return { kind: "blocked", exitCode: 2 };
    }
  }

  let env: NodeJS.ProcessEnv;
  let leakValues: string[];
  try {
    ({ env, leakValues } = buildRunEnvironment({
      baseEnv: options.baseEnv,
      secretNames: options.secretNames,
      envSpecs,
      resolveSecret: options.resolveSecret,
    }));
  } catch (err: any) {
    options.stderr(`${err.message}\n`);
    return { kind: "error", exitCode: 1 };
  }

  if (parsed.allowUnsafe) {
    options.stderr("WARNING: keyclasp run exfiltration protection disabled by --allow-unsafe.\n");
    const outcome = await spawnRaw(parsed.commandArgs, env);
    reportSpawnError(outcome, options.stderr);
    return outcome;
  }

  const outcome = await spawnGuarded(parsed.commandArgs, env, leakValues, options.stdout, options.stderr);
  reportSpawnError(outcome, options.stderr);
  return outcome;
}

function reportSpawnError(outcome: RunOutcome, writeStderr: (chunk: string) => void): void {
  if (outcome.kind !== "error" || !outcome.error) return;
  const code = (outcome.error as NodeJS.ErrnoException).code;
  const suffix = typeof code === "string" ? ` (${code})` : "";
  writeStderr(`Failed to start child command${suffix}.\n`);
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
    const child = spawn(command, rest, { stdio: "inherit", env });
    child.on("error", (error) => resolve({ kind: "error", exitCode: 1, error }));
    child.on("close", (code, signal) => resolve({ kind: "exit", exitCode: exitCodeForClose(code, signal) }));
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
  let settled = false;
  let closed = false;
  let killTimer: ReturnType<typeof setTimeout> | null = null;

  return new Promise((resolve) => {
    const resolveOnce = (outcome: RunOutcome) => {
      if (settled) return;
      settled = true;
      resolve(outcome);
    };

    const child = spawn(command, rest, {
      stdio: ["inherit", "pipe", "pipe"],
      env,
    });

    const handleLeak = () => {
      if (leakDetected) return;
      leakDetected = true;
      writeStderr("\nBLOCKED: command output contained an injected secret; terminated.\n");
      if (closed) return;
      child.kill("SIGTERM");
      killTimer = setTimeout(() => {
        if (!closed) child.kill("SIGKILL");
      }, 250);
    };

    child.stdout?.on("data", (chunk: Buffer) => {
      const result = stdoutRedactor.write(stdoutDecoder.write(chunk));
      if (result.output) writeStdout(result.output);
      if (result.leaked) handleLeak();
    });

    child.stderr?.on("data", (chunk: Buffer) => {
      const result = stderrRedactor.write(stderrDecoder.write(chunk));
      if (result.output) writeStderr(result.output);
      if (result.leaked) handleLeak();
    });

    child.on("error", (error) => resolveOnce({ kind: "error", exitCode: 1, error }));
    child.on("close", (code, signal) => {
      closed = true;
      if (killTimer) {
        clearTimeout(killTimer);
        killTimer = null;
      }

      const lastStdout = stdoutDecoder.end();
      if (lastStdout) {
        const result = stdoutRedactor.write(lastStdout);
        if (result.output) writeStdout(result.output);
        if (result.leaked) handleLeak();
      }
      const lastStderr = stderrDecoder.end();
      if (lastStderr) {
        const result = stderrRedactor.write(lastStderr);
        if (result.output) writeStderr(result.output);
        if (result.leaked) handleLeak();
      }

      const finalStdout = stdoutRedactor.end();
      if (finalStdout.output) writeStdout(finalStdout.output);
      const finalStderr = stderrRedactor.end();
      if (finalStderr.output) writeStderr(finalStderr.output);
      if (finalStdout.leaked || finalStderr.leaked) handleLeak();

      if (leakDetected) {
        resolveOnce({ kind: "leak", exitCode: 2 });
      } else {
        resolveOnce({ kind: "exit", exitCode: exitCodeForClose(code, signal) });
      }
    });
  });
}

function exitCodeForClose(code: number | null, signal: NodeJS.Signals | null): number {
  if (code !== null) return code;
  if (!signal) return 1;
  const signalNumber = os.constants.signals[signal];
  return 128 + (signalNumber ?? 0);
}
