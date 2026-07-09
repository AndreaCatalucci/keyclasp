import { spawn } from "node:child_process";
import os from "node:os";
import { StringDecoder } from "node:string_decoder";
import path from "node:path";

export const REDACTION = "[KEYBLIND_REDACTED]";
export const MIN_LEAK_VALUE_LENGTH = 8;

export interface ParsedRunArgs {
  allowUnsafe: boolean;
  commandArgs: string[];
}

export interface UnsafeCommand {
  reason: string;
}

export interface RunEnvironmentInput {
  baseEnv: NodeJS.ProcessEnv;
  secretNames: string[];
  resolveSecret: (name: string) => string | null;
}

export interface RunEnvironment {
  env: NodeJS.ProcessEnv;
  leakValues: string[];
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
  resolveSecret: (name: string) => string | null;
  stdout: (chunk: string) => void;
  stderr: (chunk: string) => void;
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
  let allowUnsafe = false;
  let parsingKeyblindOptions = true;

  for (const arg of args) {
    if (parsingKeyblindOptions && arg === "--allow-unsafe") {
      allowUnsafe = true;
      continue;
    }
    if (parsingKeyblindOptions && arg === "--") {
      parsingKeyblindOptions = false;
      continue;
    }
    parsingKeyblindOptions = false;
    commandArgs.push(arg);
  }

  return { allowUnsafe, commandArgs };
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

  for (const name of input.secretNames) {
    if (name.includes("\0")) continue;
    const value = input.resolveSecret(name);
    if (value === null || value.includes("\0")) continue;

    env[name] = value;
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
      const keepLength = Math.max(0, maxSecretLength - 1);
      let flushLength = Math.max(0, combined.length - keepLength);
      let leaked = false;

      for (const value of values) {
        let index = combined.indexOf(value);
        while (index !== -1) {
          leaked = true;
          const end = index + value.length;
          if (index < flushLength && end > flushLength) {
            flushLength = index;
          }
          index = combined.indexOf(value, index + 1);
        }
      }

      if (combined.length <= keepLength) {
        carry = combined;
        return { output: "", leaked };
      }

      carry = combined.slice(flushLength);
      const redacted = redact(combined.slice(0, flushLength));
      return { output: redacted.output, leaked: leaked || redacted.leaked };
    },

    end(): RedactorResult {
      const redacted = redact(carry);
      carry = "";
      return redacted;
    },
  };
}

export async function runCommandWithSecrets(options: RunCommandOptions): Promise<RunOutcome> {
  const parsed = parseRunArgs(options.args);
  if (parsed.commandArgs.length === 0) {
    options.stderr("Usage: keyblind run [--allow-unsafe] <command...>\n");
    return { kind: "error", exitCode: 1 };
  }

  const unsafe = checkUnsafeCommand(parsed.commandArgs);
  if (!parsed.allowUnsafe && unsafe) {
    options.stderr(`BLOCKED: ${unsafe.reason}.\n`);
    options.stderr("Operator override: keyblind run --allow-unsafe -- <command...>\n");
    return { kind: "blocked", exitCode: 2 };
  }

  const { env, leakValues } = buildRunEnvironment({
    baseEnv: options.baseEnv,
    secretNames: options.secretNames,
    resolveSecret: options.resolveSecret,
  });

  if (parsed.allowUnsafe) {
    options.stderr("WARNING: keyblind run exfiltration protection disabled by --allow-unsafe.\n");
    return spawnRaw(parsed.commandArgs, env);
  }

  return spawnGuarded(parsed.commandArgs, env, leakValues, options.stdout, options.stderr);
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
