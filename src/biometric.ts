// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Keyclasp

import { spawnSync } from "node:child_process";
import { stdin, stdout } from "node:process";
import { StringDecoder } from "node:string_decoder";
import { fileURLToPath } from "node:url";
import { vaultHasPassphrase, authorizeAndUnlockVaultPassphrase } from "./vault.js";
import type { OperatorAuthorization } from "./runtime.js";
export type { OperatorAuthorization } from "./runtime.js";

export interface BiometricRunnerResult {
  status: number | null;
  error?: Error;
  stdout?: string;
  stderr?: string;
}

export type BiometricRunner = (command: string, args: string[]) => BiometricRunnerResult;

export interface BiometricAuthenticationOptions {
  platform?: NodeJS.Platform;
  helperPath?: string;
  runner?: BiometricRunner;
}

export type BiometricEvaluation =
  | { kind: "ok" }
  | { kind: "unavailable"; message: string }
  | { kind: "cancelled"; message: string }
  | { kind: "denied"; message: string };

export interface OperatorAuthenticationOptions extends BiometricAuthenticationOptions {
  promptPassphrase?: () => string | Promise<string>;
  verifyPassphrase?: (passphrase: string) => boolean;
  vaultHasPassphrase?: () => boolean;
}

type SecretResolver = (name: string) => string | null;
type OperatorAuthenticator = (reason: string) => unknown | Promise<unknown>;

const MACOS_HELPER_PATH = fileURLToPath(
  new URL("../native/macos-biometric.js", import.meta.url),
);

function runMacOSHelper(command: string, args: string[]): BiometricRunnerResult {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    timeout: 60_000,
  });
  return {
    status: result.status,
    error: result.error,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

export function evaluateBiometricAuthentication(
  reason: string,
  options: BiometricAuthenticationOptions = {},
): BiometricEvaluation {
  const platform = options.platform ?? process.platform;
  if (platform !== "darwin") {
    return { kind: "unavailable", message: "Touch ID is unavailable on this platform." };
  }

  const runner = options.runner ?? runMacOSHelper;
  const result = runner(
    "/usr/bin/osascript",
    ["-l", "JavaScript", options.helperPath ?? MACOS_HELPER_PATH, reason],
  );

  if (result.error) {
    return { kind: "unavailable", message: "The macOS biometric authentication helper could not start." };
  }
  if (result.status === 0) {
    return { kind: "ok" };
  }

  const output = `${result.stderr ?? ""}\n${result.stdout ?? ""}`;
  if (output.includes("KEYCLASP_BIOMETRIC_USER_CANCELLED")) {
    return { kind: "cancelled", message: "Biometric authentication was cancelled by the operator." };
  }
  if (output.includes("KEYCLASP_BIOMETRIC_UNAVAILABLE")) {
    return { kind: "unavailable", message: "Touch ID is unavailable or not enrolled." };
  }
  if (/unavailable|not enrolled/i.test(output)) {
    return { kind: "unavailable", message: "Touch ID is unavailable or not enrolled." };
  }
  return { kind: "denied", message: "Biometric authentication failed." };
}

export function requireBiometricAuthentication(
  reason: string,
  options: BiometricAuthenticationOptions = {},
): void {
  const result = evaluateBiometricAuthentication(reason, options);
  if (result.kind === "ok") return;
  if (result.kind === "unavailable" && (options.platform ?? process.platform) !== "darwin") {
    throw new Error("This operation requires macOS Touch ID; no fallback authentication is allowed.");
  }
  if (result.kind === "unavailable" && result.message.includes("could not start")) {
    throw new Error("The macOS biometric authentication helper could not start.");
  }
  if (result.kind === "unavailable") {
    throw new Error("Touch ID is unavailable or not enrolled.");
  }
  throw new Error(result.message);
}

let passphrasePromptTail: Promise<void> = Promise.resolve();

async function defaultPromptPassphrase(): Promise<string> {
  const previousPrompt = passphrasePromptTail;
  let releasePrompt!: () => void;
  passphrasePromptTail = new Promise<void>((resolve) => {
    releasePrompt = resolve;
  });

  await previousPrompt;
  try {
    return await readPassphraseFromTerminal();
  } finally {
    releasePrompt();
  }
}

async function readPassphraseFromTerminal(): Promise<string> {
  if (!stdin.isTTY) {
    throw new Error("Operator authorization requires an interactive terminal.");
  }

  const wasRaw = stdin.isRaw === true;
  return new Promise((resolve, reject) => {
    stdout.write("Enter vault passphrase: ");
    let value = "";
    let settled = false;
    const decoder = new StringDecoder("utf8");
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      let finalError = error;
      const cleanup = (action: () => void) => {
        try {
          action();
        } catch (cleanupError) {
          finalError ??= cleanupError instanceof Error
            ? cleanupError
            : new Error("Could not restore the terminal after passphrase entry.");
        }
      };
      cleanup(() => stdin.removeListener("data", onData));
      cleanup(() => stdin.removeListener("end", onEnd));
      cleanup(() => stdin.removeListener("close", onClose));
      cleanup(() => stdin.removeListener("error", onError));
      cleanup(() => stdin.setRawMode?.(wasRaw));
      cleanup(() => stdin.pause());
      cleanup(() => { stdout.write("\n"); });
      if (finalError) reject(finalError);
      else resolve(value);
    };
    const onEnd = () => finish(new Error("Passphrase entry ended before a value was submitted."));
    const onClose = () => finish(new Error("Passphrase input closed before a value was submitted."));
    const onError = () => finish(new Error("Could not read the vault passphrase."));
    const onData = (chunk: Buffer) => {
      const processed = processPassphraseInput(value, decoder.write(chunk));
      value = processed.value;
      for (const action of processed.actions) {
        if (action === "mask") stdout.write("*");
        else {
          stdout.moveCursor(-1, 0);
          stdout.write(" ");
          stdout.moveCursor(-1, 0);
        }
      }
      if (processed.cancelled) finish(new Error("Passphrase entry was cancelled."));
      else if (processed.submitted) finish();
    };
    try {
      stdin.setRawMode?.(true);
      stdin.resume();
      stdin.on("data", onData);
      stdin.once("end", onEnd);
      stdin.once("close", onClose);
      stdin.once("error", onError);
    } catch (error) {
      finish(error instanceof Error ? error : new Error("Could not read the vault passphrase."));
    }
  });
}

export function processPassphraseInput(
  initialValue: string,
  input: string,
): { value: string; actions: Array<"mask" | "erase">; submitted: boolean; cancelled: boolean } {
  let value = initialValue;
  const actions: Array<"mask" | "erase"> = [];
  for (const character of input) {
    if (character === "\n" || character === "\r") {
      return { value, actions, submitted: true, cancelled: false };
    }
    if (character === "\u0003" || character === "\u0004") {
      return { value, actions, submitted: false, cancelled: true };
    }
    if (character === "\u007f") {
      const characters = [...value];
      if (characters.length > 0) {
        characters.pop();
        value = characters.join("");
        actions.push("erase");
      }
      continue;
    }
    if (character >= " ") {
      value += character;
      actions.push("mask");
    }
  }
  return { value, actions, submitted: false, cancelled: false };
}

export async function requireOperatorAuthentication(
  reason: string,
  options: OperatorAuthenticationOptions = {},
): Promise<OperatorAuthorization> {
  const platform = options.platform ?? process.platform;
  if (platform === "darwin") {
    const biometric = evaluateBiometricAuthentication(reason, options);
    if (biometric.kind === "ok") return { method: "touch-id" };
    if (biometric.kind === "unavailable" && biometric.message.includes("could not start")) {
      throw new Error("The macOS biometric authentication helper could not start.");
    }
    if (biometric.kind === "unavailable") throw new Error("Touch ID is unavailable or not enrolled.");
    throw new Error(biometric.message);
  }
  if (platform !== "linux") {
    throw new Error("Operator authorization is not supported on this platform yet.");
  }

  const hasPassphrase = options.vaultHasPassphrase ?? vaultHasPassphrase;
  if (!hasPassphrase()) {
    throw new Error("This Linux operation requires a non-empty vault passphrase; machine-only vaults fail closed.");
  }

  const prompt = options.promptPassphrase ?? defaultPromptPassphrase;
  const verify = options.verifyPassphrase ?? authorizeAndUnlockVaultPassphrase;
  const entered = await prompt();
  if (!verify(entered)) {
    throw new Error("Vault passphrase is incorrect.");
  }
  return { method: "passphrase", passphrase: entered };
}

export async function resolveSecretForOperator(
  name: string,
  resolveSecret: SecretResolver,
  authenticate: OperatorAuthenticator = requireOperatorAuthentication,
): Promise<string | null> {
  await authenticate(`Reveal secret "${name}"`);
  return resolveSecret(name);
}
