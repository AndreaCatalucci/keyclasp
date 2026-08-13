// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Keyclasp

import { spawnSync } from "node:child_process";
import { stdin, stdout } from "node:process";
import readline from "node:readline";
import { fileURLToPath } from "node:url";
import { vaultHasPassphrase, verifyVaultPassphrase } from "./vault.js";

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
  | { kind: "denied"; message: string };

export interface OperatorAuthenticationOptions extends BiometricAuthenticationOptions {
  promptPassphrase?: () => string | Promise<string>;
  verifyPassphrase?: (passphrase: string) => boolean;
  vaultHasPassphrase?: () => boolean;
}

type SecretResolver = (name: string) => string | null;
type OperatorAuthenticator = (reason: string) => void | Promise<void>;

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
  if (/unavailable|not enrolled/i.test(output)) {
    return { kind: "unavailable", message: "Touch ID is unavailable or not enrolled." };
  }
  return { kind: "denied", message: "Biometric authentication failed or was cancelled." };
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
  throw new Error("Biometric authentication failed or was cancelled.");
}

async function defaultPromptPassphrase(): Promise<string> {
  if (!stdin.isTTY) {
    throw new Error("Touch ID is unavailable. Re-run in an interactive terminal to enter the vault passphrase.");
  }

  const rl = readline.createInterface({ input: stdin, output: stdout });
  return new Promise((resolve) => {
    stdout.write("Enter vault passphrase: ");
    let value = "";
    const onData = (char: Buffer) => {
      const str = char.toString();
      switch (str) {
        case "\n":
        case "\r":
          stdin.removeListener("data", onData);
          stdin.pause();
          stdout.write("\n");
          rl.close();
          resolve(value);
          break;
        case "\u0003":
          stdin.removeListener("data", onData);
          stdin.pause();
          stdout.write("\n");
          rl.close();
          process.exit(1);
          break;
        case "\u007f":
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

export async function requireOperatorAuthentication(
  reason: string,
  options: OperatorAuthenticationOptions = {},
): Promise<void> {
  const biometric = evaluateBiometricAuthentication(reason, options);
  if (biometric.kind === "ok") return;
  if (biometric.kind === "denied") {
    throw new Error(biometric.message);
  }

  const hasPassphrase = options.vaultHasPassphrase ?? vaultHasPassphrase;
  if (!hasPassphrase()) {
    throw new Error("Touch ID is unavailable and this vault has no passphrase. Re-init with a passphrase, or use explicit --env mappings.");
  }

  const prompt = options.promptPassphrase ?? defaultPromptPassphrase;
  const verify = options.verifyPassphrase ?? verifyVaultPassphrase;
  const entered = await prompt();
  if (!verify(entered)) {
    throw new Error("Vault passphrase is incorrect.");
  }
}

export async function resolveSecretForOperator(
  name: string,
  resolveSecret: SecretResolver,
  authenticate: OperatorAuthenticator = requireOperatorAuthentication,
): Promise<string | null> {
  await authenticate(`Reveal secret "${name}"`);
  return resolveSecret(name);
}
