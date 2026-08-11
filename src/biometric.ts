// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Keyblind

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export interface BiometricRunnerResult {
  status: number | null;
  error?: Error;
}

export type BiometricRunner = (command: string, args: string[]) => BiometricRunnerResult;

export interface BiometricAuthenticationOptions {
  platform?: NodeJS.Platform;
  helperPath?: string;
  runner?: BiometricRunner;
}

type SecretResolver = (name: string) => string | null;
type BiometricAuthenticator = (reason: string) => void;

const MACOS_HELPER_PATH = fileURLToPath(
  new URL("../native/macos-biometric.js", import.meta.url),
);

function runMacOSHelper(command: string, args: string[]): BiometricRunnerResult {
  const result = spawnSync(command, args, {
    stdio: ["ignore", "ignore", "ignore"],
    timeout: 60_000,
  });
  return { status: result.status, error: result.error };
}

export function requireBiometricAuthentication(
  reason: string,
  options: BiometricAuthenticationOptions = {},
): void {
  const platform = options.platform ?? process.platform;
  if (platform !== "darwin") {
    throw new Error("This operation requires macOS Touch ID; no fallback authentication is allowed.");
  }

  const runner = options.runner ?? runMacOSHelper;
  const result = runner(
    "/usr/bin/osascript",
    ["-l", "JavaScript", options.helperPath ?? MACOS_HELPER_PATH, reason],
  );

  if (result.error) {
    throw new Error("The macOS biometric authentication helper could not start.");
  }
  if (result.status !== 0) {
    throw new Error("Biometric authentication failed or was cancelled.");
  }
}

export function resolveSecretForOperator(
  name: string,
  resolveSecret: SecretResolver,
  authenticate: BiometricAuthenticator = requireBiometricAuthentication,
): string | null {
  authenticate(`Reveal secret "${name}"`);
  return resolveSecret(name);
}
