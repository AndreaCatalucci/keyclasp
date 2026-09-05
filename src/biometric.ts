// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Keyclasp

import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { stdin, stdout } from "node:process";
import { StringDecoder } from "node:string_decoder";
import { fileURLToPath } from "node:url";
import { assertNoWriteGrantingMacOsAcl } from "./owner-only-path.js";
import { vaultHasPassphrase, authorizeAndUnlockVaultPassphrase } from "./vault.js";
import type { OperatorAuthorization } from "./runtime.js";
export type { OperatorAuthorization } from "./runtime.js";

export interface BiometricRunnerResult {
  status: number | null;
  error?: Error;
}

export type BiometricRunner = (
  command: string,
  args: string[],
  input: string,
  env: NodeJS.ProcessEnv,
) => BiometricRunnerResult;

export type BiometricHelperValidator = (helperPath: string, manifestPath: string) => void;

export interface BiometricAuthenticationOptions {
  platform?: NodeJS.Platform;
  helperPath?: string;
  manifestPath?: string;
  runner?: BiometricRunner;
  validateHelper?: BiometricHelperValidator;
}

export type BiometricEvaluation =
  | { kind: "ok" }
  | { kind: "unavailable"; message: string }
  | { kind: "cancelled"; message: string }
  | { kind: "denied"; message: string }
  | { kind: "timeout"; message: string }
  | { kind: "invalid"; message: string };

export interface OperatorAuthenticationOptions extends BiometricAuthenticationOptions {
  promptPassphrase?: () => string | Promise<string>;
  verifyPassphrase?: (passphrase: string) => boolean;
  vaultHasPassphrase?: () => boolean;
}

const MACOS_HELPER_PATH = fileURLToPath(new URL(
  "../native/Keyclasp.app/Contents/MacOS/keyclasp-biometric",
  import.meta.url,
));
const MACOS_HELPER_MANIFEST_PATH = fileURLToPath(new URL(
  "../keyclasp-macos-helper-candidate.json",
  import.meta.url,
));
const MACOS_HELPER_IDENTIFIER = "dev.keyclasp.biometric";

interface HelperManifestFile {
  path: string;
  sha256: string;
}

interface HelperManifest {
  schemaVersion: number;
  bundle: string;
  bundleIdentifier: string;
  architecture: string;
  designatedRequirement: string;
  signature: {
    hardenedRuntime: boolean;
    entitlements: string[];
  };
  bundleFiles: HelperManifestFile[];
}

export function minimalMacOSHelperEnvironment(): NodeJS.ProcessEnv {
  return {
    PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
    LANG: "C",
    LC_ALL: "C",
    TMPDIR: "/tmp",
  };
}

function runMacOSHelper(
  command: string,
  args: string[],
  input: string,
  env: NodeJS.ProcessEnv,
): BiometricRunnerResult {
  const result = spawnSync(command, args, {
    input,
    env,
    stdio: ["pipe", "ignore", "ignore"],
    timeout: 60_000,
  });
  return {
    status: result.status,
    error: result.error,
  };
}

function readHelperManifest(manifestPath: string): HelperManifest {
  let value: unknown;
  try {
    value = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  } catch {
    throw new Error("The packaged macOS biometric helper manifest is unavailable or invalid.");
  }
  if (!value || typeof value !== "object") {
    throw new Error("The packaged macOS biometric helper manifest is invalid.");
  }
  const manifest = value as Partial<HelperManifest>;
  if (
    manifest.schemaVersion !== 2 ||
    manifest.bundle !== "Keyclasp.app" ||
    manifest.bundleIdentifier !== MACOS_HELPER_IDENTIFIER ||
    manifest.architecture !== "arm64" ||
    typeof manifest.designatedRequirement !== "string" ||
    manifest.designatedRequirement.length === 0 ||
    manifest.signature?.hardenedRuntime !== true ||
    !Array.isArray(manifest.signature.entitlements) ||
    manifest.signature.entitlements.length !== 0 ||
    !Array.isArray(manifest.bundleFiles)
  ) {
    throw new Error("The packaged macOS biometric helper manifest is invalid.");
  }
  return manifest as HelperManifest;
}

function checkedStat(entryPath: string, expectedUid: number, kind: "directory" | "file"): fs.Stats {
  const before = fs.lstatSync(entryPath);
  if (before.isSymbolicLink() || (kind === "directory" ? !before.isDirectory() : !before.isFile())) {
    throw new Error(`The macOS biometric helper path contains an unexpected ${kind} entry.`);
  }
  if (before.uid !== expectedUid || (before.mode & 0o022) !== 0) {
    throw new Error("The macOS biometric helper path has unsafe ownership or permissions.");
  }
  if (kind === "file" && before.nlink !== 1) {
    throw new Error("The macOS biometric helper path contains a multiply linked file.");
  }
  if (process.platform === "darwin") {
    assertNoWriteGrantingMacOsAcl(entryPath, "macOS biometric helper path");
  }
  const after = fs.lstatSync(entryPath);
  if (
    before.dev !== after.dev ||
    before.ino !== after.ino ||
    after.uid !== expectedUid ||
    (after.mode & 0o022) !== 0 ||
    after.isSymbolicLink() ||
    (kind === "directory" ? !after.isDirectory() : !after.isFile()) ||
    (kind === "file" && after.nlink !== 1)
  ) {
    throw new Error("The macOS biometric helper path changed during validation.");
  }
  return after;
}

function runValidationTool(command: string, args: string[]): { stdout: string; stderr: string } {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    env: minimalMacOSHelperEnvironment(),
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.status !== 0 || result.error) {
    throw new Error("The macOS biometric helper failed platform validation.");
  }
  return { stdout: result.stdout, stderr: result.stderr };
}

function validateAncestorChain(packageRoot: string, currentUid: number | undefined): void {
  let current = packageRoot;
  while (true) {
    const stat = fs.lstatSync(current);
    if (
      stat.isSymbolicLink() ||
      !stat.isDirectory() ||
      (stat.uid !== 0 && stat.uid !== currentUid) ||
      (stat.mode & 0o022) !== 0
    ) {
      throw new Error("The macOS biometric helper has an unsafe ancestor path.");
    }
    if (process.platform === "darwin") {
      assertNoWriteGrantingMacOsAcl(current, "macOS biometric helper ancestor");
    }
    const after = fs.lstatSync(current);
    if (stat.dev !== after.dev || stat.ino !== after.ino || stat.mode !== after.mode || stat.uid !== after.uid) {
      throw new Error("The macOS biometric helper ancestor changed during validation.");
    }
    const parent = path.dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

export function validateMacOSBiometricHelper(
  helperPath: string,
  manifestPath: string,
  expectedPackageOwnerUid?: number,
): void {
  const resolvedHelper = path.resolve(helperPath);
  const resolvedManifest = path.resolve(manifestPath);
  const packageRoot = path.dirname(resolvedManifest);
  const expectedHelper = path.join(packageRoot, "native", "Keyclasp.app", "Contents", "MacOS", "keyclasp-biometric");
  if (resolvedHelper !== expectedHelper) {
    throw new Error("The macOS biometric helper is outside the packaged bundle layout.");
  }

  const nativeDirectory = path.join(packageRoot, "native");
  const bundle = path.join(nativeDirectory, "Keyclasp.app");
  const contents = path.join(bundle, "Contents");
  const executableDirectory = path.join(contents, "MacOS");
  const infoPlist = path.join(contents, "Info.plist");
  const packageStat = fs.lstatSync(packageRoot);
  const currentUid = process.getuid?.();
  validateAncestorChain(packageRoot, currentUid);
  if (
    !packageStat.isDirectory() ||
    packageStat.isSymbolicLink() ||
    (packageStat.uid !== 0 && packageStat.uid !== currentUid) ||
    (expectedPackageOwnerUid !== undefined && packageStat.uid !== expectedPackageOwnerUid)
  ) {
    throw new Error("The macOS biometric helper package root has an unexpected owner or type.");
  }
  const expectedUid = packageStat.uid;
  for (const directory of [packageRoot, nativeDirectory, bundle, contents, executableDirectory]) {
    checkedStat(directory, expectedUid, "directory");
  }
  for (const file of [resolvedManifest, infoPlist, resolvedHelper]) {
    checkedStat(file, expectedUid, "file");
  }
  if ((fs.statSync(resolvedHelper).mode & 0o111) === 0) {
    throw new Error("The macOS biometric helper is not executable.");
  }
  if (fs.realpathSync(resolvedHelper) !== resolvedHelper || fs.realpathSync(resolvedManifest) !== resolvedManifest) {
    throw new Error("The macOS biometric helper path must not contain symbolic links.");
  }

  const manifest = readHelperManifest(resolvedManifest);
  const descriptors = new Map(manifest.bundleFiles.map((entry) => [entry.path, entry]));
  if (descriptors.size !== manifest.bundleFiles.length) {
    throw new Error("The packaged macOS biometric helper manifest contains duplicate paths.");
  }
  for (const [absolutePath, relativePath] of [
    [infoPlist, "native/Keyclasp.app/Contents/Info.plist"],
    [resolvedHelper, "native/Keyclasp.app/Contents/MacOS/keyclasp-biometric"],
  ] as const) {
    const descriptor = descriptors.get(relativePath);
    if (!descriptor || !/^[a-f0-9]{64}$/.test(descriptor.sha256)) {
      throw new Error("The packaged macOS biometric helper manifest is incomplete.");
    }
    const actual = crypto.createHash("sha256").update(fs.readFileSync(absolutePath)).digest("hex");
    if (actual !== descriptor.sha256) {
      throw new Error("The packaged macOS biometric helper does not match its manifest.");
    }
  }

  runValidationTool("/usr/bin/codesign", ["--verify", "--strict", bundle]);
  const signatureResult = runValidationTool("/usr/bin/codesign", ["-d", "--verbose=4", "-r-", bundle]);
  const signature = `${signatureResult.stdout}${signatureResult.stderr}`;
  const identifier = /^Identifier=(.+)$/m.exec(signature)?.[1];
  const requirement = /^# designated => (.+)$/m.exec(signature)?.[1];
  if (identifier !== MACOS_HELPER_IDENTIFIER || requirement !== manifest.designatedRequirement) {
    throw new Error("The macOS biometric helper has an unexpected signing identity.");
  }
  if (!/^CodeDirectory .*flags=.*\([^)]*runtime[^)]*\)/m.test(signature)) {
    throw new Error("The macOS biometric helper is not signed with hardened runtime enabled.");
  }
  const entitlements = runValidationTool("/usr/bin/codesign", ["-d", "--entitlements", "-", bundle]);
  if (entitlements.stdout.trim().length !== 0) {
    throw new Error("The macOS biometric helper has unexpected entitlements.");
  }
  const plistIdentifier = runValidationTool("/usr/bin/plutil", [
    "-extract", "CFBundleIdentifier", "raw", infoPlist,
  ]).stdout.trim();
  if (plistIdentifier !== MACOS_HELPER_IDENTIFIER) {
    throw new Error("The macOS biometric helper bundle identifier is invalid.");
  }
  const architectures = runValidationTool("/usr/bin/lipo", ["-archs", resolvedHelper]).stdout.trim();
  if (architectures !== manifest.architecture) {
    throw new Error("The macOS biometric helper architecture is invalid.");
  }

  const finalHash = crypto.createHash("sha256").update(fs.readFileSync(resolvedHelper)).digest("hex");
  if (finalHash !== descriptors.get("native/Keyclasp.app/Contents/MacOS/keyclasp-biometric")?.sha256) {
    throw new Error("The macOS biometric helper changed during validation.");
  }
}

export function preflightBiometricAuthentication(
  options: BiometricAuthenticationOptions = {},
): void {
  const platform = options.platform ?? process.platform;
  if (platform !== "darwin") return;
  const helperPath = options.helperPath ?? MACOS_HELPER_PATH;
  const manifestPath = options.manifestPath ?? MACOS_HELPER_MANIFEST_PATH;
  const validateHelper = options.validateHelper ?? validateMacOSBiometricHelper;
  validateHelper(helperPath, manifestPath);
}

export function evaluateBiometricAuthentication(
  reason: string,
  options: BiometricAuthenticationOptions = {},
): BiometricEvaluation {
  const platform = options.platform ?? process.platform;
  if (platform !== "darwin") {
    return { kind: "unavailable", message: "Touch ID is unavailable on this platform." };
  }

  try {
    preflightBiometricAuthentication(options);
  } catch {
    return { kind: "unavailable", message: "The macOS biometric authentication helper failed validation." };
  }
  const runner = options.runner ?? runMacOSHelper;
  const helperPath = options.helperPath ?? MACOS_HELPER_PATH;
  const result = runner(helperPath, [], reason, minimalMacOSHelperEnvironment());

  if (result.error) {
    if ((result.error as NodeJS.ErrnoException).code === "ETIMEDOUT") {
      return { kind: "timeout", message: "Biometric authentication timed out." };
    }
    return { kind: "unavailable", message: "The macOS biometric authentication helper could not start." };
  }
  if (result.status === 0) {
    return { kind: "ok" };
  }

  if (result.status === 2) {
    return { kind: "cancelled", message: "Biometric authentication was cancelled by the operator." };
  }
  if (result.status === 3) {
    return { kind: "unavailable", message: "Touch ID is unavailable or not enrolled." };
  }
  if (result.status === 5) {
    return { kind: "timeout", message: "Biometric authentication timed out." };
  }
  if (result.status === 64) {
    return { kind: "invalid", message: "The macOS biometric authentication helper rejected its input." };
  }
  return { kind: "denied", message: "Biometric authentication failed." };
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
    if (biometric.kind === "unavailable" && biometric.message.includes("helper")) {
      throw new Error(biometric.message);
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
