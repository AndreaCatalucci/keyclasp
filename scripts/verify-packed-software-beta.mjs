#!/usr/bin/env node

import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { createRequire } from "node:module";

function fail(message) {
  throw new Error(message);
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", ...options });
  if (result.error) fail(`${command} could not start: ${result.error.message}`);
  return result;
}

function requireSuccess(result, label) {
  if (result.status !== 0) fail(`${label} failed (${String(result.status)}): ${result.stderr}`);
}

function collectInstalledLocations(packageRoot, nodeModules = path.join(packageRoot, "node_modules"), prefix = "node_modules", output = []) {
  if (!fs.existsSync(nodeModules)) return output;
  for (const entry of fs.readdirSync(nodeModules, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.name === ".bin") continue;
    if (entry.name.startsWith("@")) {
      for (const scoped of fs.readdirSync(path.join(nodeModules, entry.name), { withFileTypes: true })) {
        if (scoped.isDirectory()) collectPackage(`${entry.name}/${scoped.name}`);
      }
    } else {
      collectPackage(entry.name);
    }
  }
  function collectPackage(name) {
    const directory = path.join(nodeModules, name);
    const manifest = JSON.parse(fs.readFileSync(path.join(directory, "package.json"), "utf8"));
    const location = `${prefix}/${name}`;
    output.push(`${location}:${manifest.name}@${manifest.version}`);
    collectInstalledLocations(packageRoot, path.join(directory, "node_modules"), `${location}/node_modules`, output);
  }
  return output;
}

const artifactArgument = process.argv[2];
if (!artifactArgument) fail("Usage: node scripts/verify-packed-software-beta.mjs <exact-tarball>");
if (process.platform !== "darwin" && process.platform !== "linux") {
  fail("Exact software-beta qualification runs only on supported macOS or Linux hosts.");
}
if (process.env.EXPECTED_PLATFORM && process.platform !== process.env.EXPECTED_PLATFORM) {
  fail(`Exact-artifact runner platform mismatch: expected ${process.env.EXPECTED_PLATFORM}, received ${process.platform}.`);
}
if (process.env.EXPECTED_ARCH && process.arch !== process.env.EXPECTED_ARCH) {
  fail(`Exact-artifact runner architecture mismatch: expected ${process.env.EXPECTED_ARCH}, received ${process.arch}.`);
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp beta 雪-"));
const artifactBytes = fs.readFileSync(path.resolve(artifactArgument));
const artifact = path.join(root, path.basename(artifactArgument));
fs.writeFileSync(artifact, artifactBytes, { mode: 0o600, flag: "wx" });
const sha256 = crypto.createHash("sha256").update(fs.readFileSync(artifact)).digest("hex");
const expectedSha256 = process.env.EXPECTED_SHA256;
if (!expectedSha256 || !/^[a-f0-9]{64}$/.test(expectedSha256)) {
  fail("EXPECTED_SHA256 must name the reviewed candidate before exact-artifact qualification.");
}
if (sha256 !== expectedSha256) {
  fail(`Artifact SHA-256 mismatch: expected ${expectedSha256}, received ${sha256}.`);
}
const archiveListing = run("tar", ["-tzf", artifact]);
requireSuccess(archiveListing, "artifact content listing");
const archiveEntries = archiveListing.stdout.split("\n");
if (archiveEntries.some((entry) => entry.startsWith("package/node_modules/better-sqlite3/build/"))) {
  fail("The artifact contains host build output under bundled better-sqlite3/build.");
}
const nativeEntries = archiveEntries.filter((entry) => entry.endsWith(".node")).sort();
const expectedNativeEntries = ["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64", "linuxmusl-arm64", "linuxmusl-x64", "win32-arm64", "win32-x64"]
  .map((target) => `package/node_modules/better-sqlite3/prebuilds/${target}.node`).sort();
if (JSON.stringify(nativeEntries) !== JSON.stringify(expectedNativeEntries)) {
  fail(`The artifact native contents differ from the reviewed bundled prebuild set: ${JSON.stringify(nativeEntries)}.`);
}

const install = path.join(root, "installed package");
const vaultHome = path.join(root, "vault λ with spaces");
const npmCache = path.join(root, "npm-cache");
fs.mkdirSync(install, { mode: 0o700 });
const nativeInstallMode = process.env.KEYCLASP_NATIVE_INSTALL_MODE ?? "prebuilt";
if (nativeInstallMode !== "prebuilt" && nativeInstallMode !== "source") fail("KEYCLASP_NATIVE_INSTALL_MODE must be prebuilt or source.");
const installEnv = {
  ...process.env,
  npm_config_cache: npmCache,
  npm_config_build_from_source: nativeInstallMode === "source" ? "true" : "false",
  npm_config_foreground_scripts: "true",
  npm_config_loglevel: "info",
};

try {
  const installed = run("npm", ["install", "--no-audit", "--no-fund", "--prefix", install, artifact], { env: installEnv });
  requireSuccess(installed, "exact-tarball install");
  const installOutput = `${installed.stdout}\n${installed.stderr}`;
  if (nativeInstallMode === "prebuilt" && !/Keyclasp verified the bundled better-sqlite3 prebuilt SHA-256/i.test(installOutput)) {
    fail("The installed better-sqlite3 prebuilt was not bound to its reviewed native SHA-256.");
  }
  if (nativeInstallMode === "source" &&
      (!/(gyp info|build\/Release\/better_sqlite3|SOLINK_MODULE)/i.test(installOutput) ||
       !/explicit better-sqlite3 source build from the bundled reviewed sources/i.test(installOutput))) {
    fail("The requested better-sqlite3 source-build path was not observed during installation.");
  }

  const packageRoot = path.join(install, "node_modules", "keyclasp");
  const packageJson = JSON.parse(fs.readFileSync(path.join(packageRoot, "package.json"), "utf8"));
  if (packageJson.version !== "0.2.0-beta.1") fail(`Installed version is ${String(packageJson.version)}.`);
  if (JSON.stringify(packageJson.os) !== JSON.stringify(["darwin", "linux"])) fail("Installed OS allowlist is not frozen.");
  if (JSON.stringify(packageJson.cpu) !== JSON.stringify(["arm64", "x64"])) fail("Installed CPU allowlist is not frozen.");
  if (packageJson.engines?.node !== "24.x || 26.x") fail("Installed Node matrix is not frozen.");
  if (JSON.stringify(packageJson.bundleDependencies) !== JSON.stringify(["better-sqlite3"])) {
    fail("Installed package does not bundle exactly the reviewed better-sqlite3 production tree.");
  }
  const dependencyManifest = JSON.parse(fs.readFileSync(path.join(packageRoot, "software-beta-dependencies.json"), "utf8"));
  const biometricManifest = JSON.parse(fs.readFileSync(path.join(packageRoot, "software-beta-macos-biometric.json"), "utf8"));
  if (biometricManifest.bundle !== "Keyclasp.app" ||
      biometricManifest.bundleIdentifier !== "dev.keyclasp.biometric" ||
      biometricManifest.architecture !== "arm64" ||
      biometricManifest.signature !== "ad-hoc") {
    fail("The installed Touch ID helper manifest does not match the reviewed Keyclasp identity.");
  }
  for (const descriptor of biometricManifest.bundleFiles) {
    const installedPath = path.join(packageRoot, descriptor.path);
    if (!fs.statSync(installedPath).isFile() ||
        crypto.createHash("sha256").update(fs.readFileSync(installedPath)).digest("hex") !== descriptor.sha256) {
      fail(`The installed Touch ID helper file differs from its reviewed SHA-256: ${descriptor.path}`);
    }
  }
  if (fs.existsSync(path.join(packageRoot, "native", "macos-biometric.js"))) {
    fail("The obsolete osascript biometric helper is present in the installed package.");
  }
  if (process.platform === "darwin") {
    const helperBundle = path.join(packageRoot, "native", "Keyclasp.app");
    requireSuccess(run("/usr/bin/codesign", ["--verify", "--strict", helperBundle]), "installed Touch ID helper signature");
    const helperExecutable = path.join(helperBundle, "Contents", "MacOS", "keyclasp-biometric");
    try {
      fs.accessSync(helperExecutable, fs.constants.X_OK);
    } catch {
      fail("The installed Touch ID helper is not executable.");
    }
    const architectures = run("/usr/bin/lipo", ["-archs", helperExecutable]);
    requireSuccess(architectures, "installed Touch ID helper architecture");
    if (architectures.stdout.trim() !== "arm64") fail("The installed Touch ID helper is not arm64-only.");
    const displayName = run("/usr/bin/plutil", ["-extract", "CFBundleDisplayName", "raw", path.join(helperBundle, "Contents", "Info.plist")]);
    requireSuccess(displayName, "installed Touch ID helper display name");
    if (displayName.stdout.trim() !== "Keyclasp") fail("The installed Touch ID helper display name is not Keyclasp.");
    const signatureDetails = run("/usr/bin/codesign", ["-dvvv", helperBundle]);
    requireSuccess(signatureDetails, "installed Touch ID helper signing identity");
    if (!signatureDetails.stderr.includes("Identifier=dev.keyclasp.biometric") ||
        !signatureDetails.stderr.includes("Signature=adhoc")) {
      fail("The installed Touch ID helper is not the reviewed ad-hoc Keyclasp identity.");
    }
  }
  const expectedProductionVersions = dependencyManifest.dependencies
    .map((descriptor) => `${descriptor.location}:${descriptor.name}@${descriptor.version}`)
    .sort();
  for (const forbidden of ["tests", "docs", "native/keyclasp-core", ".github"]) {
    if (fs.existsSync(path.join(packageRoot, forbidden))) fail(`Forbidden package path is present: ${forbidden}`);
  }

  const cli = path.join(packageRoot, "dist", "cli.js");
  const environment = { ...process.env, KEYCLASP_HOME: vaultHome };
  const version = run(process.execPath, [cli, "version"], { env: environment, cwd: root });
  requireSuccess(version, "installed version");
  if (version.stdout.trim() !== "0.2.0-beta.1") fail(`Unexpected installed version output: ${version.stdout.trim()}`);

  const initialized = run(process.execPath, [cli, "init"], { env: environment, input: "\n" });
  requireSuccess(initialized, "fresh machine-only initialization");
  const stored = run(process.execPath, [cli, "set", "AGENT_TOKEN", "--project", "agent.project", "--environment", "beta"], {
    env: environment,
    input: "agent-workflow-secret\n",
  });
  requireSuccess(stored, "fresh secret storage");

  const metacharacters = "literal ; $() ' 🌨";
  const named = run(process.execPath, [
    cli, "run", "--project", "agent.project", "--environment", "beta", "--env", "AGENT_TOKEN:EXPECTED_TOKEN", "--",
    process.execPath, "-e",
    "process.exit(process.env.EXPECTED_TOKEN === 'agent-workflow-secret' && process.argv[1] === " + JSON.stringify(metacharacters) + " ? 0 : 9)",
    metacharacters,
  ], { env: environment });
  requireSuccess(named, "representative named agent run with literal shell metacharacters");

  const status = run(process.execPath, [cli, "status", "--project", "agent.project", "--environment", "beta"], { env: environment });
  requireSuccess(status, "installed status");
  if (!status.stdout.includes("software-machine")) fail("Fresh installed status did not report software-machine.");

  if (process.platform === "linux") {
    const blockedChildSentinel = path.join(root, "blocked-child-launched");
    const expectedAuthorizationFailure = /non-empty vault passphrase; machine-only vaults fail closed/i;
    for (const [label, args] of [
      ["broad run", ["run", "--project", "agent.project", "--environment", "beta", "--", process.execPath, "-e", "require('node:fs').writeFileSync(process.argv[1], 'launched')", blockedChildSentinel]],
      ["get", ["get", "AGENT_TOKEN", "--project", "agent.project", "--environment", "beta"]],
      ["lock", ["lock", "--project", "agent.project", "--environment", "beta", "AGENT_TOKEN"]],
    ]) {
      const blocked = run(process.execPath, [cli, ...args], { env: { ...environment, CI: "1" } });
      if (blocked.status === 0 || !expectedAuthorizationFailure.test(blocked.stderr)) {
        fail(`${label} did not return the Linux machine-only authorization failure: ${blocked.stderr}`);
      }
      if (`${blocked.stdout}\n${blocked.stderr}`.includes("agent-workflow-secret")) fail(`Blocked ${label} printed the secret.`);
    }
    if (fs.existsSync(blockedChildSentinel)) fail("The blocked broad run launched its child.");
    const unchangedPolicy = run(process.execPath, [cli, "status", "--project", "agent.project", "--environment", "beta"], { env: environment });
    requireSuccess(unchangedPolicy, "policy status after blocked lock");
    if (!unchangedPolicy.stdout.includes("Authorization: unlocked")) fail("The blocked lock changed authorization state.");
  }

  const removed = run("npm", ["uninstall", "--prefix", install, "keyclasp"], { env: installEnv });
  requireSuccess(removed, "package uninstall");
  const reinstalled = run("npm", ["install", "--no-audit", "--no-fund", "--prefix", install, artifact], { env: installEnv });
  requireSuccess(reinstalled, "exact-tarball reinstall");
  const reinstalledCli = path.join(install, "node_modules", "keyclasp", "dist", "cli.js");
  const afterReinstall = run(process.execPath, [
    reinstalledCli, "run", "--project", "agent.project", "--environment", "beta", "--env", "AGENT_TOKEN", "--",
    process.execPath, "-e", "process.exit(process.env.AGENT_TOKEN === 'agent-workflow-secret' ? 0 : 9)",
  ], { env: environment });
  requireSuccess(afterReinstall, "vault continuity after uninstall and reinstall");

  const signalled = run(process.execPath, [
    reinstalledCli, "run", "--project", "agent.project", "--environment", "beta", "--env", "AGENT_TOKEN", "--",
    process.execPath, "-e", "process.kill(process.pid, 'SIGTERM')",
  ], { env: environment });
  if (signalled.status !== 143) fail(`Guarded child SIGTERM returned ${String(signalled.status)} instead of 143.`);

  async function verifyWrapperSignalRelay(label, extraRunArgs = []) {
    const readyPath = path.join(root, `${label}-ready`);
    const terminatedPath = path.join(root, `${label}-terminated`);
    const workerSource = [
      "const fs = require('node:fs');",
      "process.on('SIGTERM', () => fs.writeFileSync(process.argv[2], 'relayed'));",
      "fs.writeFileSync(process.argv[1], String(process.pid));",
      "setInterval(() => {}, 1000);",
    ].join(" ");
    const childSource = [
      "const { spawn } = require('node:child_process');",
      `spawn(process.execPath, ['-e', ${JSON.stringify(workerSource)}, process.argv[1], process.argv[2]], { stdio: 'ignore' });`,
      "setInterval(() => {}, 1000);",
    ].join(" ");
    let stdout = "";
    let stderr = "";
    const wrapper = spawn(process.execPath, [
      reinstalledCli, "run", ...extraRunArgs,
      "--project", "agent.project", "--environment", "beta", "--env", "AGENT_TOKEN", "--",
      process.execPath, "-e", childSource, readyPath, terminatedPath,
    ], { env: environment, stdio: ["ignore", "pipe", "pipe"] });
    const wrapperResult = new Promise((resolve) => {
      wrapper.on("close", (status, signal) => resolve({ status, signal }));
      wrapper.on("error", (error) => resolve({ status: null, signal: null, error }));
    });
    wrapper.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    wrapper.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
    const deadline = Date.now() + 5_000;
    while (!fs.existsSync(readyPath) && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    if (!fs.existsSync(readyPath)) {
      wrapper.kill("SIGKILL");
      fail(`${label} child did not become ready: ${stderr}`);
    }
    wrapper.kill("SIGTERM");
    const result = await wrapperResult;
    if (result.status !== 143 || result.signal !== null || !fs.existsSync(terminatedPath)) {
      fail(`${label} did not relay SIGTERM and await its child process group: ${JSON.stringify({ result, stdout, stderr })}`);
    }
    const childPid = Number(fs.readFileSync(readyPath, "utf8"));
    try {
      process.kill(childPid, 0);
      fail(`${label} left child ${childPid} running after wrapper exit.`);
    } catch (error) {
      if (error?.code !== "ESRCH") throw error;
    }
  }
  await verifyWrapperSignalRelay("guarded-wrapper-signal");
  await verifyWrapperSignalRelay("raw-wrapper-signal", ["--allow-unsafe"]);

  const packageRequire = createRequire(path.join(install, "node_modules", "keyclasp", "package.json"));
  const installedSqliteManifest = packageRequire("better-sqlite3/package.json");
  if (installedSqliteManifest.version !== "13.0.3") fail(`Installed better-sqlite3 version is ${installedSqliteManifest.version}.`);
  const actualProductionVersions = collectInstalledLocations(packageRoot).sort();
  if (JSON.stringify(actualProductionVersions) !== JSON.stringify(expectedProductionVersions)) {
    fail(`Installed production tree differs from software-beta-dependencies.json. Expected ${JSON.stringify(expectedProductionVersions)}, received ${JSON.stringify(actualProductionVersions)}.`);
  }
  const Database = packageRequire("better-sqlite3");
  const nativeProbe = new Database(":memory:");
  nativeProbe.prepare("SELECT 1 AS value").get();
  nativeProbe.close();

  const dist = path.join(install, "node_modules", "keyclasp", "dist");
  const vault = await import(pathToFileURL(path.join(dist, "vault.js")));
  const policy = await import(pathToFileURL(path.join(dist, "policy.js")));
  const recovery = await import(pathToFileURL(path.join(dist, "recovery.js")));

  const legacyHome = path.join(root, "legacy one-key vault");
  process.env.KEYCLASP_HOME = legacyHome;
  vault.closeDb();
  vault.clearKey();
  vault.initializeVault("");
  const legacyKey = vault.getKey();
  vault.writeLegacyV3KeyFileForTests(legacyKey, "");
  vault.closeDb();
  const legacyDb = new Database(path.join(legacyHome, "vault.db"));
  legacyDb.exec("DROP TABLE secrets; DROP TABLE vault_metadata; CREATE TABLE secrets (project TEXT NOT NULL, environment TEXT NOT NULL, name TEXT NOT NULL, encrypted_value BLOB NOT NULL, iv BLOB NOT NULL, auth_tag BLOB NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now')), PRIMARY KEY (project, environment, name))");
  const encrypted = vault.encrypt("migrated-value", legacyKey);
  legacyDb.prepare("INSERT INTO secrets (project, environment, name, encrypted_value, iv, auth_tag) VALUES (?, ?, ?, ?, ?, ?)")
    .run("migration", "beta", "LEGACY_TOKEN", encrypted.encrypted, encrypted.iv, encrypted.authTag);
  legacyDb.close();
  vault.clearKey();
  const migrated = run(process.execPath, [
    reinstalledCli, "run", "--project", "migration", "--environment", "beta", "--env", "LEGACY_TOKEN", "--",
    process.execPath, "-e", "process.exit(process.env.LEGACY_TOKEN === 'migrated-value' ? 0 : 9)",
  ], { env: { ...process.env, KEYCLASP_HOME: legacyHome } });
  requireSuccess(migrated, "one-key migration through installed CLI");

  const recoveryHome = path.join(root, "mixed recovery vault");
  const backup = path.join(root, "mixed backup");
  process.env.KEYCLASP_HOME = recoveryHome;
  vault.closeDb();
  vault.clearKey();
  vault.initializeVault("portable-passphrase");
  vault.storeSecret("recovery", "beta", "MACHINE_TOKEN", "machine-value");
  vault.storeSecret("recovery", "beta", "INTERACTIVE_TOKEN", "interactive-value");
  policy.mutateAuthorizationRule({ project: "recovery", environment: "beta", secret: "INTERACTIVE_TOKEN" }, "lock", (db, rules) => {
    vault.transitionRecordCustody(db, rules, policy.evaluateAuthorizationRules);
  });
  recovery.createManagedBackup(backup);
  fs.renameSync(recoveryHome, `${recoveryHome}.before-restore`);
  const restored = recovery.restoreManagedBackup(backup, "portable-passphrase");
  if (restored.manifest.custody !== "dual-key") fail("Mixed managed restore did not preserve dual-key custody.");
  vault.unlockVault("portable-passphrase");
  if (vault.resolveSecret("recovery", "beta", "MACHINE_TOKEN") !== "machine-value" ||
      vault.resolveSecret("recovery", "beta", "INTERACTIVE_TOKEN") !== "interactive-value") {
    fail("Mixed managed restore changed a recovered value.");
  }

  policy.mutateAuthorizationRule({ project: "recovery", environment: "beta", secret: "INTERACTIVE_TOKEN" }, "unlock", (db, rules) => {
    vault.transitionRecordCustody(db, rules, policy.evaluateAuthorizationRules);
  });
  if (vault.readSecretKeyClass("recovery", "beta", "INTERACTIVE_TOKEN") !== "machine") fail("Unlock did not move the record to machine custody.");
  policy.mutateAuthorizationRule({ project: "recovery", environment: "beta", secret: "INTERACTIVE_TOKEN" }, "lock", (db, rules) => {
    vault.transitionRecordCustody(db, rules, policy.evaluateAuthorizationRules);
  });
  policy.mutateAuthorizationRule({ project: "recovery", environment: "beta", secret: "INTERACTIVE_TOKEN" }, "inherit", (db, rules) => {
    vault.transitionRecordCustody(db, rules, policy.evaluateAuthorizationRules);
  });
  if (vault.readSecretKeyClass("recovery", "beta", "INTERACTIVE_TOKEN") !== "machine") fail("Inherit did not restore default machine custody.");

  const interruptedHome = path.join(root, "interrupted custody vault");
  process.env.KEYCLASP_HOME = interruptedHome;
  vault.closeDb();
  vault.clearKey();
  vault.initializeVault("");
  vault.setCustodyFaultForTests("after-bundle");
  let interrupted = false;
  try {
    vault.enrollInteractivePassphrase("interruption-passphrase");
  } catch {
    interrupted = true;
  } finally {
    vault.setCustodyFaultForTests(null);
  }
  if (!interrupted || !vault.recoverInterruptedCustodyTransition()) fail("Interrupted custody write did not recover from the exact installed code.");
  if (vault.getVaultDescriptor().custody !== "machine-only") fail("Interrupted pre-commit enrollment changed custody.");

  const portableHome = path.join(root, "portable source vault");
  const portableBackup = path.join(root, "portable all-interactive backup");
  process.env.KEYCLASP_HOME = portableHome;
  vault.closeDb();
  vault.clearKey();
  vault.setMachineIdentityForTests({ stable: Buffer.alloc(32, 31) });
  vault.initializeVault("portable-only-passphrase");
  vault.storeSecret("portable", "beta", "ONLY_INTERACTIVE", "portable-value");
  policy.mutateAuthorizationRule({ project: "portable", environment: "beta", secret: "ONLY_INTERACTIVE" }, "lock", (db, rules) => {
    vault.transitionRecordCustody(db, rules, policy.evaluateAuthorizationRules);
  });
  recovery.createManagedBackup(portableBackup);
  vault.closeDb();
  vault.clearKey();
  fs.renameSync(portableHome, `${portableHome}.source`);
  vault.setMachineIdentityForTests({ stable: Buffer.alloc(32, 47) });
  recovery.restoreManagedBackup(portableBackup, "portable-only-passphrase");
  vault.unlockVault("portable-only-passphrase");
  if (vault.readSecretKeyClass("portable", "beta", "ONLY_INTERACTIVE") !== "interactive" ||
      vault.resolveSecret("portable", "beta", "ONLY_INTERACTIVE") !== "portable-value") {
    fail("All-interactive portable restore changed custody or plaintext.");
  }
  vault.setMachineIdentityForTests(null);

  vault.closeDb();
  vault.clearKey();
  console.log(JSON.stringify({
    result: "PASS",
    platform: process.platform,
    arch: process.arch,
    node: process.version,
    nativeInstallMode,
    sha256,
    version: packageJson.version,
    checks: ["install", "fresh-init", "named-run", process.platform === "linux" ? "machine-only-authorization-fail-closed" : "physical-authorization-covered-separately", "uninstall-reinstall", "unusual-paths", "metacharacters", "signals", "native-addon", "one-key-migration", "lock-unlock-inherit", "mixed-backup-restore", "portable-restore", "interrupted-write-recovery"],
  }));
} finally {
  delete process.env.KEYCLASP_HOME;
  fs.rmSync(root, { recursive: true, force: true });
}
