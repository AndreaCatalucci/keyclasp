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

function shellQuote(value) {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

function processIsRunning(pid) {
  try {
    process.kill(pid, 0);
  } catch (error) {
    if (error?.code === "ESRCH") return false;
    throw error;
  }
  if (process.platform !== "linux") return true;
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
    const commandEnd = stat.lastIndexOf(")");
    if (commandEnd === -1) return true;
    const state = stat.slice(commandEnd + 1).trim().split(/\s+/, 1)[0];
    return state !== "Z" && state !== "X";
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    return true;
  }
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
  const biometricManifest = JSON.parse(fs.readFileSync(path.join(packageRoot, "keyclasp-macos-helper-candidate.json"), "utf8"));
  if (biometricManifest.bundle !== "Keyclasp.app" ||
      biometricManifest.bundleIdentifier !== "dev.keyclasp.biometric" ||
      biometricManifest.architecture !== "arm64" ||
      biometricManifest.signature?.kind !== "ad-hoc" ||
      biometricManifest.signature?.hardenedRuntime !== true ||
      biometricManifest.signature?.entitlements?.length !== 0 ||
      biometricManifest.sourceRevision !== "31aac732317e40597eeee02695b019a2045228ad") {
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

  const initialized = run(process.execPath, [cli, "init", "--machine-only"], { env: environment });
  requireSuccess(initialized, "explicit machine-only initialization");
  const stored = run(process.execPath, [cli, "set", "AGENT_TOKEN", "--project", "agent.project", "--environment", "beta"], {
    env: environment,
    input: "agent-workflow-secret\n",
  });
  requireSuccess(stored, "fresh secret storage");
  const overlapStored = run(process.execPath, [cli, "set", "OVERLAP_TOKEN", "--project", "agent.project", "--environment", "beta"], {
    env: environment,
    input: "abcd123a\n",
  });
  requireSuccess(overlapStored, "self-overlapping output canary storage");
  for (const stream of ["stdout", "stderr"]) {
    const leak = run(process.execPath, [
      cli, "run", "--project", "agent.project", "--environment", "beta", "--env", "OVERLAP_TOKEN", "--",
      process.execPath, "-e", `process.${stream}.write(process.env.OVERLAP_TOKEN)`,
    ], { env: environment });
    const transcript = `${leak.stdout}\n${leak.stderr}`;
    if (leak.status !== 2 || transcript.includes("abcd123a") || !transcript.includes("[KEYCLASP_REDACTED]")) {
      fail(`The ${stream} self-overlap canary was not contained with exit code 2.`);
    }
  }

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

  const deferredFailures = [];
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
      deferredFailures.push(`${label} child did not become ready: ${stderr}`);
      return;
    }
    wrapper.kill("SIGTERM");
    const result = await Promise.race([
      wrapperResult,
      new Promise((resolve) => setTimeout(() => resolve({ status: null, signal: null, timeout: true }), 10_000)),
    ]);
    if (result.timeout) {
      wrapper.kill("SIGKILL");
      deferredFailures.push(`${label} did not finish child-process-group supervision within 10 seconds: ${JSON.stringify({ stdout, stderr })}`);
      return;
    }
    if (result.status !== 143 || result.signal !== null || !fs.existsSync(terminatedPath)) {
      deferredFailures.push(`${label} did not relay SIGTERM and await its child process group: ${JSON.stringify({ result, stdout, stderr })}`);
      return;
    }
    const childPid = Number(fs.readFileSync(readyPath, "utf8"));
    if (processIsRunning(childPid)) {
      deferredFailures.push(`${label} left child ${childPid} running after wrapper exit.`);
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

  const custodyHome = path.join(root, "custody remanence vault");
  process.env.KEYCLASP_HOME = custodyHome;
  vault.closeDb();
  vault.clearKey();
  vault.setMachineIdentityForTests({ stable: Buffer.alloc(32, 41) });
  vault.initializeVault("custody-passphrase");
  for (let index = 0; index < 500; index += 1) {
    vault.storeSecret("custody", "prod", `API_KEY_${index}`, `synthetic-value-${index}-${"a".repeat(60)}`, "machine");
  }
  if (vault.getDb().pragma("secure_delete", { simple: true }) !== 1) fail("F1 secure_delete is not enabled.");
  policy.mutateAuthorizationRule({ project: "custody", environment: "prod" }, "lock", (db, rules) => {
    vault.transitionRecordCustody(db, rules, policy.evaluateAuthorizationRules);
  });
  vault.closeDb();
  vault.clearKey();
  const custodyProbe = spawnSync(process.execPath, ["--input-type=module", "-e", `
    import fs from "node:fs";
    import crypto from "node:crypto";
    import * as vault from ${JSON.stringify(pathToFileURL(path.join(dist, "vault.js")).href)};
    vault.setMachineIdentityForTests({ stable: Buffer.alloc(32, 41) });
    const raw = Buffer.concat(["vault.db", "vault.db-wal", "vault.db-shm"].filter((name) => fs.existsSync(process.env.KEYCLASP_HOME + "/" + name)).map((name) => fs.readFileSync(process.env.KEYCLASP_HOME + "/" + name)));
    const key = vault.getKey();
    const vaultId = vault.getVaultDescriptor().vaultId;
    const current = vault.getDb().prepare("SELECT * FROM secrets").all();
    let recovered = 0;
    for (const row of current) {
      const marker = Buffer.concat([row.record_id, Buffer.from("secretmachine")]);
      let offset = raw.indexOf(marker);
      while (offset >= 0) {
        const start = offset + marker.length;
        const length = row.encrypted_value.length;
        try {
          const decipher = crypto.createDecipheriv("aes-256-gcm", key, raw.subarray(start + length, start + length + 12), { authTagLength: 16 });
          decipher.setAAD(vault.buildRecordAssociatedData({ vaultId, recordId: row.record_id, project: row.project, environment: row.environment, name: row.name, keyClass: "machine" }));
          decipher.setAuthTag(raw.subarray(start + length + 12, start + length + 28));
          const plaintext = Buffer.concat([decipher.update(raw.subarray(start, start + length)), decipher.final()]).toString();
          if (plaintext === "synthetic-value-" + row.name.slice(8) + "-" + "a".repeat(60)) recovered += 1;
          break;
        } catch {}
        offset = raw.indexOf(marker, offset + 1);
      }
    }
    const classes = vault.summarizeKeyClasses();
    process.stdout.write(JSON.stringify({ recovered, classes }));
    vault.closeDb();
    vault.clearKey();
  `], { env: { PATH: process.env.PATH, KEYCLASP_HOME: custodyHome }, encoding: "utf8", timeout: 60_000 });
  requireSuccess(custodyProbe, "F1 fresh-process custody-remanence probe");
  const custodyResult = JSON.parse(custodyProbe.stdout);
  if (custodyResult.recovered !== 0 || custodyResult.classes.machine !== 0 || custodyResult.classes.interactive !== 500) {
    fail(`F1 custody-remanence regression failed: ${custodyProbe.stdout}`);
  }
  vault.closeDb();
  vault.clearKey();
  vault.setMachineIdentityForTests(null);

  const walHome = path.join(root, "WAL restore vault");
  const walBackup = path.join(root, "WAL restore backup");
  process.env.KEYCLASP_HOME = walHome;
  vault.setMachineIdentityForTests({ stable: Buffer.alloc(32, 3) });
  vault.initializeVault("");
  vault.storeSecret("restore", "prod", "TOKEN", "backup-value");
  recovery.createManagedBackup(walBackup);
  vault.closeDb();
  vault.clearKey();
  const abruptWriter = spawnSync(process.execPath, ["--input-type=module", "-e", [
    `import * as vault from ${JSON.stringify(pathToFileURL(path.join(dist, "vault.js")).href)};`,
    "vault.setMachineIdentityForTests({ stable: Buffer.alloc(32, 3) });",
    "vault.storeSecret('restore', 'prod', 'TOKEN', 'live-value');",
    "process.exit(23);",
  ].join("\n")], { env: { ...process.env, KEYCLASP_HOME: walHome }, encoding: "utf8", timeout: 30_000 });
  if (abruptWriter.status !== 23 || !fs.existsSync(path.join(walHome, "vault.db-wal"))) fail("F3 could not create the abrupt-writer WAL fixture.");
  recovery.restoreManagedBackup(walBackup);
  if (vault.resolveSecret("restore", "prod", "TOKEN") !== "backup-value") fail("F3 restore replayed stale live WAL state.");
  vault.closeDb();
  vault.clearKey();

  const restartHome = path.join(root, "restartable rollback vault");
  const restartBackup = path.join(root, "restartable rollback backup");
  process.env.KEYCLASP_HOME = restartHome;
  vault.initializeVault("");
  vault.storeSecret("restore", "prod", "TOKEN", "backup-value");
  recovery.createManagedBackup(restartBackup);
  vault.storeSecret("restore", "prod", "TOKEN", "live-value");
  recovery.setRestoreFaultForTests("crash-after-all-published");
  let restoreInterrupted = false;
  try {
    recovery.restoreManagedBackup(restartBackup);
  } catch (error) {
    restoreInterrupted = /complete staged publication/.test(String(error?.message));
  } finally {
    recovery.setRestoreFaultForTests(null);
  }
  if (!restoreInterrupted || !recovery.recoverInterruptedManagedRestore() || vault.resolveSecret("restore", "prod", "TOKEN") !== "live-value") {
    fail("F4 interrupted rollback did not converge to the authenticated live state.");
  }
  vault.closeDb();
  vault.clearKey();

  const machineBackupHome = path.join(root, "machine-only authorized backup vault");
  process.env.KEYCLASP_HOME = machineBackupHome;
  vault.initializeVault("");
  vault.storeSecret("backup", "prod", "TOKEN", "machine-value");
  let interactiveUnlockRequested = false;
  await recovery.createManagedBackupAuthorized(path.join(root, "machine-only authorized backup"), {
    authorize: async () => undefined,
    ensureUnlocked: async () => {
      interactiveUnlockRequested = true;
      throw new Error("Interactive custody should not be requested for a machine-only backup.");
    },
  });
  if (interactiveUnlockRequested) fail("F6 machine-only backup requested an interactive unlock.");
  vault.closeDb();
  vault.clearKey();
  vault.setMachineIdentityForTests(null);

  if (process.platform === "linux") {
    const emergencyHome = path.join(root, "emergency restore vault");
    const emergencyBackup = path.join(root, "emergency restore backup");
    process.env.KEYCLASP_HOME = emergencyHome;
    vault.initializeVault("emergency-passphrase");
    vault.unlockVault("emergency-passphrase");
    vault.storeSecret("emergency", "prod", "TOKEN", "restored-value", "interactive");
    recovery.createManagedBackup(emergencyBackup);
    vault.closeDb();
    vault.clearKey();
    fs.writeFileSync(path.join(emergencyHome, ".keyclasp.key"), "corrupt", { mode: 0o600 });
    const emergencyCommand = [process.execPath, cli, "backup", "restore", emergencyBackup].map(shellQuote).join(" ");
    const emergencyRestore = spawnSync("/usr/bin/script", [
      "--quiet", "--return", "--flush", "--echo", "never", "--command", emergencyCommand, "/dev/null",
    ], {
      cwd: root,
      encoding: "utf8",
      env: { ...process.env, KEYCLASP_HOME: emergencyHome },
      input: "emergency-passphrase\n",
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 30_000,
    });
    requireSuccess(emergencyRestore, "F5 CLI emergency restore with a corrupt live key");
    if (!/backup restored/i.test(emergencyRestore.stdout)) fail("F5 CLI emergency restore did not report success.");
    vault.unlockVault("emergency-passphrase");
    if (vault.resolveSecret("emergency", "prod", "TOKEN") !== "restored-value") fail("F5 CLI emergency restore changed the restored value.");
    vault.closeDb();
    vault.clearKey();
  }

  const legacyHome = path.join(root, "legacy one-key vault");
  process.env.KEYCLASP_HOME = legacyHome;
  vault.closeDb();
  vault.clearKey();
  vault.initializeVault("");
  const legacyKey = Buffer.from(vault.getKey());
  vault.writeLegacyV3KeyFileForTests(legacyKey, "");
  vault.closeDb();
  const legacyDb = new Database(path.join(legacyHome, "vault.db"));
  legacyDb.exec("DROP TABLE secrets; DROP TABLE vault_metadata; CREATE TABLE secrets (project TEXT NOT NULL, environment TEXT NOT NULL, name TEXT NOT NULL, encrypted_value BLOB NOT NULL, iv BLOB NOT NULL, auth_tag BLOB NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now')), PRIMARY KEY (project, environment, name))");
  const encrypted = vault.encrypt("migrated-value", legacyKey);
  legacyDb.prepare("INSERT INTO secrets (project, environment, name, encrypted_value, iv, auth_tag) VALUES (?, ?, ?, ?, ?, ?)")
    .run("migration", "beta", "LEGACY_TOKEN", encrypted.encrypted, encrypted.iv, encrypted.authTag);
  legacyDb.close();
  vault.clearKey();
  for (const legacyAbsentPath of ["strict-policy.v1.json", ".strict-policy.key", "strict-policy-audit.jsonl", ".strict-policy.pending"]) {
    fs.rmSync(path.join(legacyHome, legacyAbsentPath), { force: true });
  }
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
  if (deferredFailures.length > 0) fail(deferredFailures.join("\n"));
  console.log(JSON.stringify({
    result: "PASS",
    platform: process.platform,
    arch: process.arch,
    node: process.version,
    nativeInstallMode,
    sha256,
    version: packageJson.version,
    checks: ["install", "fresh-init", "named-run", "F1-custody-remanence", "F2-output-containment", "F3-WAL-restore", "F4-restartable-rollback", ...(process.platform === "linux" ? ["F5-CLI-emergency-restore"] : []), "F6-machine-only-backup", process.platform === "linux" ? "machine-only-authorization-fail-closed" : "physical-authorization-covered-separately", "uninstall-reinstall", "unusual-paths", "metacharacters", "signals", "native-addon", "one-key-migration", "lock-unlock-inherit", "mixed-backup-restore", "portable-restore", "interrupted-write-recovery"],
  }));
} finally {
  delete process.env.KEYCLASP_HOME;
  fs.rmSync(root, { recursive: true, force: true });
}
