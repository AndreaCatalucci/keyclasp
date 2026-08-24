#!/usr/bin/env node

import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const CANCELLED_BLOCKED_LINE = "BLOCKED: Biometric authentication was cancelled by the operator.";

export function assertCancelledLockedRun(result) {
  if (result.error) throw new Error(`The locked-run process could not start: ${result.error.message}`);
  if (result.status !== 2) {
    throw new Error(`Expected the cancelled locked run to exit with status 2; received ${String(result.status)}.`);
  }
  const stdout = result.stdout ?? "";
  const stderr = result.stderr ?? "";
  if (stdout !== "" || stderr !== `${CANCELLED_BLOCKED_LINE}\n`) {
    throw new Error(`Expected only the cancellation-specific BLOCKED result; received stdout=${JSON.stringify(stdout)} stderr=${JSON.stringify(stderr)}.`);
  }
}

export function createTranscriptRecorder(evidenceDirectory, now = () => new Date()) {
  const transcriptPath = path.join(evidenceDirectory, "transcript.txt");
  const transcript = [
    "Slice 4 exact-artifact dual-key physical Touch ID verification",
    `started_at=${now().toISOString()}`,
    `evidence_directory=${evidenceDirectory}`,
  ];
  const save = () => {
    fs.writeFileSync(transcriptPath, `${transcript.join("\n")}\n`, { mode: 0o600 });
    fs.chmodSync(transcriptPath, 0o600);
  };
  const recorder = {
    path: transcriptPath,
    note(message) {
      transcript.push("", message);
      save();
    },
    record(label, result) {
      transcript.push(
        "",
        `[${label}]`,
        `status=${String(result.status)}`,
        `signal=${String(result.signal)}`,
        `error=${result.error?.message ?? ""}`,
        "stdout:",
        result.stdout ?? "",
        "stderr:",
        result.stderr ?? "",
      );
      save();
    },
    finish(outcome) {
      transcript.push("", outcome, `finished_at=${now().toISOString()}`);
      save();
    },
  };
  save();
  return recorder;
}

export function evidenceSummary(evidenceDirectory, transcriptPath) {
  return [`Evidence: ${evidenceDirectory}`, `Transcript: ${transcriptPath}`];
}

export function spawnWithLiveTranscript(command, args, options = {}) {
  const {
    display = true,
    stdoutSink = process.stdout,
    stderrSink = process.stderr,
    ...spawnOptions
  } = options;
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      ...spawnOptions,
      stdio: ["inherit", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let spawnError;
    child.stdout.on("data", (chunk) => {
      const text = chunk.toString();
      stdout += text;
      if (display) stdoutSink.write(text);
    });
    child.stderr.on("data", (chunk) => {
      const text = chunk.toString();
      stderr += text;
      if (display) stderrSink.write(text);
    });
    child.on("error", (error) => {
      spawnError = error;
    });
    child.on("close", (status, signal) => {
      resolve({ status, signal, stdout, stderr, ...(spawnError ? { error: spawnError } : {}) });
    });
  });
}

async function main() {
  if (process.platform !== "darwin") {
    throw new Error("Slice 4 physical verification requires macOS with Touch ID.");
  }

  const repository = path.resolve(import.meta.dirname, "..");
  const artifactArgument = process.argv[2];
  if (!artifactArgument) {
    throw new Error("Usage: node scripts/verify-slice2-touch-id.mjs <exact-tarball> <expected-sha256>. This verifier never rebuilds the candidate.");
  }
  const sourceArtifactPath = path.resolve(artifactArgument);
  if (!fs.statSync(sourceArtifactPath).isFile()) throw new Error(`Exact tarball not found: ${sourceArtifactPath}`);
  const expectedSha256 = process.argv[3] ?? process.env.EXPECTED_SHA256;
  if (!expectedSha256 || !/^[a-f0-9]{64}$/.test(expectedSha256)) {
    throw new Error("Pass the reviewed candidate SHA-256 as the second argument or EXPECTED_SHA256.");
  }
  const testRoot = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-slice4-touch-id-"));
  const transcript = createTranscriptRecorder(testRoot);
  const sentinel = path.join(testRoot, "child-launched");
  const environment = { ...process.env, KEYCLASP_HOME: path.join(testRoot, ".keyclasp") };
  function note(message) {
    console.log(message);
    transcript.note(message);
  }

  async function run(label, args, options = {}) {
    const result = await spawnWithLiveTranscript(process.execPath, [cli, ...args], {
      cwd: repository,
      env: environment,
      ...options,
    });
    transcript.record(label, result);
    return result;
  }

  function fail(message) {
    transcript.finish(`FAIL: ${message}`);
    throw new Error(`${message} Transcript: ${transcript.path}`);
  }

  function runExternal(label, command, args, options = {}) {
    const result = spawnSync(command, args, {
      cwd: repository,
      env: environment,
      encoding: "utf8",
      ...options,
    });
    transcript.record(label, result);
    return result;
  }

  function requireSuccess(result, label) {
    if (result.status !== 0 || result.error) fail(`${label} failed with status ${String(result.status)}.`);
  }

  function requirePassphrasePrompt(result, label, prompt = "Enter vault passphrase:") {
    if (!result.stdout.includes(prompt)) fail(`${label} did not request the expected passphrase after Touch ID.`);
  }

  const installDirectory = path.join(testRoot, "install");
  fs.mkdirSync(installDirectory, { mode: 0o700 });
  const artifactBytes = fs.readFileSync(sourceArtifactPath);
  const artifactPath = path.join(testRoot, path.basename(sourceArtifactPath));
  fs.writeFileSync(artifactPath, artifactBytes, { mode: 0o600, flag: "wx" });
  const artifactSha1 = crypto.createHash("sha1").update(artifactBytes).digest("hex");
  const artifactSha256 = crypto.createHash("sha256").update(artifactBytes).digest("hex");
  if (artifactSha256 !== expectedSha256) fail(`Artifact SHA-256 mismatch: expected ${expectedSha256}, received ${artifactSha256}.`);
  const artifactIntegrity = `sha512-${crypto.createHash("sha512").update(artifactBytes).digest("base64")}`;
  transcript.note(`artifact=${artifactPath}\nsha1=${artifactSha1}\nsha256=${artifactSha256}\nintegrity=${artifactIntegrity}`);
  const installResult = runExternal("npm-install-packed-artifact", "npm", [
    "--silent", "install", "--prefix", installDirectory, artifactPath,
  ], { env: { ...environment, npm_config_cache: path.join(testRoot, "npm-cache") } });
  requireSuccess(installResult, "exact-artifact installation");
  const cli = path.join(installDirectory, "node_modules", "keyclasp", "dist", "cli.js");
  if (!fs.existsSync(cli)) fail("Packed-artifact installation did not contain dist/cli.js.");
  transcript.note(`exact_artifact_cli=${cli}`);
  const versionResult = runExternal("installed-version", process.execPath, [cli, "version"], { cwd: testRoot });
  requireSuccess(versionResult, "installed version");
  if (versionResult.stdout.trim() !== "0.2.0-beta.1") fail(`Installed CLI version is ${versionResult.stdout.trim()}.`);

  const disposablePassphrase = "slice4-disposable-passphrase";
  const setupPath = path.join(testRoot, "setup-passphrase-vault.mjs");
  const vaultModule = pathToFileURL(path.join(installDirectory, "node_modules", "keyclasp", "dist", "vault.js")).href;
  fs.writeFileSync(setupPath, [
    `import { initializeVault, storeSecret, closeDb, clearKey } from ${JSON.stringify(vaultModule)};`,
    `initializeVault(${JSON.stringify(disposablePassphrase)});`,
    `storeSecret("physical", "touch-id", "SLICE3_TEST", "disposable-test-value");`,
    "closeDb();",
    "clearKey();",
  ].join("\n"), { mode: 0o600 });
  fs.chmodSync(setupPath, 0o600);
  requireSuccess(runExternal("setup-passphrase-vault", process.execPath, [setupPath]), "temporary passphrase-vault setup");

  const unattendedBefore = await run("unattended-before-lock", [
    "run", "--project", "physical", "--environment", "touch-id", "--env", "SLICE3_TEST", "--",
    process.execPath, "-e", "process.exit(process.env.SLICE3_TEST === 'disposable-test-value' ? 0 : 9)",
  ]);
  requireSuccess(unattendedBefore, "unattended named run before lock");

  note(`1/10 Approve Touch ID to lock the physical/touch-id scope. Then enter ${disposablePassphrase} when prompted.`);
  const lockResult = await run("scope-lock", ["lock", "--project", "physical", "--environment", "touch-id"]);
  requireSuccess(lockResult, "scope lock");
  requirePassphrasePrompt(lockResult, "Approved lock");

  note("2/10 When the Touch ID dialog appears, click Cancel. Do not touch the sensor. The child must not launch and no passphrase prompt may appear.");
  const cancelled = await run("locked-run-cancel", [
    "run", "--project", "physical", "--environment", "touch-id", "--env", "SLICE3_TEST", "--",
    process.execPath, "-e", "require('node:fs').writeFileSync(process.argv[1], 'launched')", sentinel,
  ]);
  try {
    assertCancelledLockedRun(cancelled);
  } catch (error) {
    fail(error instanceof Error ? error.message : "The locked-run cancellation result was invalid.");
  }
  if (fs.existsSync(sentinel)) fail(`The cancelled locked run launched its child: ${sentinel}`);

  note(`3/10 Approve Touch ID for the locked named run, then enter ${disposablePassphrase}.`);
  const approvedLockedRun = await run("locked-run-approved", [
    "run", "--project", "physical", "--environment", "touch-id", "--env", "SLICE3_TEST", "--",
    process.execPath, "-e", "process.exit(process.env.SLICE3_TEST === 'disposable-test-value' ? 0 : 9)",
  ]);
  requireSuccess(approvedLockedRun, "approved locked named run");
  requirePassphrasePrompt(approvedLockedRun, "Approved locked run");

  note(`4/10 Approve Touch ID for the broad run, then enter ${disposablePassphrase}.`);
  const broadRun = await run("broad-run-approved", [
    "run", "--project", "physical", "--environment", "touch-id", "--",
    process.execPath, "-e", "process.exit(process.env.SLICE3_TEST === 'disposable-test-value' ? 0 : 9)",
  ]);
  requireSuccess(broadRun, "approved broad run");
  requirePassphrasePrompt(broadRun, "Approved broad run");

  note(`5/10 Approve Touch ID for get, then enter ${disposablePassphrase}. The printed value is disposable test data.`);
  const getResult = await run("get-approved", ["get", "SLICE3_TEST", "--project", "physical", "--environment", "touch-id"]);
  requireSuccess(getResult, "approved get");
  requirePassphrasePrompt(getResult, "Approved get");
  if (!getResult.stdout.endsWith("disposable-test-value\n")) fail("Approved get did not return the disposable value.");

  const backupDirectory = path.join(testRoot, "managed-backup");
  note(`6/10 Approve Touch ID to create the managed backup, then enter ${disposablePassphrase}.`);
  const backupCreate = await run("backup-create-approved", ["backup", "create", backupDirectory]);
  requireSuccess(backupCreate, "approved backup create");
  requirePassphrasePrompt(backupCreate, "Approved backup create");

  note(`7/10 Approve Touch ID to create an exact-secret unlock, then enter ${disposablePassphrase}.`);
  const exactUnlock = await run("exact-unlock-approved", ["unlock", "--project", "physical", "--environment", "touch-id", "SLICE3_TEST"]);
  requireSuccess(exactUnlock, "approved exact unlock");
  requirePassphrasePrompt(exactUnlock, "Approved exact unlock");
  const exactUnlocked = await run("exact-unlocked-run", [
    "run", "--project", "physical", "--environment", "touch-id", "--env", "SLICE3_TEST", "--",
    process.execPath, "-e", "process.exit(process.env.SLICE3_TEST === 'disposable-test-value' ? 0 : 9)",
  ]);
  requireSuccess(exactUnlocked, "unattended exact-unlocked run");

  note(`8/10 Approve Touch ID to inherit the broader locked rule, then enter ${disposablePassphrase}.`);
  const exactInherit = await run("exact-inherit-approved", ["inherit", "--project", "physical", "--environment", "touch-id", "SLICE3_TEST"]);
  requireSuccess(exactInherit, "approved inherit");
  requirePassphrasePrompt(exactInherit, "Approved inherit");

  note(`9/10 Approve Touch ID to restore the exact managed backup, then enter ${disposablePassphrase}.`);
  const backupRestore = await run("backup-restore-approved", ["backup", "restore", backupDirectory]);
  requireSuccess(backupRestore, "approved backup restore");
  requirePassphrasePrompt(backupRestore, "Approved backup restore", "Enter managed backup passphrase:");

  const enabledStatus = await run("status-enabled", ["status", "--project", "physical", "--environment", "touch-id"], { display: false });
  requireSuccess(enabledStatus, "enabled status check");
  if (!enabledStatus.stdout.includes("Mode:       software-dual-key") ||
      !enabledStatus.stdout.includes("Authorization: locked")) {
    fail("Status did not report software-dual-key with the scope locked.");
  }

  note(`10/10 Approve Touch ID to unlock the physical/touch-id scope. Then enter ${disposablePassphrase} when prompted.`);
  const unlockResult = await run("scope-unlock", ["unlock", "--project", "physical", "--environment", "touch-id"]);
  requireSuccess(unlockResult, "scope unlock");
  requirePassphrasePrompt(unlockResult, "Approved scope unlock");

  const disabledStatus = await run("status-disabled", ["status", "--project", "physical", "--environment", "touch-id"], { display: false });
  requireSuccess(disabledStatus, "disabled status check");
  if (!disabledStatus.stdout.includes("Authorization: unlocked")) {
    fail("Status did not report the scope unlocked after the final authorization.");
  }

  const unattendedAfter = await run("unattended-after-unlock", [
    "run", "--project", "physical", "--environment", "touch-id", "--env", "SLICE3_TEST", "--",
    process.execPath, "-e", "process.exit(process.env.SLICE3_TEST === 'disposable-test-value' ? 0 : 9)",
  ]);
  requireSuccess(unattendedAfter, "unattended named run after unlock");

  transcript.finish("PASS");
  console.log("PASS: The exact dual-key artifact passed unattended named use; Touch ID plus passphrase for lock, locked and broad runs, get, backup, restore, unlock, and inherit; cancellation with no child launch; and unattended use after machine-custody transitions.");
  for (const line of evidenceSummary(testRoot, transcript.path)) console.log(line);
}

const invokedDirectly = process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.stack ?? error.message : error);
    process.exitCode = 1;
  });
}
