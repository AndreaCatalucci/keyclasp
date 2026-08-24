#!/usr/bin/env node

import { spawnSync } from "node:child_process";
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
    "Slice 2 physical Touch ID verification",
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

function main() {
  if (process.platform !== "darwin") {
    throw new Error("Slice 2 physical verification requires macOS with Touch ID.");
  }

  const repository = path.resolve(import.meta.dirname, "..");
  const testRoot = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-slice2-touch-id-"));
  const transcript = createTranscriptRecorder(testRoot);
  const sentinel = path.join(testRoot, "child-launched");
  const environment = { ...process.env, KEYCLASP_HOME: path.join(testRoot, ".keyclasp") };
  function note(message) {
    console.log(message);
    transcript.note(message);
  }

  function run(label, args, options = {}) {
    const { display = true, ...spawnOptions } = options;
    const result = spawnSync(process.execPath, [cli, ...args], {
      cwd: repository,
      env: environment,
      encoding: "utf8",
      ...spawnOptions,
    });
    const stdout = result.stdout ?? "";
    const stderr = result.stderr ?? "";
    if (display) {
      if (stdout) process.stdout.write(stdout);
      if (stderr) process.stderr.write(stderr);
    }
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

  const artifactDirectory = path.join(testRoot, "artifact");
  const installDirectory = path.join(testRoot, "install");
  fs.mkdirSync(artifactDirectory, { mode: 0o700 });
  fs.mkdirSync(installDirectory, { mode: 0o700 });
  const packageResult = runExternal("npm-pack", "npm", [
    "--silent", "pack", "--json", "--pack-destination", artifactDirectory,
  ], { env: { ...environment, npm_config_cache: path.join(testRoot, "npm-cache") } });
  requireSuccess(packageResult, "npm pack");
  let packageReceipt;
  try {
    [packageReceipt] = JSON.parse(packageResult.stdout);
  } catch {
    fail("npm pack did not return one JSON package receipt.");
  }
  if (!packageReceipt?.filename || !packageReceipt?.shasum || !packageReceipt?.integrity) {
    fail("npm pack receipt is incomplete.");
  }
  const artifactPath = path.join(artifactDirectory, packageReceipt.filename);
  const artifactSha256 = crypto.createHash("sha256").update(fs.readFileSync(artifactPath)).digest("hex");
  transcript.note(`artifact=${artifactPath}\nsha1=${packageReceipt.shasum}\nsha256=${artifactSha256}\nintegrity=${packageReceipt.integrity}`);
  const installResult = runExternal("npm-install-packed-artifact", "npm", [
    "--silent", "install", "--prefix", installDirectory, artifactPath,
  ], { env: { ...environment, npm_config_cache: path.join(testRoot, "npm-cache") } });
  requireSuccess(installResult, "packed-artifact installation");
  const cli = path.join(installDirectory, "node_modules", "keyclasp", "dist", "cli.js");
  if (!fs.existsSync(cli)) fail("Packed-artifact installation did not contain dist/cli.js.");
  transcript.note(`packed_cli=${cli}`);

  const disposablePassphrase = "slice2-disposable-passphrase";
  const setupPath = path.join(testRoot, "setup-passphrase-vault.mjs");
  const vaultModule = pathToFileURL(path.join(installDirectory, "node_modules", "keyclasp", "dist", "vault.js")).href;
  fs.writeFileSync(setupPath, [
    `import { initializeVault, storeSecret, closeDb, clearKey } from ${JSON.stringify(vaultModule)};`,
    `initializeVault(${JSON.stringify(disposablePassphrase)});`,
    `storeSecret("physical", "touch-id", "SLICE2_TEST", "disposable-test-value");`,
    "closeDb();",
    "clearKey();",
  ].join("\n"), { mode: 0o600 });
  fs.chmodSync(setupPath, 0o600);
  requireSuccess(runExternal("setup-passphrase-vault", process.execPath, [setupPath]), "temporary passphrase-vault setup");

  note(`1/3 Approve Touch ID to lock the physical/touch-id scope. Then enter ${disposablePassphrase} when prompted.`);
  const lockResult = run("scope-lock", ["lock", "--project", "physical", "--environment", "touch-id"], {
    stdio: ["inherit", "pipe", "pipe"],
  });
  requireSuccess(lockResult, "scope lock");
  if (!lockResult.stdout.includes("Enter vault passphrase:")) fail("The approved lock did not request the passphrase after Touch ID.");

  note("2/3 When the Touch ID dialog appears, click Cancel. Do not touch the sensor. The child must not launch.");
  const cancelled = run("locked-run-cancel", [
    "run", "--project", "physical", "--environment", "touch-id", "--env", "SLICE2_TEST", "--",
    process.execPath, "-e", "require('node:fs').writeFileSync(process.argv[1], 'launched')", sentinel,
  ], { stdio: ["inherit", "pipe", "pipe"] });
  try {
    assertCancelledLockedRun(cancelled);
  } catch (error) {
    fail(error instanceof Error ? error.message : "The locked-run cancellation result was invalid.");
  }
  if (fs.existsSync(sentinel)) fail(`The cancelled locked run launched its child: ${sentinel}`);

  const enabledStatus = run("status-enabled", ["status", "--project", "physical", "--environment", "touch-id"], { display: false });
  requireSuccess(enabledStatus, "enabled status check");
  if (!enabledStatus.stdout.includes("Mode:       software-passphrase") ||
      !enabledStatus.stdout.includes("Authorization: locked")) {
    fail("Status did not report software-passphrase with the scope locked.");
  }

  note(`3/3 Approve Touch ID to unlock the physical/touch-id scope. Then enter ${disposablePassphrase} when prompted.`);
  const unlockResult = run("scope-unlock", ["unlock", "--project", "physical", "--environment", "touch-id"], {
    stdio: ["inherit", "pipe", "pipe"],
  });
  requireSuccess(unlockResult, "scope unlock");
  if (!unlockResult.stdout.includes("Enter vault passphrase:")) fail("The approved unlock did not request the passphrase after Touch ID.");

  const disabledStatus = run("status-disabled", ["status", "--project", "physical", "--environment", "touch-id"], { display: false });
  requireSuccess(disabledStatus, "disabled status check");
  if (!disabledStatus.stdout.includes("Authorization: unlocked")) {
    fail("Status did not report the scope unlocked after the final authorization.");
  }

  transcript.finish("PASS");
  console.log("PASS: The final packed artifact required Touch ID then the passphrase for lock and unlock; cancellation exited 2 with the exact BLOCKED result, requested no passphrase, launched no child, and status reported the effective software-passphrase authorization state.");
  for (const line of evidenceSummary(testRoot, transcript.path)) console.log(line);
}

const invokedDirectly = process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) main();
