import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { requireOperatorAuthentication, type BiometricRunner } from "../src/biometric.js";
import { revealSecretReason } from "../src/runtime.js";
import { setAuthorizationRuleAuthorized } from "../src/policy.js";
import { createManagedBackup, createManagedBackupAuthorized, restoreManagedBackupAuthorized, verifyManagedBackupPassphrase } from "../src/recovery.js";
import { createSoftwareRunRuntime } from "../src/software/runtime.js";
import { clearKey, closeDb, getKey, initializeVault, listSecrets, resolveSecret, resolveSecretsForRun, setMachineIdentityForTests, storeSecret, unlockVault } from "../src/vault.js";

describe("platform operator authorization", () => {
  let root: string;
  let home: string;
  let previousHome: string | undefined;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-platform-authorization-"));
    home = path.join(root, ".keyclasp");
    previousHome = process.env.KEYCLASP_HOME;
    process.env.KEYCLASP_HOME = home;
    closeDb();
    clearKey();
    setMachineIdentityForTests({ stable: Buffer.alloc(32, 11) });
  });

  afterEach(() => {
    closeDb();
    clearKey();
    setMachineIdentityForTests(null);
    if (previousHome === undefined) delete process.env.KEYCLASP_HOME;
    else process.env.KEYCLASP_HOME = previousHome;
    fs.rmSync(root, { recursive: true, force: true });
  });

  it("uses one Linux passphrase prompt to authorize and unlock a locked named run", async () => {
    initializeVault("linux-passphrase");
    storeSecret("app", "prod", "API_KEY", "linux-secret");
    clearKey();
    const promptPassphrase = vi.fn(async () => "linux-passphrase");
    const ensureUnlocked = vi.fn(async () => { getKey(); });
    const runtime = createSoftwareRunRuntime({
      ensureUnlocked,
      listSecretNames: (project, environment) => listSecrets(project, environment) as string[],
      resolveSecret,
      resolveSecrets: resolveSecretsForRun,
      readAuthorizationState: () => "locked",
      authorize: (reason) => requireOperatorAuthentication(reason, { platform: "linux", promptPassphrase }),
      baseEnv: () => ({}),
      stdout: () => {},
      stderr: () => {},
    });

    const result = await runtime.run({
      allowUnsafe: false,
      envSpecs: [{ sourceName: "API_KEY", targetName: "API_KEY" }],
      commandArgs: [process.execPath, "-e", "process.exit(process.env.API_KEY === 'linux-secret' ? 0 : 9)"],
      scope: { project: "app", environment: "prod" },
    });

    expect(result).toEqual({ kind: "exit", exitCode: 0 });
    expect(promptPassphrase).toHaveBeenCalledOnce();
    expect(ensureUnlocked).toHaveBeenCalledOnce();
  });

  it("blocks a wrong Linux passphrase before unlock, decryption, or child launch", async () => {
    initializeVault("correct-passphrase");
    storeSecret("app", "prod", "API_KEY", "linux-secret");
    clearKey();
    const promptPassphrase = vi.fn(async () => "wrong-passphrase");
    const ensureUnlocked = vi.fn(async () => undefined);
    const resolveSecrets = vi.fn(resolveSecretsForRun);
    const sentinel = path.join(root, "wrong-passphrase-child");
    const runtime = createSoftwareRunRuntime({
      ensureUnlocked,
      listSecretNames: () => ["API_KEY"],
      resolveSecret,
      resolveSecrets,
      readAuthorizationState: () => "locked",
      authorize: (reason) => requireOperatorAuthentication(reason, { platform: "linux", promptPassphrase }),
      baseEnv: () => ({}),
      stdout: () => {},
      stderr: () => {},
    });

    const result = await runtime.run({
      allowUnsafe: true,
      envSpecs: [{ sourceName: "API_KEY", targetName: "API_KEY" }],
      commandArgs: [process.execPath, "-e", "require('node:fs').writeFileSync(process.argv[1], 'launched')", sentinel],
      scope: { project: "app", environment: "prod" },
    });

    expect(result).toEqual({ kind: "blocked", exitCode: 2 });
    expect(promptPassphrase).toHaveBeenCalledOnce();
    expect(ensureUnlocked).not.toHaveBeenCalled();
    expect(resolveSecrets).not.toHaveBeenCalled();
    expect(fs.existsSync(sentinel)).toBe(false);
  });

  it("requires macOS Touch ID before the passphrase unlock for a locked passphrase run", async () => {
    initializeVault("mac-passphrase");
    storeSecret("app", "prod", "API_KEY", "mac-secret");
    clearKey();
    const events: string[] = [];
    const runner = vi.fn<BiometricRunner>(() => {
      events.push("touch-id");
      return { status: 0 };
    });
    const runtime = createSoftwareRunRuntime({
      ensureUnlocked: async () => {
        events.push("passphrase-unlock");
        unlockVault("mac-passphrase");
      },
      listSecretNames: (project, environment) => listSecrets(project, environment) as string[],
      resolveSecret,
      resolveSecrets: resolveSecretsForRun,
      readAuthorizationState: () => "locked",
      authorize: (reason) => requireOperatorAuthentication(reason, { platform: "darwin", runner }),
      baseEnv: () => ({}),
      stdout: () => {},
      stderr: () => {},
    });

    const result = await runtime.run({
      allowUnsafe: false,
      envSpecs: [{ sourceName: "API_KEY", targetName: "API_KEY" }],
      commandArgs: [process.execPath, "-e", "process.exit(0)"],
      scope: { project: "app", environment: "prod" },
    });

    expect(result.exitCode).toBe(0);
    expect(events).toEqual(["touch-id", "passphrase-unlock"]);
  });

  it("requires only the key classes needed after macOS authorization", async () => {
    initializeVault("operator-passphrase");
    storeSecret("app", "prod", "API_KEY", "secret");
    const runner = vi.fn<BiometricRunner>(() => ({ status: 0 }));
    for (const operation of ["policy", "backup"] as const) {
      clearKey();
      const events: string[] = [];
      const authorize = (reason: string) => requireOperatorAuthentication(reason, {
        platform: "darwin",
        runner: (command, args) => {
          events.push("touch-id");
          return runner(command, args);
        },
      });
      const ensureUnlocked = async () => {
        events.push("passphrase-unlock");
        unlockVault("operator-passphrase");
      };
      if (operation === "policy") {
        await setAuthorizationRuleAuthorized({ project: "app" }, true, { authorize, ensureUnlocked });
      } else {
        await createManagedBackupAuthorized(path.join(root, "authorized-backup"), { authorize, ensureUnlocked });
      }
      expect(events).toEqual(operation === "policy" ? ["touch-id", "passphrase-unlock"] : ["touch-id"]);
    }
  });

  it("uses one Linux prompt for backup authorization without unlocking an unused interactive key", async () => {
    initializeVault("backup-passphrase");
    storeSecret("app", "prod", "API_KEY", "secret");
    clearKey();
    const promptPassphrase = vi.fn(async () => "backup-passphrase");
    const ensureUnlocked = vi.fn(async () => { getKey(); });
    await createManagedBackupAuthorized(path.join(root, "linux-backup"), {
      authorize: (reason) => requireOperatorAuthentication(reason, { platform: "linux", promptPassphrase }),
      ensureUnlocked,
    });
    expect(promptPassphrase).toHaveBeenCalledOnce();
    expect(ensureUnlocked).not.toHaveBeenCalled();
  });

  it("unlocks the interactive class after authorization for a mixed backup", async () => {
    initializeVault("mixed-backup-passphrase");
    storeSecret("app", "prod", "MACHINE", "machine");
    storeSecret("app", "prod", "INTERACTIVE", "interactive", "interactive");
    const events: string[] = [];
    await createManagedBackupAuthorized(path.join(root, "mixed-backup"), {
      authorize: async () => {
        events.push("authorize");
        return { method: "touch-id" };
      },
      ensureUnlocked: async () => {
        events.push("interactive-unlock");
        unlockVault("mixed-backup-passphrase");
      },
    });
    expect(events).toEqual(["authorize", "interactive-unlock"]);
  });

  it("reuses one Linux authorization passphrase to unlock an interactive backup", async () => {
    initializeVault("one-prompt-passphrase");
    unlockVault("one-prompt-passphrase");
    storeSecret("app", "prod", "INTERACTIVE", "interactive", "interactive");
    clearKey();
    const promptPassphrase = vi.fn(async () => "one-prompt-passphrase");
    const ensureUnlocked = vi.fn(async (passphrase?: string) => { unlockVault(passphrase!); });
    await createManagedBackupAuthorized(path.join(root, "interactive-backup"), {
      authorize: (reason) => requireOperatorAuthentication(reason, { platform: "linux", promptPassphrase }),
      ensureUnlocked,
    });
    expect(promptPassphrase).toHaveBeenCalledOnce();
    expect(ensureUnlocked).toHaveBeenCalledWith("one-prompt-passphrase");
  });

  it.each([
    ["cancelled", 2],
    ["unavailable", 3],
  ])("blocks a macOS run before unlock, decryption, or child launch when Touch ID is %s", async (_label, status) => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "machine-secret");
    const ensureUnlocked = vi.fn(async () => undefined);
    const resolveSecrets = vi.fn(resolveSecretsForRun);
    const sentinel = path.join(root, "child-launched");
    const runtime = createSoftwareRunRuntime({
      ensureUnlocked,
      listSecretNames: () => ["API_KEY"],
      resolveSecret,
      resolveSecrets,
      readAuthorizationState: () => "locked",
      authorize: (reason) => requireOperatorAuthentication(reason, {
        platform: "darwin",
        runner: () => ({ status }),
      }),
      baseEnv: () => ({}),
      stdout: () => {},
      stderr: () => {},
    });

    const result = await runtime.run({
      allowUnsafe: true,
      envSpecs: [{ sourceName: "API_KEY", targetName: "API_KEY" }],
      commandArgs: [process.execPath, "-e", "require('node:fs').writeFileSync(process.argv[1], 'launched')", sentinel],
      scope: { project: "app", environment: "prod" },
    });

    expect(result).toEqual({ kind: "blocked", exitCode: 2 });
    expect(ensureUnlocked).not.toHaveBeenCalled();
    expect(resolveSecrets).not.toHaveBeenCalled();
    expect(fs.existsSync(sentinel)).toBe(false);
  });

  it("blocks an oversized complete broad-run disclosure before Touch ID, unlock, decryption, or child launch", async () => {
    initializeVault("");
    const secretNames = Array.from({ length: 80 }, (_, index) => `VERY_LONG_SECRET_NAME_${String(index).padStart(3, "0")}`);
    let helperInput = "";
    const runner = vi.fn<BiometricRunner>((_command, _args, input) => {
      helperInput = input;
      return { status: Buffer.byteLength(input, "utf8") > 1024 ? 64 : 0 };
    });
    let authorizationReason = "";
    const ensureUnlocked = vi.fn(async () => undefined);
    const resolveSecrets = vi.fn(resolveSecretsForRun);
    const stderr = vi.fn();
    const runtime = createSoftwareRunRuntime({
      ensureUnlocked,
      listSecretNames: () => secretNames,
      resolveSecret,
      resolveSecrets,
      readAuthorizationState: () => "unlocked",
      authorize: (reason) => {
        authorizationReason = reason;
        return requireOperatorAuthentication(reason, { platform: "darwin", runner });
      },
      baseEnv: () => ({}),
      stdout: () => {},
      stderr,
    });

    await expect(runtime.run({
      allowUnsafe: false,
      envSpecs: [],
      commandArgs: ["deploy"],
      scope: { project: "app", environment: "prod" },
    })).resolves.toEqual({ kind: "blocked", exitCode: 2 });
    expect(authorizationReason.split("\n")[2]).toBe(`Secrets: ${secretNames.map((name) => JSON.stringify(name)).join(", ")}`);
    expect(Buffer.byteLength(authorizationReason, "utf8")).toBeGreaterThan(1024);
    expect(helperInput).toBe(authorizationReason);
    expect(stderr).toHaveBeenCalledWith("BLOCKED: The macOS biometric authentication helper rejected its input.\n");
    expect(runner).toHaveBeenCalledOnce();
    expect(ensureUnlocked).not.toHaveBeenCalled();
    expect(resolveSecrets).not.toHaveBeenCalled();
  });

  it("fails every Linux machine-only operator path before unlock, resolution, mutation, recovery, or child launch", async () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "machine-secret");
    const promptPassphrase = vi.fn(async () => "");
    const authorize = (reason: string) => requireOperatorAuthentication(reason, { platform: "linux", promptPassphrase });
    const ensureUnlocked = vi.fn(async () => undefined);
    const resolveSecrets = vi.fn(resolveSecretsForRun);
    const runtime = createSoftwareRunRuntime({
      ensureUnlocked,
      listSecretNames: () => ["API_KEY"],
      resolveSecret,
      resolveSecrets,
      readAuthorizationState: () => "locked",
      authorize,
      baseEnv: () => ({}),
      stdout: () => {},
      stderr: () => {},
    });
    const sentinel = path.join(root, "machine-child");
    for (const envSpecs of [[{ sourceName: "API_KEY", targetName: "API_KEY" }], []]) {
      const result = await runtime.run({
        allowUnsafe: true,
        envSpecs,
        commandArgs: [process.execPath, "-e", "require('node:fs').writeFileSync(process.argv[1], 'launched')", sentinel],
        scope: { project: "app", environment: "prod" },
      });
      expect(result).toEqual({ kind: "blocked", exitCode: 2 });
    }
    const reveal = vi.fn(() => "machine-secret");
    await expect(authorize(revealSecretReason(["app", "prod", "API_KEY"]))).rejects.toThrow(/machine-only vaults fail closed/i);
    const mutate = vi.fn();
    await expect(setAuthorizationRuleAuthorized({ project: "app" }, true, {
      authorize,
      ensureUnlocked,
      mutate,
    })).rejects.toThrow(/machine-only vaults fail closed/i);
    const create = vi.fn();
    await expect(createManagedBackupAuthorized(path.join(root, "blocked-backup"), {
      authorize,
      ensureUnlocked,
      create,
    })).rejects.toThrow(/machine-only vaults fail closed/i);
    const restore = vi.fn();
    await expect(restoreManagedBackupAuthorized(path.join(root, "missing"), {
      inspectMode: () => "machine",
      authorize: (reason) => authorize(reason),
      promptPassphrase,
      restore,
    })).rejects.toThrow(/machine-only vaults fail closed/i);

    expect(promptPassphrase).not.toHaveBeenCalled();
    expect(ensureUnlocked).not.toHaveBeenCalled();
    expect(resolveSecrets).not.toHaveBeenCalled();
    expect(reveal).not.toHaveBeenCalled();
    expect(mutate).not.toHaveBeenCalled();
    expect(create).not.toHaveBeenCalled();
    expect(restore).not.toHaveBeenCalled();
    expect(fs.existsSync(sentinel)).toBe(false);
  });

  it("restores a passphrase backup after total loss with one Linux prompt", async () => {
    initializeVault("portable-passphrase");
    storeSecret("app", "prod", "API_KEY", "backup-secret", "interactive");
    const backup = path.join(root, "backup");
    createManagedBackup(backup);
    closeDb();
    clearKey();
    fs.rmSync(home, { recursive: true, force: true });
    const promptPassphrase = vi.fn(async () => "portable-passphrase");
    const secondPrompt = vi.fn(async () => "portable-passphrase");

    await restoreManagedBackupAuthorized(backup, {
      authorize: (reason, mode) => requireOperatorAuthentication(reason, {
        platform: "linux",
        vaultHasPassphrase: () => mode === "passphrase",
        promptPassphrase,
        verifyPassphrase: (passphrase) => verifyManagedBackupPassphrase(backup, passphrase),
      }),
      promptPassphrase: secondPrompt,
    });

    expect(promptPassphrase).toHaveBeenCalledOnce();
    expect(secondPrompt).not.toHaveBeenCalled();
    unlockVault("portable-passphrase");
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("backup-secret");
  });

  it("fails a non-interactive Linux authorization before resolving a secret", async () => {
    initializeVault("noninteractive-passphrase");
    clearKey();
    const reveal = vi.fn(() => "secret");
    await expect(requireOperatorAuthentication(
      revealSecretReason(["app", "prod", "API_KEY"]),
      { platform: "linux" },
    )).rejects.toThrow(/interactive terminal/i);
    expect(reveal).not.toHaveBeenCalled();
  });
});
