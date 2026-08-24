import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  clearKey,
  closeDb,
  initializeVault,
  resolveSecret,
  setMachineIdentityForTests,
  storeSecret,
  unlockVault,
} from "../src/vault.js";
import { readAuthorizationState, setAuthorizationRule } from "../src/policy.js";
import { createManagedBackup, createManagedBackupAuthorized, recoverInterruptedManagedRestore, restoreManagedBackup, restoreManagedBackupAuthorized, setBackupFaultForTests, setRestoreFaultForTests } from "../src/recovery.js";

describe("managed backup and restore", () => {
  let root: string;
  let home: string;
  let previousHome: string | undefined;

  function addInheritedAcl(directory: string): void {
    execFileSync("/bin/chmod", ["+a", "everyone allow read,file_inherit,directory_inherit", directory]);
  }

  function addWriteAcl(directory: string): void {
    execFileSync("/bin/chmod", ["+a", "everyone allow write", directory]);
  }

  function hasAcl(target: string): boolean {
    return /^\s*\d+:\s/m.test(execFileSync("/bin/ls", ["-lde", target], { encoding: "utf8" }));
  }

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-recovery-"));
    home = path.join(root, ".keyclasp");
    previousHome = process.env.KEYCLASP_HOME;
    process.env.KEYCLASP_HOME = home;
    closeDb();
    clearKey();
    setMachineIdentityForTests({ stable: Buffer.alloc(32, 3) });
  });

  afterEach(() => {
    closeDb();
    clearKey();
    setMachineIdentityForTests(null);
    setRestoreFaultForTests(null);
    setBackupFaultForTests(null);
    if (previousHome === undefined) delete process.env.KEYCLASP_HOME;
    else process.env.KEYCLASP_HOME = previousHome;
    fs.rmSync(root, { recursive: true, force: true });
  });

  it("restores one consistent machine-vault snapshot including broad and exact authorization rules", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "before-backup");
    setAuthorizationRule({ project: "app" }, true);
    setAuthorizationRule({ project: "app", environment: "prod", secret: "API_KEY" }, false);
    const backup = path.join(root, "backup");
    createManagedBackup(backup);

    storeSecret("app", "prod", "API_KEY", "after-backup");
    setAuthorizationRule({ project: "app" }, false);
    setAuthorizationRule({ project: "app", environment: "prod", secret: "API_KEY" }, true);
    restoreManagedBackup(backup);
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("before-backup");
    expect(readAuthorizationState("app", "prod", "API_KEY")).toBe("unlocked");
    expect(readAuthorizationState("app", "prod", "FUTURE_SECRET")).toBe("locked");
  });

  it("removes inherited macOS ACLs from a managed backup directory and every backup file", () => {
    if (process.platform !== "darwin") return;
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    setAuthorizationRule({ project: "app", environment: "prod" }, true);
    addInheritedAcl(root);
    const backup = path.join(root, "inherited-backup");

    createManagedBackup(backup);

    for (const target of [backup, ...fs.readdirSync(backup).map((name) => path.join(backup, name))]) {
      expect(hasAcl(target), target).toBe(false);
    }
  });

  it("removes inherited macOS ACLs from backup inputs and restored vault paths", () => {
    if (process.platform !== "darwin") return;
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    setAuthorizationRule({ project: "app", environment: "prod" }, true);
    const originalBackup = path.join(root, "original-backup");
    createManagedBackup(originalBackup);
    storeSecret("app", "prod", "API_KEY", "live-value");

    const inheritedParent = path.join(root, "inherited-parent");
    fs.mkdirSync(inheritedParent, { mode: 0o700 });
    addInheritedAcl(inheritedParent);
    const inheritedBackup = path.join(inheritedParent, "backup");
    fs.cpSync(originalBackup, inheritedBackup, { recursive: true });
    expect(hasAcl(inheritedBackup)).toBe(true);
    expect(fs.readdirSync(inheritedBackup).some((name) => hasAcl(path.join(inheritedBackup, name)))).toBe(true);
    addInheritedAcl(home);

    restoreManagedBackup(inheritedBackup);

    expect(resolveSecret("app", "prod", "API_KEY")).toBe("backup-value");
    for (const target of [
      inheritedBackup,
      ...fs.readdirSync(inheritedBackup).map((name) => path.join(inheritedBackup, name)),
      home,
      ...["vault.db", ".keyclasp.key", "strict-policy.v1.json", ".strict-policy.key"].map((name) => path.join(home, name)),
    ]) {
      expect(hasAcl(target), target).toBe(false);
    }
  });

  it("publishes backups only after staging is complete and preserves an indeterminate published copy", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    const before = path.join(root, "before-publish");
    setBackupFaultForTests("crash-before-backup-publish");
    expect(() => createManagedBackup(before)).toThrow(/before publication/);
    expect(fs.existsSync(before)).toBe(false);

    const after = path.join(root, "after-publish");
    setBackupFaultForTests("crash-after-backup-publish");
    expect(() => createManagedBackup(after)).toThrow(/after publication/);
    expect(fs.existsSync(path.join(after, "backup.json"))).toBe(true);
    setBackupFaultForTests(null);
    expect(() => restoreManagedBackup(after)).not.toThrow();
  });

  it("rejects a managed-backup parent writable by another user", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    const unsafeParent = path.join(root, "unsafe-parent");
    fs.mkdirSync(unsafeParent, { mode: 0o777 });
    fs.chmodSync(unsafeParent, 0o777);
    const destination = path.join(unsafeParent, "backup");

    expect(() => createManagedBackup(destination)).toThrow(/group or other users may write/i);
    expect(fs.existsSync(destination)).toBe(false);
  });

  it("rejects a macOS write-granting ACL on a managed-backup parent", () => {
    if (process.platform !== "darwin") return;
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "live-value");
    const backup = path.join(root, "trusted-backup");
    createManagedBackup(backup);
    addWriteAcl(root);

    expect(() => createManagedBackup(path.join(root, "blocked-backup"))).toThrow(/ACL grants write access/i);
    expect(() => restoreManagedBackup(backup)).toThrow(/ACL grants write access/i);
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("live-value");
  });

  it("does not create or restore anything when management authorization is cancelled", async () => {
    initializeVault("");
    const unlock = vi.fn(async () => undefined);
    const create = vi.fn(createManagedBackup);
    await expect(createManagedBackupAuthorized(path.join(root, "cancelled-backup"), {
      authorize: () => { throw new Error("Touch ID cancelled."); },
      ensureUnlocked: unlock,
      create,
    })).rejects.toThrow(/cancelled/i);
    expect(unlock).not.toHaveBeenCalled();
    expect(create).not.toHaveBeenCalled();
    expect(fs.existsSync(path.join(root, "cancelled-backup"))).toBe(false);

    const restore = vi.fn(restoreManagedBackup);
    await expect(restoreManagedBackupAuthorized(path.join(root, "missing"), {
      authorize: () => { throw new Error("Touch ID unavailable."); },
      promptPassphrase: vi.fn(),
      inspectMode: () => "machine",
      restore,
    })).rejects.toThrow(/unavailable/i);
    expect(restore).not.toHaveBeenCalled();
  });

  it("authenticates the live policy before backup authorization or unlock", async () => {
    initializeVault("");
    const authorize = vi.fn();
    const unlock = vi.fn(async () => undefined);
    const create = vi.fn(createManagedBackup);
    await expect(createManagedBackupAuthorized(path.join(root, "blocked-backup"), {
      validatePolicy: () => { throw new Error("policy authentication failed"); },
      authorize,
      ensureUnlocked: unlock,
      create,
    })).rejects.toThrow(/authentication failed/i);
    expect(authorize).not.toHaveBeenCalled();
    expect(unlock).not.toHaveBeenCalled();
    expect(create).not.toHaveBeenCalled();
  });

  it("does not repair backup permissions before restore authorization succeeds", async () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    const backup = path.join(root, "preauthorization-backup");
    createManagedBackup(backup);
    const manifestPath = path.join(backup, "backup.json");
    fs.chmodSync(backup, 0o755);
    fs.chmodSync(manifestPath, 0o644);

    await expect(restoreManagedBackupAuthorized(backup, {
      authorize: () => { throw new Error("Touch ID cancelled."); },
      promptPassphrase: vi.fn(),
    })).rejects.toThrow(/cancelled/i);

    expect(fs.statSync(backup).mode & 0o777).toBe(0o755);
    expect(fs.statSync(manifestPath).mode & 0o777).toBe(0o644);
  });

  it("rejects a modified backup before replacing live state", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "live-value");
    const backup = path.join(root, "backup");
    createManagedBackup(backup);
    fs.appendFileSync(path.join(backup, "vault.db"), "tamper");
    expect(() => restoreManagedBackup(backup)).toThrow(/integrity check/i);
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("live-value");
  });

  it("rejects forged runtime cleanup warnings in an input manifest", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "live-value");
    const backup = path.join(root, "backup");
    createManagedBackup(backup);
    const manifestPath = path.join(backup, "backup.json");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    manifest.cleanupWarnings = ["forged warning"];
    fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    expect(() => restoreManagedBackup(backup)).toThrow(/unknown field/i);
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("live-value");
  });

  it("rejects a rehashed but unauthenticated authorization-policy downgrade", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "live-value");
    setAuthorizationRule({ project: "app", environment: "prod" }, true);
    const backup = path.join(root, "backup");
    createManagedBackup(backup);
    const policyPath = path.join(backup, "strict-policy.v1.json");
    const policy = JSON.parse(fs.readFileSync(policyPath, "utf8"));
    policy.rules[0].locked = false;
    fs.writeFileSync(policyPath, `${JSON.stringify(policy)}\n`);
    const manifestPath = path.join(backup, "backup.json");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    manifest.files["strict-policy.v1.json"] = crypto.createHash("sha256").update(fs.readFileSync(policyPath)).digest("hex");
    fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    expect(() => restoreManagedBackup(backup)).toThrow(/manifest failed authentication/i);
    expect(readAuthorizationState("app", "prod")).toBe("locked");
  });

  it("restores over a corrupt current key without consulting it", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "restored-value");
    const backup = path.join(root, "backup");
    createManagedBackup(backup);
    closeDb();
    clearKey();
    fs.writeFileSync(path.join(home, ".keyclasp.key"), "corrupt", { mode: 0o600 });
    restoreManagedBackup(backup);
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("restored-value");
  });

  it("restores after total loss without requiring live initialization state", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "recovered-after-loss");
    const backup = path.join(root, "backup");
    createManagedBackup(backup);
    closeDb();
    clearKey();
    fs.rmSync(home, { recursive: true, force: true });

    restoreManagedBackup(backup);
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("recovered-after-loss");
  });

  for (const boundary of [
    "crash-after-first-stage-copy",
    "crash-after-journal",
    "crash-after-first-previous",
    "crash-after-previous-fsync",
    "crash-after-first-publish",
    "crash-after-all-published",
  ] as const) {
    it(`restores the prior complete set after simulated process death ${boundary}`, () => {
      initializeVault("");
      storeSecret("app", "prod", "API_KEY", "backup-value");
      const backup = path.join(root, "backup");
      createManagedBackup(backup);
      storeSecret("app", "prod", "API_KEY", "live-value");
      setRestoreFaultForTests(boundary);
      expect(() => restoreManagedBackup(backup)).toThrow(/Injected managed-restore crash/);
      expect(fs.existsSync(path.join(home, ".restore-transaction.v1.json"))).toBe(true);
      setRestoreFaultForTests(null);
      expect(recoverInterruptedManagedRestore()).toBe(true);
      expect(resolveSecret("app", "prod", "API_KEY")).toBe("live-value");
      expect(fs.existsSync(path.join(home, ".restore-transaction.v1.json"))).toBe(false);
    });
  }

  it("recovers an interrupted restore in a fresh process after the faulting process exits", () => {
    initializeVault("restart-passphrase");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    const backup = path.join(root, "restart-backup");
    createManagedBackup(backup);
    storeSecret("app", "prod", "API_KEY", "live-value");
    closeDb();
    clearKey();
    const recoveryUrl = pathToFileURL(path.join(process.cwd(), "dist", "recovery.js")).href;
    const vaultUrl = pathToFileURL(path.join(process.cwd(), "dist", "vault.js")).href;
    const environment = { ...process.env, KEYCLASP_HOME: home };
    const crashed = spawnSync(process.execPath, ["--input-type=module", "-e", [
      `import { restoreManagedBackup, setRestoreFaultForTests } from ${JSON.stringify(recoveryUrl)};`,
      "setRestoreFaultForTests('crash-after-first-publish');",
      `try { restoreManagedBackup(${JSON.stringify(backup)}, 'restart-passphrase'); } catch { process.exit(23); }`,
      "process.exit(24);",
    ].join("\n")], { encoding: "utf8", env: environment });
    expect(crashed.status, crashed.stderr).toBe(23);
    expect(fs.existsSync(path.join(home, ".restore-transaction.v1.json"))).toBe(true);

    const recovered = spawnSync(process.execPath, ["--input-type=module", "-e", [
      `import { recoverInterruptedManagedRestore } from ${JSON.stringify(recoveryUrl)};`,
      `import { unlockVault, resolveSecret } from ${JSON.stringify(vaultUrl)};`,
      "recoverInterruptedManagedRestore();",
      "unlockVault('restart-passphrase');",
      "process.stdout.write(resolveSecret('app', 'prod', 'API_KEY') ?? 'missing');",
    ].join("\n")], { encoding: "utf8", env: environment });
    expect(recovered.status, recovered.stderr).toBe(0);
    expect(recovered.stdout).toBe("live-value");
    expect(fs.existsSync(path.join(home, ".restore-transaction.v1.json"))).toBe(false);
  });

  it("finishes durable cleanup after a committed restore is interrupted", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    const backup = path.join(root, "backup");
    createManagedBackup(backup);
    storeSecret("app", "prod", "API_KEY", "live-value");
    setRestoreFaultForTests("crash-after-commit-journal");
    expect(() => restoreManagedBackup(backup)).toThrow(/commit journal/);
    expect(fs.existsSync(path.join(home, ".restore-transaction.v1.json"))).toBe(true);
    setRestoreFaultForTests(null);
    expect(recoverInterruptedManagedRestore()).toBe(true);
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("backup-value");
    expect(fs.readdirSync(home).some((name) => name.endsWith(".previous") || name.endsWith(".restore"))).toBe(false);
  });

  it("rejects a forged restore journal without promoting planted previous files", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "live-value");
    closeDb();
    clearKey();
    const transactionId = "forged";
    fs.copyFileSync(path.join(home, ".keyclasp.key"), path.join(home, `.keyclasp.key.${transactionId}.previous`));
    fs.writeFileSync(path.join(home, ".restore-transaction.v1.json"), `${JSON.stringify({
      version: 1,
      phase: "replacing",
      transactionId,
      staged: [],
      previous: [".keyclasp.key"],
      previousHashes: {},
      stagedHashes: {},
      mac: "forged",
    })}\n`, { mode: 0o600 });
    expect(() => recoverInterruptedManagedRestore()).toThrow(/failed authentication/i);
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("live-value");
  });

  it("keeps passphrase backups portable across a machine-identity change", () => {
    initializeVault("portable-passphrase");
    unlockVault("portable-passphrase");
    storeSecret("app", "prod", "API_KEY", "portable-value");
    const backup = path.join(root, "backup");
    createManagedBackup(backup);
    setMachineIdentityForTests({ stable: Buffer.alloc(32, 9) });
    restoreManagedBackup(backup, "portable-passphrase");
    unlockVault("portable-passphrase");
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("portable-value");
  });

  it("rejects a wrong backup passphrase without changing live state", () => {
    initializeVault("correct-passphrase");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    const backup = path.join(root, "passphrase-backup");
    createManagedBackup(backup);
    storeSecret("app", "prod", "API_KEY", "live-value");

    expect(() => restoreManagedBackup(backup, "wrong-passphrase")).toThrow(/passphrase is incorrect/i);
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("live-value");
  });

  it("rejects a copied machine backup before replacing a usable live vault", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "machine-value");
    const backup = path.join(root, "backup");
    createManagedBackup(backup);
    closeDb();
    clearKey();
    setMachineIdentityForTests({ stable: Buffer.alloc(32, 9) });
    home = path.join(root, "other-machine-vault");
    process.env.KEYCLASP_HOME = home;
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "other-machine-live");
    expect(() => restoreManagedBackup(backup)).toThrow(/cannot be unlocked on the current machine/i);
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("other-machine-live");
  });
});
