import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import Database from "better-sqlite3";
import {
  clearKey,
  closeDb,
  initializeVault,
  readSecretKeyClass,
  resolveSecret,
  setMachineIdentityForTests,
  storeSecret,
  unlockVault,
} from "../src/vault.js";
import { readAuthorizationState, setAuthorizationRule } from "../src/policy.js";
import { createManagedBackup, createManagedBackupAuthorized, getRestorePrimitiveCountsForTests, recoverInterruptedManagedRestore, restoreManagedBackup, restoreManagedBackupAuthorized, setBackupFaultForTests, setRestoreFaultForTests, setRestoreOperationFaultForTests, setRestorePrimitiveFaultForTests } from "../src/recovery.js";
import { assertNoExternalVaultClients } from "../src/vault-files.js";

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

  function restoreJournalExists(): boolean {
    return fs.existsSync(home) && fs.readdirSync(home).some((name) => name.startsWith(".restore-transaction.v2."));
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
    setRestoreOperationFaultForTests(null);
    setRestorePrimitiveFaultForTests(null);
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

  it.runIf(process.platform === "linux")("ignores proc process directories hidden by Linux ptrace policy", () => {
    initializeVault("");
    const realReaddir = fs.readdirSync.bind(fs);
    const pid = String(process.pid);
    const readdir = vi.spyOn(fs, "readdirSync").mockImplementation(((target: fs.PathLike, options?: any) => {
      if (String(target) === "/proc") return [pid];
      if (String(target) === `/proc/${pid}/fd`) {
        throw Object.assign(new Error("permission denied"), { code: "EACCES" });
      }
      return realReaddir(target, options);
    }) as typeof fs.readdirSync);
    try {
      expect(() => assertNoExternalVaultClients(home)).not.toThrow();
    } finally {
      readdir.mockRestore();
    }
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

  it("authorizes before authenticating policy or requesting a required key", async () => {
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
    expect(authorize).toHaveBeenCalledOnce();
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

  it("refuses to publish a backup containing a record that fails AAD authentication", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "live-value");
    closeDb();
    clearKey();
    const database = new Database(path.join(home, "vault.db"));
    database.prepare("UPDATE secrets SET auth_tag = ? WHERE name = ?").run(crypto.randomBytes(16), "API_KEY");
    database.close();
    const destination = path.join(root, "invalid-record-backup");
    expect(() => createManagedBackup(destination)).toThrow();
    expect(fs.existsSync(destination)).toBe(false);
  });

  it("treats SQLITE_BUSY as writer exclusion and leaves live state in place", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    const backup = path.join(root, "busy-backup");
    createManagedBackup(backup);
    storeSecret("app", "prod", "API_KEY", "live-value");
    closeDb();
    clearKey();
    const external = new Database(path.join(home, "vault.db"));
    external.exec("BEGIN IMMEDIATE");
    const before = crypto.createHash("sha256").update(fs.readFileSync(path.join(home, "vault.db"))).digest("hex");
    try {
      expect(() => restoreManagedBackup(backup)).toThrow(/busy|exclusive|SQLite file open/i);
      expect(crypto.createHash("sha256").update(fs.readFileSync(path.join(home, "vault.db"))).digest("hex")).toBe(before);
      expect(restoreJournalExists()).toBe(false);
    } finally {
      external.exec("ROLLBACK");
      external.close();
    }
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("live-value");
  });

  it("stops an interrupted rollback while another SQLite client is writing", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    const backup = path.join(root, "busy-recovery-backup");
    createManagedBackup(backup);
    storeSecret("app", "prod", "API_KEY", "live-value");
    setRestoreFaultForTests("crash-after-first-publish");
    expect(() => restoreManagedBackup(backup)).toThrow(/Injected managed-restore crash/);
    setRestoreFaultForTests(null);

    const external = new Database(path.join(home, "vault.db"));
    external.exec("BEGIN IMMEDIATE");
    try {
      expect(() => recoverInterruptedManagedRestore()).toThrow(/busy|stop every external SQLite client|SQLite file open/i);
      expect(restoreJournalExists()).toBe(true);
    } finally {
      external.exec("ROLLBACK");
      external.close();
    }
    expect(recoverInterruptedManagedRestore()).toBe(true);
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("live-value");
  });

  it("stops on a quiescence I/O failure without creating restore state", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    const backup = path.join(root, "io-backup");
    createManagedBackup(backup);
    storeSecret("app", "prod", "API_KEY", "live-value");
    closeDb();
    clearKey();
    const failure = Object.assign(new Error("synthetic fsync failure"), { code: "EIO" });
    const fsync = vi.spyOn(fs, "fsyncSync").mockImplementationOnce(() => { throw failure; });
    expect(() => restoreManagedBackup(backup)).toThrow(/synthetic fsync failure/);
    fsync.mockRestore();
    expect(restoreJournalExists()).toBe(false);
    expect(fs.readdirSync(home).filter((name) => /^\.restore-(?:staging|previous|damaged-evidence)\./.test(name))).toEqual([]);
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("live-value");
  });

  it("rejects a recognized live file that appears during staging", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    const backup = path.join(root, "inventory-race-backup");
    createManagedBackup(backup);
    storeSecret("app", "prod", "API_KEY", "live-value");
    closeDb();
    clearKey();
    const originalCopy = fs.copyFileSync.bind(fs);
    let injected = false;
    const copy = vi.spyOn(fs, "copyFileSync").mockImplementation((source, destination, mode) => {
      originalCopy(source, destination, mode);
      if (!injected && String(source) === path.join(backup, "vault.db")) {
        injected = true;
        fs.writeFileSync(path.join(home, "strict-policy.v1.json"), "{}\n", { mode: 0o600 });
      }
    });
    try {
      expect(() => restoreManagedBackup(backup)).toThrow(/appeared during restore preparation/);
    } finally {
      copy.mockRestore();
    }
    expect(restoreJournalExists()).toBe(false);
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

  it("restores over a missing current key after excluding SQLite writers", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "restored-value");
    const backup = path.join(root, "missing-key-backup");
    createManagedBackup(backup);
    closeDb();
    clearKey();
    fs.unlinkSync(path.join(home, ".keyclasp.key"));
    restoreManagedBackup(backup);
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("restored-value");
  });

  it("restores over a non-canonical current v5 key bundle", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "restored-value");
    const backup = path.join(root, "corrupt-v5-backup");
    createManagedBackup(backup);
    closeDb();
    clearKey();
    fs.writeFileSync(path.join(home, ".keyclasp.key"), "keyclasp:v5\n{", { mode: 0o600 });
    restoreManagedBackup(backup);
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("restored-value");
  });

  it("quarantines an obsolete corrupt restore-journal key", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "restored-value");
    const backup = path.join(root, "corrupt-journal-key-backup");
    createManagedBackup(backup);
    fs.writeFileSync(path.join(home, ".restore-journal.key"), "x", { mode: 0o600 });

    const result = restoreManagedBackup(backup);
    expect(result.rollbackEvidencePath).toBeTruthy();
    expect(fs.readFileSync(path.join(result.rollbackEvidencePath!, ".restore-journal.key"), "utf8")).toBe("x");
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("restored-value");
  });

  it("uses a new transaction key when a pending restore key is corrupt", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    const backup = path.join(root, "pending-corrupt-key-backup");
    createManagedBackup(backup);
    storeSecret("app", "prod", "API_KEY", "live-value");
    setRestoreFaultForTests("crash-after-first-publish");
    expect(() => restoreManagedBackup(backup)).toThrow(/first staged publication/);
    setRestoreFaultForTests(null);
    const oldKey = fs.readdirSync(home).find((name) => name.startsWith(".restore-journal.v2."))!;
    fs.writeFileSync(path.join(home, oldKey), "x", { mode: 0o600 });

    const result = restoreManagedBackup(backup);
    expect(result.rollbackEvidencePath).toBeTruthy();
    expect(fs.readFileSync(path.join(result.rollbackEvidencePath!, oldKey), "utf8")).toBe("x");
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("backup-value");
  });

  it("uses a corrupt ordinary recovery journal only as quarantined rollback material", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "restored-value");
    const backup = path.join(root, "journal-backup");
    createManagedBackup(backup);
    storeSecret("app", "prod", "API_KEY", "live-value");
    const corruptJournal = Buffer.from("synthetic-corrupt-journal");
    fs.writeFileSync(path.join(home, ".restore-transaction.v1.json"), corruptJournal, { mode: 0o600 });

    const result = restoreManagedBackup(backup);
    expect(result.rollbackEvidencePath).toBeTruthy();
    expect(fs.readFileSync(path.join(result.rollbackEvidencePath!, ".restore-transaction.v1.json"))).toEqual(corruptJournal);
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("restored-value");
    expect(restoreJournalExists()).toBe(false);
  });

  it("cleans a transaction key and deterministic journal temp left before intent publication", () => {
    initializeVault("");
    const transactionId = "orphan";
    const keyName = `.restore-journal.v2.${transactionId}.key`;
    const temporaryName = `.restore-transaction.v2.${transactionId}.tmp`;
    fs.writeFileSync(path.join(home, keyName), crypto.randomBytes(32), { mode: 0o600 });
    fs.writeFileSync(path.join(home, temporaryName), "incomplete", { mode: 0o600 });

    expect(recoverInterruptedManagedRestore()).toBe(true);
    expect(fs.existsSync(path.join(home, keyName))).toBe(false);
    expect(fs.existsSync(path.join(home, temporaryName))).toBe(false);
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
      expect(restoreJournalExists()).toBe(true);
      setRestoreFaultForTests(null);
      expect(recoverInterruptedManagedRestore()).toBe(true);
      expect(resolveSecret("app", "prod", "API_KEY")).toBe("live-value");
      expect(restoreJournalExists()).toBe(false);
    });
  }

  it("cleans a partial staging copy left by process death", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    const backup = path.join(root, "partial-copy-backup");
    createManagedBackup(backup);
    storeSecret("app", "prod", "API_KEY", "live-value");
    setRestoreFaultForTests("crash-after-first-stage-copy");
    expect(() => restoreManagedBackup(backup)).toThrow(/first staged copy/);
    setRestoreFaultForTests(null);
    const stagingName = fs.readdirSync(home).find((name) => name.startsWith(".restore-staging."))!;
    const stagedDatabase = path.join(home, stagingName, "vault.db");
    const partialDatabase = `${stagedDatabase}.partial`;
    fs.renameSync(stagedDatabase, partialDatabase);
    fs.truncateSync(partialDatabase, 31);

    expect(recoverInterruptedManagedRestore()).toBe(true);
    expect(restoreJournalExists()).toBe(false);
    expect(fs.existsSync(path.join(home, stagingName))).toBe(false);
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("live-value");
  });

  it("recovers an interrupted restore in a fresh process after the faulting process exits", () => {
    initializeVault("restart-passphrase");
    storeSecret("app", "prod", "API_KEY", "backup-value", "interactive");
    const backup = path.join(root, "restart-backup");
    createManagedBackup(backup);
    storeSecret("app", "prod", "API_KEY", "live-value", "interactive");
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
    expect(restoreJournalExists()).toBe(true);

    const recovered = spawnSync(process.execPath, ["--input-type=module", "-e", [
      `import { recoverInterruptedManagedRestore } from ${JSON.stringify(recoveryUrl)};`,
      `import { unlockVault, resolveSecret } from ${JSON.stringify(vaultUrl)};`,
      "recoverInterruptedManagedRestore();",
      "unlockVault('restart-passphrase');",
      "process.stdout.write(resolveSecret('app', 'prod', 'API_KEY') ?? 'missing');",
    ].join("\n")], { encoding: "utf8", env: environment });
    expect(recovered.status, recovered.stderr).toBe(0);
    expect(recovered.stdout).toBe("live-value");
    expect(restoreJournalExists()).toBe(false);
  });

  it("does not replay an abruptly exited writer WAL over an authenticated backup", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    const backup = path.join(root, "wal-backup");
    createManagedBackup(backup);
    closeDb();
    clearKey();

    const vaultUrl = pathToFileURL(path.join(process.cwd(), "dist", "vault.js")).href;
    const writer = spawnSync(process.execPath, ["--input-type=module", "-e", [
      `import * as vault from ${JSON.stringify(vaultUrl)};`,
      "vault.setMachineIdentityForTests({ stable: Buffer.alloc(32, 3) });",
      "vault.storeSecret('app', 'prod', 'API_KEY', 'live-after-backup');",
      "process.exit(23);",
    ].join("\n")], { env: { ...process.env, KEYCLASP_HOME: home }, encoding: "utf8" });
    expect(writer.status, writer.stderr).toBe(23);
    expect(fs.existsSync(path.join(home, "vault.db-wal"))).toBe(true);

    restoreManagedBackup(backup);
    expect(fs.existsSync(path.join(home, "vault.db-wal"))).toBe(false);
    expect(fs.existsSync(path.join(home, "vault.db-shm"))).toBe(false);
    closeDb();
    clearKey();
    const reader = spawnSync(process.execPath, ["--input-type=module", "-e", [
      `import * as vault from ${JSON.stringify(vaultUrl)};`,
      "vault.setMachineIdentityForTests({ stable: Buffer.alloc(32, 3) });",
      "process.stdout.write(vault.resolveSecret('app', 'prod', 'API_KEY') === 'backup-value' ? 'MATCH' : 'MISMATCH');",
    ].join("\n")], { env: { ...process.env, KEYCLASP_HOME: home }, encoding: "utf8" });
    expect(reader.status, reader.stderr).toBe(0);
    expect(reader.stdout).toBe("MATCH");
  });

  it("restores the abruptly committed WAL value when publication rolls back", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    const backup = path.join(root, "wal-rollback-backup");
    createManagedBackup(backup);
    closeDb();
    clearKey();
    const vaultUrl = pathToFileURL(path.join(process.cwd(), "dist", "vault.js")).href;
    const writer = spawnSync(process.execPath, ["--input-type=module", "-e", [
      `import * as vault from ${JSON.stringify(vaultUrl)};`,
      "vault.setMachineIdentityForTests({ stable: Buffer.alloc(32, 3) });",
      "vault.storeSecret('app', 'prod', 'API_KEY', 'committed-in-wal');",
      "process.exit(23);",
    ].join("\n")], { env: { ...process.env, KEYCLASP_HOME: home }, encoding: "utf8" });
    expect(writer.status, writer.stderr).toBe(23);
    setRestoreFaultForTests("crash-after-all-published");
    expect(() => restoreManagedBackup(backup)).toThrow(/complete staged publication/);
    setRestoreFaultForTests(null);
    expect(recoverInterruptedManagedRestore()).toBe(true);
    closeDb();
    clearKey();

    const reader = spawnSync(process.execPath, ["--input-type=module", "-e", [
      `import * as vault from ${JSON.stringify(vaultUrl)};`,
      "vault.setMachineIdentityForTests({ stable: Buffer.alloc(32, 3) });",
      "process.stdout.write(vault.resolveSecret('app', 'prod', 'API_KEY') ?? 'missing');",
    ].join("\n")], { env: { ...process.env, KEYCLASP_HOME: home }, encoding: "utf8" });
    expect(reader.status, reader.stderr).toBe(0);
    expect(reader.stdout).toBe("committed-in-wal");
  });

  it("converges after two consecutive interruptions during rollback", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    const backup = path.join(root, "rollback-backup");
    createManagedBackup(backup);
    storeSecret("app", "prod", "API_KEY", "live-value");
    setRestoreFaultForTests("crash-after-all-published");
    expect(() => restoreManagedBackup(backup)).toThrow(/complete staged publication/);
    setRestoreFaultForTests(null);

    setRestoreOperationFaultForTests({ occurrence: 1, point: "after-mutation" });
    expect(() => recoverInterruptedManagedRestore()).toThrow(/after-mutation interruption/);
    setRestoreOperationFaultForTests({ occurrence: 1, point: "after-completion" });
    expect(() => recoverInterruptedManagedRestore()).toThrow(/after-completion interruption/);
    setRestoreOperationFaultForTests(null);
    expect(recoverInterruptedManagedRestore()).toBe(true);
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("live-value");
    expect(fs.readdirSync(home).some((name) => /^\.restore-(?:transaction|staging|previous)\./.test(name))).toBe(false);
  });

  it("resumes in a fresh process after rollback cleanup unlinks a staged database", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    const backup = path.join(root, "cleanup-backup");
    createManagedBackup(backup);
    storeSecret("app", "prod", "API_KEY", "live-value");
    setRestoreFaultForTests("crash-after-all-published");
    expect(() => restoreManagedBackup(backup)).toThrow(/complete staged publication/);
    setRestoreFaultForTests(null);
    const journalName = fs.readdirSync(home).find((name) => name.startsWith(".restore-transaction.v2."))!;
    const renameCount = JSON.parse(fs.readFileSync(path.join(home, journalName), "utf8")).operations.length as number;
    const recoveryUrl = pathToFileURL(path.join(process.cwd(), "dist", "recovery.js")).href;
    const environment = { ...process.env, KEYCLASP_HOME: home };
    const interrupted = spawnSync(process.execPath, ["--input-type=module", "-e", [
      `import { recoverInterruptedManagedRestore, setRestoreOperationFaultForTests } from ${JSON.stringify(recoveryUrl)};`,
      `setRestoreOperationFaultForTests({ occurrence: ${renameCount + 1}, point: 'after-mutation' });`,
      "try { recoverInterruptedManagedRestore(); } catch { process.exit(23); }",
      "process.exit(24);",
    ].join("\n")], { encoding: "utf8", env: environment });
    expect(interrupted.status, interrupted.stderr).toBe(23);
    expect(restoreJournalExists()).toBe(true);

    const recovered = spawnSync(process.execPath, ["--input-type=module", "-e", [
      `import { recoverInterruptedManagedRestore } from ${JSON.stringify(recoveryUrl)};`,
      "recoverInterruptedManagedRestore();",
    ].join("\n")], { encoding: "utf8", env: environment });
    expect(recovered.status, recovered.stderr).toBe(0);
    expect(restoreJournalExists()).toBe(false);
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("live-value");
  });

  it("reconciles every rollback rename at all three operation boundaries in fresh processes", () => {
    const recoveryUrl = pathToFileURL(path.join(process.cwd(), "dist", "recovery.js")).href;
    for (const point of ["before-mutation", "after-mutation", "after-completion"] as const) {
      for (const occurrence of [1, 2, 3, 4]) {
        closeDb();
        clearKey();
        home = path.join(root, `rename-${point}-${occurrence}`);
        process.env.KEYCLASP_HOME = home;
        initializeVault("");
        storeSecret("app", "prod", "API_KEY", "backup-value");
        const backup = path.join(root, `rename-backup-${point}-${occurrence}`);
        createManagedBackup(backup);
        storeSecret("app", "prod", "API_KEY", "live-value");
        setRestoreFaultForTests("crash-after-all-published");
        expect(() => restoreManagedBackup(backup)).toThrow(/complete staged publication/);
        setRestoreFaultForTests(null);
        const journalName = fs.readdirSync(home).find((name) => name.startsWith(".restore-transaction.v2."))!;
        expect(JSON.parse(fs.readFileSync(path.join(home, journalName), "utf8")).operations).toHaveLength(4);

        const interrupted = spawnSync(process.execPath, ["--input-type=module", "-e", [
          `import { recoverInterruptedManagedRestore, setRestoreOperationFaultForTests } from ${JSON.stringify(recoveryUrl)};`,
          `setRestoreOperationFaultForTests({ occurrence: ${occurrence}, point: ${JSON.stringify(point)} });`,
          "try { recoverInterruptedManagedRestore(); } catch { process.exit(23); }",
          "process.exit(24);",
        ].join("\n")], { encoding: "utf8", env: { ...process.env, KEYCLASP_HOME: home } });
        expect(interrupted.status, interrupted.stderr).toBe(23);
        expect(recoverInterruptedManagedRestore()).toBe(true);
        expect(resolveSecret("app", "prod", "API_KEY")).toBe("live-value");
      }
    }
  }, 120_000);

  it("reconciles each rollback cleanup unlink at all three operation boundaries", () => {
    const recoveryUrl = pathToFileURL(path.join(process.cwd(), "dist", "recovery.js")).href;
    for (const point of ["before-mutation", "after-mutation", "after-completion"] as const) {
      for (const unlinkOccurrence of [1, 2]) {
        closeDb();
        clearKey();
        home = path.join(root, `unlink-${point}-${unlinkOccurrence}`);
        process.env.KEYCLASP_HOME = home;
        initializeVault("");
        storeSecret("app", "prod", "API_KEY", "backup-value");
        const backup = path.join(root, `unlink-backup-${point}-${unlinkOccurrence}`);
        createManagedBackup(backup);
        storeSecret("app", "prod", "API_KEY", "live-value");
        setRestoreFaultForTests("crash-after-all-published");
        expect(() => restoreManagedBackup(backup)).toThrow(/complete staged publication/);
        setRestoreFaultForTests(null);
        const journalName = fs.readdirSync(home).find((name) => name.startsWith(".restore-transaction.v2."))!;
        const renameCount = JSON.parse(fs.readFileSync(path.join(home, journalName), "utf8")).operations.length as number;

        const interrupted = spawnSync(process.execPath, ["--input-type=module", "-e", [
          `import { recoverInterruptedManagedRestore, setRestoreOperationFaultForTests } from ${JSON.stringify(recoveryUrl)};`,
          `setRestoreOperationFaultForTests({ occurrence: ${renameCount + unlinkOccurrence}, point: ${JSON.stringify(point)} });`,
          "try { recoverInterruptedManagedRestore(); } catch { process.exit(23); }",
          "process.exit(24);",
        ].join("\n")], { encoding: "utf8", env: { ...process.env, KEYCLASP_HOME: home } });
        expect(interrupted.status, interrupted.stderr).toBe(23);
        expect(recoverInterruptedManagedRestore()).toBe(true);
        expect(resolveSecret("app", "prod", "API_KEY")).toBe("live-value");
      }
    }
  }, 120_000);

  it("recovers in a fresh process from every indexed restore primitive boundary", () => {
    const recoveryUrl = pathToFileURL(path.join(process.cwd(), "dist", "recovery.js")).href;
    const vaultUrl = pathToFileURL(path.join(process.cwd(), "dist", "vault.js")).href;
    const topologyNames = ["vault.db", "vault.db-wal", "vault.db-shm", ".keyclasp.key", "strict-policy.v1.json", ".strict-policy.key"];
    const snapshot = (directory: string): Record<string, string | null> => Object.fromEntries(topologyNames.map((name) => {
      const file = path.join(directory, name);
      return [name, fs.existsSync(file) ? crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex") : null];
    }));

    const backupHome = path.join(root, "primitive-backup-home");
    home = backupHome;
    process.env.KEYCLASP_HOME = home;
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    setAuthorizationRule({ project: "app" }, false);
    const countBackup = path.join(root, "primitive-count-backup");
    createManagedBackup(countBackup);
    const completeNewState = snapshot(countBackup);
    closeDb();
    clearKey();

    const liveTemplate = path.join(root, "primitive-live-template");
    home = liveTemplate;
    process.env.KEYCLASP_HOME = home;
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "live-value");
    setAuthorizationRule({ environment: "prod" }, false);
    closeDb();
    clearKey();
    const writer = spawnSync(process.execPath, ["--input-type=module", "-e", [
      `import { setMachineIdentityForTests, storeSecret } from ${JSON.stringify(vaultUrl)};`,
      "setMachineIdentityForTests({ stable: Buffer.alloc(32, 3) });",
      "storeSecret('app', 'prod', 'API_KEY', 'live-wal-value');",
      "process.exit(23);",
    ].join("\n")], { encoding: "utf8", env: { ...process.env, KEYCLASP_HOME: liveTemplate } });
    expect(writer.status, writer.stderr).toBe(23);
    expect(fs.existsSync(path.join(liveTemplate, "vault.db-wal"))).toBe(true);
    expect(fs.existsSync(path.join(liveTemplate, "vault.db-shm"))).toBe(true);
    const completeOldState = snapshot(liveTemplate);
    expect(completeOldState[".keyclasp.key"]).not.toBe(completeNewState[".keyclasp.key"]);
    expect(completeOldState["strict-policy.v1.json"]).not.toBe(completeNewState["strict-policy.v1.json"]);

    home = path.join(root, "primitive-count-home");
    process.env.KEYCLASP_HOME = home;
    fs.cpSync(liveTemplate, home, { recursive: true });
    setRestorePrimitiveFaultForTests(null);
    restoreManagedBackup(countBackup);
    const counts = getRestorePrimitiveCountsForTests();
    expect(Object.keys(counts).sort()).toEqual(["copy", "directory-cleanup", "journal", "rename", "sync", "unlink", "validation"]);
    expect(Object.values(counts).every((count) => count > 0)).toBe(true);
    fs.rmSync(home, { recursive: true, force: true });

    for (const [primitive, count] of Object.entries(counts)) {
      for (const point of ["before-mutation", "after-mutation", "after-completion"] as const) {
        for (let occurrence = 1; occurrence <= count!; occurrence += 1) {
          closeDb();
          clearKey();
          const caseName = `${primitive}-${point}-${occurrence}`;
          home = path.join(root, `primitive-${caseName}`);
          process.env.KEYCLASP_HOME = home;
          fs.cpSync(liveTemplate, home, { recursive: true });

          const interrupted = spawnSync(process.execPath, ["--input-type=module", "-e", [
            `import { restoreManagedBackup, setRestorePrimitiveFaultForTests, wasRestorePrimitiveFaultTriggeredForTests } from ${JSON.stringify(recoveryUrl)};`,
            `import { setMachineIdentityForTests } from ${JSON.stringify(vaultUrl)};`,
            "setMachineIdentityForTests({ stable: Buffer.alloc(32, 3) });",
            `setRestorePrimitiveFaultForTests({ primitive: ${JSON.stringify(primitive)}, occurrence: ${occurrence}, point: ${JSON.stringify(point)} });`,
            `try { restoreManagedBackup(${JSON.stringify(countBackup)}); } catch { if (wasRestorePrimitiveFaultTriggeredForTests()) process.exit(23); throw new Error('Unexpected restore failure'); }`,
            "if (wasRestorePrimitiveFaultTriggeredForTests()) process.exit(23);",
            "process.exit(24);",
          ].join("\n")], { encoding: "utf8", env: { ...process.env, KEYCLASP_HOME: home } });
          expect(interrupted.status, `${caseName}: ${interrupted.stderr}`).toBe(23);

          const recovered = spawnSync(process.execPath, ["--input-type=module", "-e", [
            `import { recoverInterruptedManagedRestore } from ${JSON.stringify(recoveryUrl)};`,
            "recoverInterruptedManagedRestore();",
          ].join("\n")], { encoding: "utf8", env: { ...process.env, KEYCLASP_HOME: home } });
          expect(recovered.status, `${caseName}: ${recovered.stderr}`).toBe(0);
          const recoveredState = snapshot(home);
          expect(
            [JSON.stringify(completeOldState), JSON.stringify(completeNewState)],
            `${caseName}: mixed managed-file generation`,
          ).toContain(JSON.stringify(recoveredState));
          expect(fs.readdirSync(home).some((name) => /^\.restore-(?:transaction|journal\.v2|staging|previous)\./.test(name))).toBe(false);
          const readback = spawnSync(process.execPath, ["--input-type=module", "-e", [
            `import { resolveSecret, setMachineIdentityForTests } from ${JSON.stringify(vaultUrl)};`,
            "setMachineIdentityForTests({ stable: Buffer.alloc(32, 3) });",
            "const value = resolveSecret('app', 'prod', 'API_KEY');",
            "if (value !== 'live-wal-value' && value !== 'backup-value') process.exit(25);",
          ].join("\n")], { encoding: "utf8", env: { ...process.env, KEYCLASP_HOME: home } });
          expect(readback.status, `${caseName}: ${readback.stderr}`).toBe(0);
          fs.rmSync(home, { recursive: true, force: true });
        }
      }
    }
  }, 1_800_000);

  it("quarantines every pending v2 transaction file during emergency restore", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    const backup = path.join(root, "pending-backup");
    createManagedBackup(backup);
    storeSecret("app", "prod", "API_KEY", "live-value");
    setRestoreFaultForTests("crash-after-first-publish");
    expect(() => restoreManagedBackup(backup)).toThrow(/Injected managed-restore crash/);
    setRestoreFaultForTests(null);
    const oldJournal = fs.readdirSync(home).find((name) => name.startsWith(".restore-transaction.v2."))!;
    const oldTransactionId = oldJournal.slice(".restore-transaction.v2.".length, -".json".length);
    const oldPaths = [`.restore-staging.${oldTransactionId}`, `.restore-previous.${oldTransactionId}`];
    expect(oldPaths.every((name) => fs.existsSync(path.join(home, name)))).toBe(true);

    const result = restoreManagedBackup(backup);
    expect(result.rollbackEvidencePath).toBeTruthy();
    expect(fs.existsSync(path.join(result.rollbackEvidencePath!, oldJournal))).toBe(true);
    for (const oldPath of oldPaths) {
      expect(fs.existsSync(path.join(home, oldPath))).toBe(false);
      expect(fs.existsSync(path.join(result.rollbackEvidencePath!, oldPath))).toBe(true);
    }
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("backup-value");
  });

  it("rolls back an interrupted emergency restore before resuming the prior transaction", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    const backup = path.join(root, "nested-recovery-backup");
    createManagedBackup(backup);
    storeSecret("app", "prod", "API_KEY", "live-value");
    setRestoreFaultForTests("crash-after-first-publish");
    expect(() => restoreManagedBackup(backup)).toThrow(/first staged publication/);
    const oldJournal = fs.readdirSync(home).find((name) => name.startsWith(".restore-transaction.v2."))!;

    setRestoreFaultForTests("crash-after-all-published");
    expect(() => restoreManagedBackup(backup)).toThrow(/complete staged publication/);
    setRestoreFaultForTests(null);
    expect(fs.readdirSync(home).filter((name) => name.startsWith(".restore-transaction.v2.")).length).toBe(1);

    expect(recoverInterruptedManagedRestore()).toBe(true);
    expect(fs.existsSync(path.join(home, oldJournal))).toBe(true);
    expect(fs.readdirSync(home).filter((name) => name.startsWith(".restore-transaction.v2.")).length).toBe(1);
    expect(recoverInterruptedManagedRestore()).toBe(true);
    expect(restoreJournalExists()).toBe(false);
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("live-value");
  });

  it("recursively quarantines two interrupted transaction topologies on a third restore", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    const backup = path.join(root, "recursive-emergency-backup");
    createManagedBackup(backup);
    storeSecret("app", "prod", "API_KEY", "live-value");
    setRestoreFaultForTests("crash-after-first-publish");
    expect(() => restoreManagedBackup(backup)).toThrow(/first staged publication/);

    setRestoreFaultForTests("crash-after-journal");
    expect(() => restoreManagedBackup(backup)).toThrow(/journal publication/);
    setRestoreFaultForTests(null);
    expect(fs.readdirSync(home).filter((name) => name.startsWith(".restore-transaction.v2.")).length).toBe(2);

    const result = restoreManagedBackup(backup);
    expect(result.rollbackEvidencePath).toBeTruthy();
    const retainedEvidence = path.basename(result.rollbackEvidencePath!);
    expect(fs.readdirSync(home).some((name) => name !== retainedEvidence && /^\.restore-(?:transaction|journal\.v2|staging|previous|damaged-evidence)\./.test(name))).toBe(false);
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("backup-value");
  });

  it("quarantines a damaged raw DB, WAL, and SHM before publishing the backup", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    const backup = path.join(root, "damaged-backup");
    createManagedBackup(backup);
    closeDb();
    clearKey();
    const damaged = {
      "vault.db": Buffer.from("not-a-database"),
      "vault.db-wal": Buffer.from("damaged-wal"),
      "vault.db-shm": Buffer.from("damaged-shm"),
    };
    for (const [name, contents] of Object.entries(damaged)) {
      fs.writeFileSync(path.join(home, name), contents, { mode: 0o600 });
    }

    const result = restoreManagedBackup(backup);
    expect(result.rollbackEvidencePath).toBeTruthy();
    for (const [name, contents] of Object.entries(damaged)) {
      expect(fs.readFileSync(path.join(result.rollbackEvidencePath!, name))).toEqual(contents);
    }
    expect(fs.existsSync(path.join(home, "vault.db-wal"))).toBe(false);
    expect(fs.existsSync(path.join(home, "vault.db-shm"))).toBe(false);
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("backup-value");
  });

  it("quarantines a valid-header database that SQLite reports as NOTADB", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    const backup = path.join(root, "notadb-backup");
    createManagedBackup(backup);
    closeDb();
    clearKey();
    const invalid = crypto.randomBytes(4096);
    Buffer.from("SQLite format 3\0", "binary").copy(invalid);
    fs.writeFileSync(path.join(home, "vault.db"), invalid, { mode: 0o600 });

    const result = restoreManagedBackup(backup);
    expect(result.rollbackEvidencePath).toBeTruthy();
    expect(fs.readFileSync(path.join(result.rollbackEvidencePath!, "vault.db"))).toEqual(invalid);
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("backup-value");
  });

  it("quarantines a valid SQLite vault whose metadata schema is missing a required column", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    const backup = path.join(root, "malformed-schema-backup");
    createManagedBackup(backup);
    closeDb();
    clearKey();
    const database = new Database(path.join(home, "vault.db"));
    database.exec(`
      ALTER TABLE vault_metadata RENAME TO vault_metadata_original;
      CREATE TABLE vault_metadata (
        singleton INTEGER PRIMARY KEY,
        vault_id BLOB NOT NULL,
        bundle_generation INTEGER NOT NULL,
        bundle_hash BLOB NOT NULL,
        machine_key_check_iv BLOB NOT NULL,
        machine_key_check_tag BLOB NOT NULL,
        interactive_key_check_iv BLOB,
        interactive_key_check_tag BLOB,
        interactive_key_present INTEGER NOT NULL
      );
      INSERT INTO vault_metadata
      SELECT singleton, vault_id, bundle_generation, bundle_hash,
             machine_key_check_iv, machine_key_check_tag,
             interactive_key_check_iv, interactive_key_check_tag, interactive_key_present
      FROM vault_metadata_original;
      DROP TABLE vault_metadata_original;
    `);
    database.close();
    const malformed = fs.readFileSync(path.join(home, "vault.db"));

    const result = restoreManagedBackup(backup);

    expect(result.rollbackEvidencePath).toBeTruthy();
    expect(fs.readFileSync(path.join(result.rollbackEvidencePath!, "vault.db"))).toEqual(malformed);
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("backup-value");
  });

  it("preserves abrupt-writer DB, WAL, and SHM bytes when the live key is corrupt", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    const backup = path.join(root, "corrupt-key-wal-backup");
    createManagedBackup(backup);
    closeDb();
    clearKey();
    const vaultUrl = pathToFileURL(path.join(process.cwd(), "dist", "vault.js")).href;
    const writer = spawnSync(process.execPath, ["--input-type=module", "-e", [
      `import * as vault from ${JSON.stringify(vaultUrl)};`,
      "vault.setMachineIdentityForTests({ stable: Buffer.alloc(32, 3) });",
      "vault.storeSecret('app', 'prod', 'API_KEY', 'committed-in-wal');",
      "process.exit(23);",
    ].join("\n")], { env: { ...process.env, KEYCLASP_HOME: home }, encoding: "utf8" });
    expect(writer.status, writer.stderr).toBe(23);
    fs.writeFileSync(path.join(home, ".keyclasp.key"), "corrupt", { mode: 0o600 });
    const raw = Object.fromEntries(["vault.db", "vault.db-wal", "vault.db-shm"]
      .filter((name) => fs.existsSync(path.join(home, name)))
      .map((name) => [name, fs.readFileSync(path.join(home, name))]));
    expect(Object.keys(raw)).toContain("vault.db-wal");

    const result = restoreManagedBackup(backup);
    expect(result.rollbackEvidencePath).toBeTruthy();
    for (const [name, contents] of Object.entries(raw)) {
      expect(fs.readFileSync(path.join(result.rollbackEvidencePath!, name))).toEqual(contents);
    }
  });

  it("finishes durable cleanup after a committed restore is interrupted", () => {
    initializeVault("");
    storeSecret("app", "prod", "API_KEY", "backup-value");
    const backup = path.join(root, "backup");
    createManagedBackup(backup);
    storeSecret("app", "prod", "API_KEY", "live-value");
    setRestoreFaultForTests("crash-after-commit-journal");
    expect(() => restoreManagedBackup(backup)).toThrow(/commit journal/);
    expect(restoreJournalExists()).toBe(true);
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
    fs.writeFileSync(path.join(home, `.restore-transaction.v2.${transactionId}.json`), `${JSON.stringify({
      version: 2,
      phase: "publishing",
      branch: "healthy",
      transactionId,
      stagingDirectory: `.restore-staging.${transactionId}`,
      previousDirectory: `.restore-previous.${transactionId}`,
      transactionDirectories: [],
      previousHashes: {},
      stagedHashes: {},
      operations: [],
      mac: "forged",
    })}\n`, { mode: 0o600 });
    expect(() => recoverInterruptedManagedRestore()).toThrow(/transaction key is missing|failed authentication/i);
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("live-value");
  });

  it("keeps passphrase backups portable across a machine-identity change", () => {
    initializeVault("portable-passphrase");
    unlockVault("portable-passphrase");
    storeSecret("app", "prod", "API_KEY", "portable-value", "interactive");
    const backup = path.join(root, "backup");
    createManagedBackup(backup);
    setMachineIdentityForTests({ stable: Buffer.alloc(32, 9) });
    restoreManagedBackup(backup, "portable-passphrase");
    unlockVault("portable-passphrase");
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("portable-value");
  });

  it("cleans converted portable staging files after process death", () => {
    initializeVault("portable-passphrase");
    unlockVault("portable-passphrase");
    storeSecret("app", "prod", "API_KEY", "portable-value", "interactive");
    const backup = path.join(root, "portable-crash-backup");
    createManagedBackup(backup);
    setMachineIdentityForTests({ stable: Buffer.alloc(32, 9) });
    setRestoreFaultForTests("crash-during-portable-conversion");
    expect(() => restoreManagedBackup(backup, "portable-passphrase")).toThrow(/portable conversion/);
    setRestoreFaultForTests(null);

    expect(recoverInterruptedManagedRestore()).toBe(true);
    expect(restoreJournalExists()).toBe(false);
    expect(fs.readdirSync(home).some((name) => name.startsWith(".restore-staging."))).toBe(false);
  });

  it("cleans portable SQLite sidecars after fresh-process death inside conversion", () => {
    initializeVault("portable-passphrase");
    unlockVault("portable-passphrase");
    storeSecret("app", "prod", "API_KEY", "portable-value", "interactive");
    const backup = path.join(root, "portable-open-crash-backup");
    createManagedBackup(backup);
    setMachineIdentityForTests({ stable: Buffer.alloc(32, 9) });
    closeDb();
    clearKey();
    const recoveryUrl = pathToFileURL(path.join(process.cwd(), "dist", "recovery.js")).href;
    const vaultUrl = pathToFileURL(path.join(process.cwd(), "dist", "vault.js")).href;
    const crashed = spawnSync(process.execPath, ["--input-type=module", "-e", [
      `import { restoreManagedBackup, setRestoreFaultForTests } from ${JSON.stringify(recoveryUrl)};`,
      `import { setMachineIdentityForTests } from ${JSON.stringify(vaultUrl)};`,
      "setMachineIdentityForTests({ stable: Buffer.alloc(32, 9) });",
      "setRestoreFaultForTests('crash-during-open-portable-conversion');",
      `restoreManagedBackup(${JSON.stringify(backup)}, 'portable-passphrase');`,
    ].join("\n")], { encoding: "utf8", env: { ...process.env, KEYCLASP_HOME: home } });
    expect(crashed.status, crashed.stderr).toBe(23);
    const stagingName = fs.readdirSync(home).find((name) => name.startsWith(".restore-staging."))!;
    const possibleSidecars = ["vault.db.portable-journal", "vault.db.portable-wal", "vault.db.portable-shm"];
    expect(possibleSidecars.some((name) => fs.existsSync(path.join(home, stagingName, name)))).toBe(true);

    expect(recoverInterruptedManagedRestore()).toBe(true);
    expect(restoreJournalExists()).toBe(false);
    expect(fs.readdirSync(home).some((name) => name.startsWith(".restore-staging."))).toBe(false);
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

  it("backs up and restores a mixed dual-key vault on its source machine", () => {
    initializeVault("mixed-passphrase");
    storeSecret("app", "prod", "MACHINE_KEY", "machine-before");
    storeSecret("app", "prod", "INTERACTIVE_KEY", "interactive-before", "interactive");
    const backup = path.join(root, "mixed-backup");
    createManagedBackup(backup);
    const manifest = JSON.parse(fs.readFileSync(path.join(backup, "backup.json"), "utf8"));
    expect(manifest).toMatchObject({
      version: 2,
      custody: "dual-key",
      recordClasses: { machine: 1, interactive: 1 },
    });
    expect(Object.keys(manifest.authenticators).sort()).toEqual(["interactive", "machine"]);

    storeSecret("app", "prod", "MACHINE_KEY", "machine-after");
    storeSecret("app", "prod", "INTERACTIVE_KEY", "interactive-after", "interactive");
    restoreManagedBackup(backup, "mixed-passphrase");
    unlockVault("mixed-passphrase");
    expect(resolveSecret("app", "prod", "MACHINE_KEY")).toBe("machine-before");
    expect(resolveSecret("app", "prod", "INTERACTIVE_KEY")).toBe("interactive-before");
    expect(readSecretKeyClass("app", "prod", "MACHINE_KEY")).toBe("machine");
    expect(readSecretKeyClass("app", "prod", "INTERACTIVE_KEY")).toBe("interactive");
  });

  it("rejects a copied mixed backup without changing the live target vault", () => {
    initializeVault("mixed-copy-passphrase");
    storeSecret("app", "prod", "MACHINE_KEY", "source-machine");
    storeSecret("app", "prod", "INTERACTIVE_KEY", "source-interactive", "interactive");
    const backup = path.join(root, "mixed-copy-backup");
    createManagedBackup(backup);

    closeDb();
    clearKey();
    setMachineIdentityForTests({ stable: Buffer.alloc(32, 9) });
    home = path.join(root, "mixed-copy-target");
    process.env.KEYCLASP_HOME = home;
    initializeVault("");
    storeSecret("app", "prod", "LIVE_KEY", "target-live");
    closeDb();
    clearKey();
    const before = Object.fromEntries(["vault.db", ".keyclasp.key"].map((name) => [name, crypto.createHash("sha256").update(fs.readFileSync(path.join(home, name))).digest("hex")]));

    expect(() => restoreManagedBackup(backup, "mixed-copy-passphrase")).toThrow(/cannot be unlocked on the current machine/i);

    const after = Object.fromEntries(["vault.db", ".keyclasp.key"].map((name) => [name, crypto.createHash("sha256").update(fs.readFileSync(path.join(home, name))).digest("hex")]));
    expect(after).toEqual(before);
    expect(resolveSecret("app", "prod", "LIVE_KEY")).toBe("target-live");
  });

  it("restores an all-interactive backup on another machine with fresh machine custody", () => {
    initializeVault("portable-interactive-passphrase");
    storeSecret("app", "prod", "INTERACTIVE_KEY", "portable-interactive", "interactive");
    const backup = path.join(root, "all-interactive-backup");
    createManagedBackup(backup);
    const sourceBundle = fs.readFileSync(path.join(backup, ".keyclasp.key"));
    const sourceDb = new Database(path.join(backup, "vault.db"), { readonly: true });
    const sourceRow = sourceDb.prepare("SELECT key_class, encrypted_value, iv, auth_tag FROM secrets WHERE name = 'INTERACTIVE_KEY'").get() as {
      key_class: string; encrypted_value: Buffer; iv: Buffer; auth_tag: Buffer;
    };
    sourceDb.close();

    closeDb();
    clearKey();
    setMachineIdentityForTests({ stable: Buffer.alloc(32, 9) });
    home = path.join(root, "all-interactive-target");
    process.env.KEYCLASP_HOME = home;
    initializeVault("");
    storeSecret("app", "prod", "LIVE_KEY", "replace-me");

    restoreManagedBackup(backup, "portable-interactive-passphrase");
    unlockVault("portable-interactive-passphrase");
    expect(resolveSecret("app", "prod", "INTERACTIVE_KEY")).toBe("portable-interactive");
    expect(readSecretKeyClass("app", "prod", "INTERACTIVE_KEY")).toBe("interactive");
    const restoredDb = new Database(path.join(home, "vault.db"), { readonly: true });
    const restoredRow = restoredDb.prepare("SELECT key_class, encrypted_value, iv, auth_tag FROM secrets WHERE name = 'INTERACTIVE_KEY'").get() as typeof sourceRow;
    restoredDb.close();
    expect(restoredRow).toEqual(sourceRow);
    expect(fs.readFileSync(path.join(home, ".keyclasp.key"))).not.toEqual(sourceBundle);
  });

  it("rejects missing and modified class authenticators before changing live state", () => {
    initializeVault("class-auth-passphrase");
    storeSecret("app", "prod", "INTERACTIVE_KEY", "backup-value", "interactive");
    const omitted = path.join(root, "omitted-auth-backup");
    createManagedBackup(omitted);
    storeSecret("app", "prod", "INTERACTIVE_KEY", "live-value", "interactive");
    const omittedPath = path.join(omitted, "backup.json");
    const omittedManifest = JSON.parse(fs.readFileSync(omittedPath, "utf8"));
    delete omittedManifest.authenticators.interactive;
    fs.writeFileSync(omittedPath, `${JSON.stringify(omittedManifest, null, 2)}\n`);
    expect(() => restoreManagedBackup(omitted, "class-auth-passphrase")).toThrow(/invalid key-class authenticators/i);
    expect(resolveSecret("app", "prod", "INTERACTIVE_KEY")).toBe("live-value");

    const tampered = path.join(root, "tampered-auth-backup");
    createManagedBackup(tampered);
    const tamperedPath = path.join(tampered, "backup.json");
    const tamperedManifest = JSON.parse(fs.readFileSync(tamperedPath, "utf8"));
    const authentic = Buffer.from(tamperedManifest.authenticators.interactive, "base64");
    authentic[0] ^= 0xff;
    tamperedManifest.authenticators.interactive = authentic.toString("base64");
    fs.writeFileSync(tamperedPath, `${JSON.stringify(tamperedManifest, null, 2)}\n`);
    expect(() => restoreManagedBackup(tampered, "class-auth-passphrase")).toThrow(/manifest failed authentication/i);
    expect(resolveSecret("app", "prod", "INTERACTIVE_KEY")).toBe("live-value");
  });
});
