import { afterEach, beforeEach, describe, expect, it } from "vitest";
import Database from "better-sqlite3";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  clearKey,
  closeDb,
  enrollInteractivePassphrase,
  encrypt,
  getKey,
  getVaultDescriptor,
  initializeVault,
  isInteractiveKeyUnlocked,
  readKeyAccessCountsForTests,
  readSecretKeyClass,
  needsDualKeyMigration,
  recoverInterruptedDualKeyMigration,
  migrateLegacyVaultToDualKey,
  recoverInterruptedCustodyTransition,
  resetKeyAccessCountsForTests,
  resolveSecret,
  rotateInteractivePassphrase,
  setCustodyFaultForTests,
  setDualKeyMigrationFaultForTests,
  setMachineIdentityForTests,
  storeSecret,
  transitionRecordCustody,
  unlockVault,
  writeLegacyV3KeyFileForTests,
} from "../src/vault.js";
import { evaluateAuthorizationRules, mutateAuthorizationRule } from "../src/policy.js";
import { createSoftwareRunRuntime } from "../src/software/runtime.js";

describe("dual-key software custody", () => {
  let root: string;
  let home: string;
  let previousHome: string | undefined;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-dual-key-"));
    home = path.join(root, ".keyclasp");
    previousHome = process.env.KEYCLASP_HOME;
    process.env.KEYCLASP_HOME = home;
    closeDb();
    clearKey();
    setMachineIdentityForTests({ stable: Buffer.alloc(32, 41) });
  });

  afterEach(() => {
    closeDb();
    clearKey();
    setCustodyFaultForTests(null);
    setDualKeyMigrationFaultForTests(null);
    setMachineIdentityForTests(null);
    if (previousHome === undefined) delete process.env.KEYCLASP_HOME;
    else process.env.KEYCLASP_HOME = previousHome;
    fs.rmSync(root, { recursive: true, force: true });
  });

  function mutate(action: "lock" | "unlock" | "inherit"): void {
    mutateAuthorizationRule({ project: "app", environment: "prod", secret: "API_KEY" }, action, (db, rules) => {
      transitionRecordCustody(db, rules, evaluateAuthorizationRules);
    });
  }

  function replaceWithLegacyV3(passphrase: string): void {
    initializeVault("");
    const key = getKey();
    writeLegacyV3KeyFileForTests(key, passphrase);
    closeDb();
    const database = new Database(path.join(home, "vault.db"));
    database.exec("DROP TABLE secrets; DROP TABLE vault_metadata");
    database.exec(`CREATE TABLE secrets (
      project TEXT NOT NULL, environment TEXT NOT NULL, name TEXT NOT NULL,
      encrypted_value BLOB NOT NULL, iv BLOB NOT NULL, auth_tag BLOB NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (project, environment, name)
    )`);
    const insert = database.prepare("INSERT INTO secrets (project, environment, name, encrypted_value, iv, auth_tag) VALUES (?, ?, ?, ?, ?, ?)");
    for (const [name, value] of [["MACHINE", "machine-value"], ["LOCKED", "locked-value"]]) {
      const encrypted = encrypt(value, key);
      insert.run("app", "prod", name, encrypted.encrypted, encrypted.iv, encrypted.authTag);
    }
    database.close();
    clearKey();
    if (passphrase) unlockVault(passphrase);
    else getKey();
    closeDb();
    clearKey();
  }

  it("initializes machine-only or dual-key state with machine-class default records", () => {
    initializeVault("");
    expect(getVaultDescriptor().custody).toBe("machine-only");
    storeSecret("app", "prod", "API_KEY", "machine-value");
    expect(readSecretKeyClass("app", "prod", "API_KEY")).toBe("machine");

    closeDb();
    clearKey();
    fs.rmSync(home, { recursive: true, force: true });
    initializeVault("interactive-passphrase");
    expect(getVaultDescriptor().custody).toBe("dual-key");
    expect(isInteractiveKeyUnlocked()).toBe(true);
  });

  it("makes machine-key possession insufficient for an interactive record and authenticates key_class", () => {
    initializeVault("interactive-passphrase");
    storeSecret("app", "prod", "API_KEY", "interactive-value");
    mutate("lock");
    expect(readSecretKeyClass("app", "prod", "API_KEY")).toBe("interactive");

    clearKey();
    getKey();
    expect(() => resolveSecret("app", "prod", "API_KEY")).toThrow(/locked/i);
    unlockVault("interactive-passphrase");
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("interactive-value");

    closeDb();
    const database = new Database(path.join(home, "vault.db"));
    database.prepare("UPDATE secrets SET key_class = 'machine' WHERE name = 'API_KEY'").run();
    database.close();
    clearKey();
    expect(() => resolveSecret("app", "prod", "API_KEY")).toThrow(/authenticate|Unsupported state/i);
  });

  it("moves custody through lock, unlock, and inherit fallback", () => {
    initializeVault("interactive-passphrase");
    storeSecret("app", "prod", "API_KEY", "value");
    mutateAuthorizationRule({ project: "app" }, "lock", (db, rules) => {
      transitionRecordCustody(db, rules, evaluateAuthorizationRules);
    });
    expect(readSecretKeyClass("app", "prod", "API_KEY")).toBe("interactive");
    mutate("unlock");
    expect(readSecretKeyClass("app", "prod", "API_KEY")).toBe("machine");
    mutate("inherit");
    expect(readSecretKeyClass("app", "prod", "API_KEY")).toBe("interactive");
  });

  it("does not unwrap or decrypt the interactive path for a machine-class resolution", () => {
    initializeVault("interactive-passphrase");
    storeSecret("app", "prod", "API_KEY", "machine-value");
    clearKey();
    resetKeyAccessCountsForTests();
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("machine-value");
    expect(readKeyAccessCountsForTests()).toEqual({ interactiveUnwraps: 0, interactiveDecrypts: 0 });
  });

  it("resolves explicit and broad mixed-class runs only after interactive unlock", async () => {
    initializeVault("mixed-passphrase");
    storeSecret("app", "prod", "MACHINE", "machine-value", "machine");
    storeSecret("app", "prod", "INTERACTIVE", "interactive-value", "interactive");
    clearKey();
    let allowUnlock = false;
    const resolved: Array<Record<string, string>> = [];
    const runtime = createSoftwareRunRuntime({
      ensureUnlocked: async () => {
        if (!allowUnlock) throw new Error("interactive key remains locked");
        unlockVault("mixed-passphrase");
      },
      listSecretNames: () => ["INTERACTIVE", "MACHINE"],
      resolveSecret,
      resolveSecrets: (project, environment, names) => {
        const values = new Map(names.map((name) => [name, resolveSecret(project, environment, name)!]));
        resolved.push(Object.fromEntries(values));
        return values;
      },
      readAuthorizationState: (_project, _environment, secret) => secret === "INTERACTIVE" ? "locked" : "unlocked",
      readKeyClass: readSecretKeyClass,
      authorize: async () => ({ method: "biometric" as const }),
      baseEnv: () => ({}),
      stdout: () => undefined,
      stderr: () => undefined,
      execute: async (options) => {
        if (options.authorizationRequired) await options.authorize?.(options.authorizationReason!);
        await options.ensureUnlocked?.();
        const names = options.request.envSpecs.length === 0
          ? options.secretNames
          : options.request.envSpecs.map((spec) => spec.sourceName);
        options.resolveSecrets(names);
        return { kind: "exit", exitCode: 0 };
      },
    });
    const explicit = {
      allowUnsafe: false,
      envSpecs: [
        { sourceName: "MACHINE", targetName: "MACHINE" },
        { sourceName: "INTERACTIVE", targetName: "INTERACTIVE" },
      ],
      commandArgs: ["command"],
      scope: { project: "app", environment: "prod" },
    };

    await expect(runtime.run(explicit)).rejects.toThrow(/remains locked/i);
    expect(resolved).toEqual([]);
    allowUnlock = true;
    await expect(runtime.run(explicit)).resolves.toEqual({ kind: "exit", exitCode: 0 });
    clearKey();
    await expect(runtime.run({ ...explicit, envSpecs: [] })).resolves.toEqual({ kind: "exit", exitCode: 0 });
    expect(resolved).toEqual([
      { MACHINE: "machine-value", INTERACTIVE: "interactive-value" },
      { INTERACTIVE: "interactive-value", MACHINE: "machine-value" },
    ]);
  });

  it("rolls back earlier record transitions when a later ciphertext fails authentication", () => {
    initializeVault("rollback-passphrase");
    storeSecret("app", "prod", "API_KEY", "first", "machine");
    storeSecret("app", "prod", "OTHER", "second", "machine");
    mutateAuthorizationRule({ project: "baseline" }, "unlock");
    closeDb();
    const database = new Database(path.join(home, "vault.db"));
    database.prepare("UPDATE secrets SET auth_tag = ? WHERE name = 'OTHER'").run(Buffer.alloc(16, 99));
    const rowsBefore = database.prepare("SELECT name, key_class, encrypted_value, iv, auth_tag FROM secrets ORDER BY name").all();
    database.close();
    const policyBefore = fs.readFileSync(path.join(home, "strict-policy.v1.json"));
    const anchorBefore = fs.readFileSync(path.join(home, ".strict-policy.key"));

    expect(() => mutateAuthorizationRule({ project: "app" }, "lock", (db, rules) => {
      transitionRecordCustody(db, rules, evaluateAuthorizationRules);
    })).toThrow();

    expect(fs.readFileSync(path.join(home, "strict-policy.v1.json"))).toEqual(policyBefore);
    expect(fs.readFileSync(path.join(home, ".strict-policy.key"))).toEqual(anchorBefore);
    closeDb();
    const after = new Database(path.join(home, "vault.db"), { readonly: true });
    expect(after.prepare("SELECT name, key_class, encrypted_value, iv, auth_tag FROM secrets ORDER BY name").all()).toEqual(rowsBefore);
    after.close();
  });

  it("enrolls and rotates passphrase wraps without rewriting record ciphertext", () => {
    initializeVault("");
    enrollInteractivePassphrase("first-passphrase");
    storeSecret("app", "prod", "API_KEY", "value", "interactive");
    const beforeDb = new Database(path.join(home, "vault.db"), { readonly: true });
    const before = beforeDb.prepare("SELECT encrypted_value, iv, auth_tag FROM secrets WHERE name = 'API_KEY'").get() as Record<string, Buffer>;
    beforeDb.close();
    rotateInteractivePassphrase("first-passphrase", "second-passphrase");
    const afterDb = new Database(path.join(home, "vault.db"), { readonly: true });
    const after = afterDb.prepare("SELECT encrypted_value, iv, auth_tag FROM secrets WHERE name = 'API_KEY'").get() as Record<string, Buffer>;
    afterDb.close();
    expect(after).toEqual(before);
    clearKey();
    expect(() => unlockVault("first-passphrase")).toThrow(/incorrect/i);
    unlockVault("second-passphrase");
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("value");
  });

  it.each(["after-journal", "after-bundle"] as const)(
    "rolls enrollment back after an interruption %s before the database commit",
    (fault) => {
      initializeVault("");
      setCustodyFaultForTests(fault);
      expect(() => enrollInteractivePassphrase("passphrase-one")).toThrow(/custody crash/i);
      setCustodyFaultForTests(null);
      expect(recoverInterruptedCustodyTransition()).toBe(true);
      expect(getVaultDescriptor().custody).toBe("machine-only");
    },
  );

  it("commits enrollment after an interruption following the database commit", () => {
    initializeVault("");
    setCustodyFaultForTests("after-database");
    expect(() => enrollInteractivePassphrase("passphrase-two")).toThrow(/database commit/i);
    setCustodyFaultForTests(null);
    expect(recoverInterruptedCustodyTransition()).toBe(true);
    expect(getVaultDescriptor().custody).toBe("dual-key");
    unlockVault("passphrase-two");
  });

  it("migrates a passphrase one-key vault into interactive and machine custody", () => {
    replaceWithLegacyV3("legacy-passphrase");
    migrateLegacyVaultToDualKey(
      (_project, _environment, secret) => secret === "LOCKED" ? "locked" : "unlocked",
      { currentPassphrase: "legacy-passphrase" },
    );
    expect(getVaultDescriptor().custody).toBe("dual-key");
    expect(readSecretKeyClass("app", "prod", "MACHINE")).toBe("machine");
    expect(readSecretKeyClass("app", "prod", "LOCKED")).toBe("interactive");
    clearKey();
    expect(resolveSecret("app", "prod", "MACHINE")).toBe("machine-value");
    expect(() => resolveSecret("app", "prod", "LOCKED")).toThrow(/locked/i);
    unlockVault("legacy-passphrase");
    expect(resolveSecret("app", "prod", "LOCKED")).toBe("locked-value");
  });

  it("leaves a legacy machine vault unchanged when locked migration lacks enrollment", () => {
    replaceWithLegacyV3("");
    const keyBefore = fs.readFileSync(path.join(home, ".keyclasp.key"));
    const databaseBefore = fs.readFileSync(path.join(home, "vault.db"));
    expect(() => migrateLegacyVaultToDualKey(
      (_project, _environment, secret) => secret === "LOCKED" ? "locked" : "unlocked",
    )).toThrow(/enrollment/i);
    expect(fs.readFileSync(path.join(home, ".keyclasp.key"))).toEqual(keyBefore);
    expect(fs.readFileSync(path.join(home, "vault.db"))).toEqual(databaseBefore);
  });

  it.each(["after-backup", "after-journal", "after-bundle", "after-database"] as const)(
    "recovers a dual-key migration interruption %s from the database commit point",
    (fault) => {
      replaceWithLegacyV3("");
      setDualKeyMigrationFaultForTests(fault);
      expect(() => migrateLegacyVaultToDualKey(() => "unlocked")).toThrow(/Injected dual-key migration/i);
      setDualKeyMigrationFaultForTests(null);
      closeDb();
      clearKey();
      expect(recoverInterruptedDualKeyMigration()).toBe(fault !== "after-backup");
      if (fault === "after-database") {
        expect(needsDualKeyMigration()).toBe(false);
        expect(resolveSecret("app", "prod", "MACHINE")).toBe("machine-value");
      } else {
        expect(needsDualKeyMigration()).toBe(true);
        migrateLegacyVaultToDualKey(() => "unlocked");
        expect(resolveSecret("app", "prod", "MACHINE")).toBe("machine-value");
      }
    },
  );
});
