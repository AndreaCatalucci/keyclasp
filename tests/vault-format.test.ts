import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import {
  clearKey,
  closeDb,
  encrypt,
  getKey,
  initializeVault,
  isInitialized,
  listSecrets,
  resolveSecret,
  resolveSecretsForRun,
  setVaultMigrationFaultForTests,
  setVaultMigrationBackupHookForTests,
  storeSecret,
  unlockVault,
  writeLegacyV3KeyFileForTests,
} from "../src/vault.js";

const previousHome = process.env.KEYCLASP_HOME;
let root: string;
let home: string;

function resetRuntime(): void {
  closeDb();
  clearKey();
}

function dbPath(): string {
  return path.join(home, "vault.db");
}

function rawDb(): Database.Database {
  return new Database(dbPath());
}

function replaceWithLegacyRow(value = "legacy-value"): void {
  const key = getKey();
  writeLegacyV3KeyFileForTests(key, "test-passphrase");
  closeDb();
  const db = rawDb();
  try {
    db.exec("DROP TABLE vault_metadata; DROP TABLE secrets");
    db.exec(`
      CREATE TABLE secrets (
        project TEXT NOT NULL,
        environment TEXT NOT NULL,
        name TEXT NOT NULL,
        encrypted_value BLOB NOT NULL,
        iv BLOB NOT NULL,
        auth_tag BLOB NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        PRIMARY KEY (project, environment, name)
      )
    `);
    const encrypted = encrypt(value, key);
    db.prepare(`
      INSERT INTO secrets (project, environment, name, encrypted_value, iv, auth_tag)
      VALUES ('app', 'prod', 'API_KEY', ?, ?, ?)
    `).run(encrypted.encrypted, encrypted.iv, encrypted.authTag);
  } finally {
    db.close();
  }
  clearKey();
}

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-format-"));
  home = path.join(root, ".keyclasp");
  process.env.KEYCLASP_HOME = home;
  resetRuntime();
  setVaultMigrationFaultForTests(null);
  setVaultMigrationBackupHookForTests(null);
  initializeVault("test-passphrase");
});

afterEach(() => {
  setVaultMigrationFaultForTests(null);
  setVaultMigrationBackupHookForTests(null);
  resetRuntime();
  if (previousHome === undefined) delete process.env.KEYCLASP_HOME;
  else process.env.KEYCLASP_HOME = previousHome;
  fs.rmSync(root, { recursive: true, force: true });
});

describe("authenticated record identity", () => {
  it("checks the complete batch exists before decrypting any selected record", () => {
    storeSecret("app", "prod", "FIRST", "first-value");
    closeDb();
    const db = rawDb();
    try {
      db.prepare("UPDATE secrets SET auth_tag = ? WHERE name = 'FIRST'").run(crypto.randomBytes(16));
    } finally {
      db.close();
    }
    resetRuntime();
    unlockVault("test-passphrase");

    expect(() => resolveSecretsForRun("app", "prod", ["FIRST", "MISSING"]))
      .toThrow(/Secret "MISSING" disappeared/);
  });

  it("rejects ciphertext replayed under another name or scope", () => {
    storeSecret("app", "prod", "FIRST", "first-value");
    storeSecret("app", "prod", "SECOND", "second-value");
    resetRuntime();
    unlockVault("test-passphrase");
    closeDb();

    const db = rawDb();
    try {
      const first = db.prepare("SELECT encrypted_value, iv, auth_tag FROM secrets WHERE name = 'FIRST'").get() as
        { encrypted_value: Buffer; iv: Buffer; auth_tag: Buffer };
      db.prepare("UPDATE secrets SET encrypted_value = ?, iv = ?, auth_tag = ? WHERE name = 'SECOND'")
        .run(first.encrypted_value, first.iv, first.auth_tag);
    } finally {
      db.close();
    }
    resetRuntime();
    unlockVault("test-passphrase");
    expect(() => resolveSecret("app", "prod", "SECOND")).toThrow();
  });

  it.each([
    ["project", "other"],
    ["environment", "other"],
    ["name", "OTHER_KEY"],
    ["record_kind", "policy"],
  ] as const)("rejects isolated %s tampering", (field, value) => {
    storeSecret("app", "prod", "API_KEY", "bound-value");
    closeDb();
    const db = rawDb();
    try {
      db.pragma("ignore_check_constraints = ON");
      db.prepare(`UPDATE secrets SET ${field} = ? WHERE name = 'API_KEY'`).run(value);
    } finally {
      db.close();
    }
    resetRuntime();
    unlockVault("test-passphrase");
    const identity = {
      project: field === "project" ? value : "app",
      environment: field === "environment" ? value : "prod",
      name: field === "name" ? value : "API_KEY",
    };
    expect(() => resolveSecret(identity.project, identity.environment, identity.name)).toThrow();
  });

  it("rejects isolated vault identity tampering", () => {
    storeSecret("app", "prod", "API_KEY", "bound-value");
    closeDb();
    const db = rawDb();
    try {
      db.prepare("UPDATE vault_metadata SET vault_id = ? WHERE singleton = 1").run(crypto.randomBytes(16));
    } finally {
      db.close();
    }
    resetRuntime();
    expect(() => unlockVault("test-passphrase")).toThrow(/does not unlock this vault/);
  });

  it("rejects a record copied from another vault", () => {
    storeSecret("source", "prod", "API_KEY", "source-value");
    closeDb();
    const sourceDb = rawDb();
    const row = sourceDb.prepare("SELECT * FROM secrets WHERE name = 'API_KEY'").get() as Record<string, unknown>;
    sourceDb.close();

    const otherHome = path.join(root, "other-vault");
    process.env.KEYCLASP_HOME = otherHome;
    resetRuntime();
    initializeVault("other-passphrase");
    closeDb();
    const targetDb = new Database(path.join(otherHome, "vault.db"));
    try {
      targetDb.prepare(`
        INSERT INTO secrets
          (project, environment, name, record_id, record_kind, key_class, encrypted_value, iv, auth_tag, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(...Object.values(row));
    } finally {
      targetDb.close();
    }
    resetRuntime();
    unlockVault("other-passphrase");
    expect(() => resolveSecret("source", "prod", "API_KEY")).toThrow();
  });

  it("forces older writers that omit record identity to fail closed", () => {
    closeDb();
    const db = rawDb();
    expect(() => db.prepare(`
      INSERT INTO secrets (project, environment, name, encrypted_value, iv, auth_tag)
      VALUES ('old', 'writer', 'VALUE', ?, ?, ?)
    `).run(Buffer.from("x"), crypto.randomBytes(12), crypto.randomBytes(16))).toThrow(/record_id|NOT NULL/i);
    db.close();
  });
});

describe("locked migration", () => {
  for (const boundary of ["after-backup", "before-commit", "after-commit"] as const) {
    it(`retries safely after an interruption ${boundary}`, () => {
      replaceWithLegacyRow();
      setVaultMigrationFaultForTests(boundary);
      expect(() => unlockVault("test-passphrase")).toThrow(/Injected migration interruption/);
      expect(() => getKey()).toThrow(/locked|passphrase/i);
      const keyMagic = fs.readFileSync(path.join(home, ".keyclasp.key")).subarray(0, 12).toString("utf8");
      expect(keyMagic).toBe(boundary === "after-backup" ? "keyclasp:v3\n" : "keyclasp:v4\n");
      if (boundary === "after-backup") {
        const backup = fs.readdirSync(home)
          .find((name) => name.startsWith("vault.db.v1.") && name.endsWith(".bak"));
        expect(backup).toBeDefined();
        const backupDb = new Database(path.join(home, backup!), { readonly: true });
        try {
          expect(backupDb.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'vault_metadata'").get()).toBeUndefined();
          const columns = (backupDb.pragma("table_info(secrets)") as { name: string }[]).map((column) => column.name);
          expect(columns).not.toContain("record_id");
          expect(columns).not.toContain("record_kind");
        } finally {
          backupDb.close();
        }
      }
      resetRuntime();
      setVaultMigrationFaultForTests(null);
      unlockVault("test-passphrase");
      expect(fs.readFileSync(path.join(home, ".keyclasp.key")).subarray(0, 12).toString("utf8")).toBe("keyclasp:v4\n");
      expect(resolveSecret("app", "prod", "API_KEY")).toBe("legacy-value");
      const backups = fs.readdirSync(home).filter((name) => name.startsWith("vault.db.v1.") && name.endsWith(".bak"));
      expect(backups.length).toBeGreaterThan(0);
    });
  }

  it("restores and remigrates the backup produced before conversion", () => {
    replaceWithLegacyRow("restored-value");
    unlockVault("test-passphrase");
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("restored-value");
    closeDb();
    const backup = fs.readdirSync(home)
      .filter((name) => name.startsWith("vault.db.v1.") && name.endsWith(".bak"))
      .map((name) => path.join(home, name))
      .sort((left, right) => fs.statSync(right).mtimeMs - fs.statSync(left).mtimeMs)[0];
    expect(backup).toBeDefined();
    fs.copyFileSync(backup!, dbPath());
    const keyBackup = fs.readdirSync(home)
      .filter((name) => name.startsWith(".keyclasp.key.") && name.endsWith(".bak"))
      .map((name) => path.join(home, name))
      .sort((left, right) => fs.statSync(right).mtimeMs - fs.statSync(left).mtimeMs)[0];
    expect(keyBackup).toBeDefined();
    fs.copyFileSync(keyBackup!, path.join(home, ".keyclasp.key"));
    resetRuntime();
    unlockVault("test-passphrase");
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("restored-value");
  });

  it("holds the write lock while taking the migration backup", () => {
    replaceWithLegacyRow("locked-backup-value");
    let competingWriteError = "";
    setVaultMigrationBackupHookForTests((backupPath) => {
      const backupDb = new Database(backupPath, { readonly: true });
      try {
        expect(backupDb.prepare("SELECT name FROM secrets").pluck().all()).toEqual(["API_KEY"]);
      } finally {
        backupDb.close();
      }

      const competitor = new Database(dbPath());
      competitor.pragma("busy_timeout = 1");
      try {
        competitor.prepare(`
          INSERT INTO secrets (project, environment, name, encrypted_value, iv, auth_tag)
          VALUES ('app', 'prod', 'RACING', ?, ?, ?)
        `).run(Buffer.from("x"), crypto.randomBytes(12), crypto.randomBytes(16));
      } catch (err: any) {
        competingWriteError = `${err?.code ?? ""} ${err?.message ?? ""}`;
      } finally {
        competitor.close();
      }
    });

    unlockVault("test-passphrase");
    expect(competingWriteError).toMatch(/SQLITE_BUSY|locked/i);
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("locked-backup-value");
    expect(resolveSecret("app", "prod", "RACING")).toBeNull();
  });
});

describe("owner-only permissions", () => {
  it("repairs permissive existing vault files and SQLite side files", () => {
    if (process.platform === "win32") return;
    resetRuntime();
    const sideFile = `${dbPath()}-shm`;
    fs.writeFileSync(sideFile, "");
    for (const target of [home, dbPath(), path.join(home, ".keyclasp.key"), sideFile]) fs.chmodSync(target, 0o777);

    expect(isInitialized()).toBe(true);
    expect(fs.statSync(home).mode & 0o777).toBe(0o700);
    for (const target of [dbPath(), path.join(home, ".keyclasp.key"), sideFile]) {
      expect(fs.statSync(target).mode & 0o777).toBe(0o600);
    }
  });

  it("rejects a vault file symlink without changing its target", () => {
    if (process.platform === "win32") return;
    const outside = path.join(root, "outside");
    fs.writeFileSync(outside, "unchanged", { mode: 0o644 });
    fs.symlinkSync(outside, path.join(home, ".keyclasp.key.evil.bak"));
    expect(() => isInitialized()).toThrow(/symbolic links are not allowed/);
    expect(fs.readFileSync(outside, "utf8")).toBe("unchanged");
    expect(fs.statSync(outside).mode & 0o777).toBe(0o644);
  });

  it("tolerates a key publication temp file disappearing during permission inspection", () => {
    const transient = path.join(home, `.keyclasp.key.${process.pid}.fixture.tmp`);
    fs.writeFileSync(transient, "temporary", { mode: 0o600 });
    const realLstat = fs.lstatSync.bind(fs);
    const lstat = vi.spyOn(fs, "lstatSync").mockImplementation(((target: fs.PathLike, options?: any) => {
      const stat = realLstat(target, options as any) as any;
      if (path.resolve(String(target)) === transient) fs.unlinkSync(transient);
      return stat;
    }) as typeof fs.lstatSync);
    try {
      expect(isInitialized()).toBe(true);
    } finally {
      lstat.mockRestore();
    }
  });

  it("rejects vault paths not owned by the current user", () => {
    if (process.platform === "win32" || process.getuid === undefined) return;
    const actualUid = process.getuid();
    const getuid = vi.spyOn(process, "getuid").mockReturnValue(actualUid + 1);
    try {
      expect(() => isInitialized()).toThrow(/owner UID.*current UID/i);
    } finally {
      getuid.mockRestore();
    }
  });

  it("rejects every sensitive vault file class when it is not owned by the current user", () => {
    if (process.platform === "win32" || process.getuid === undefined) return;
    resetRuntime();
    const keyPath = path.join(home, ".keyclasp.key");
    const paths = [
      keyPath,
      dbPath(),
      `${dbPath()}-wal`,
      `${dbPath()}-shm`,
      `${dbPath()}.v1.fixture.bak`,
      `${keyPath}.1.bak`,
    ];
    for (const target of paths.slice(2, 5)) fs.copyFileSync(dbPath(), target);
    fs.copyFileSync(keyPath, paths[5]);
    const actualUid = process.getuid();
    const realLstat = fs.lstatSync.bind(fs);
    for (const mismatchedPath of paths) {
      const targeted = vi.spyOn(fs, "lstatSync").mockImplementation(((target: fs.PathLike, options?: any) => {
        const stat = realLstat(target, options as any) as fs.Stats;
        if (path.resolve(String(target)) !== mismatchedPath) return stat as any;
        return new Proxy(stat, { get: (value, property) => property === "uid" ? actualUid + 1 : Reflect.get(value, property) }) as any;
      }) as typeof fs.lstatSync);
      try {
        expect(() => isInitialized()).toThrow(/owner UID.*current UID/i);
      } finally {
        targeted.mockRestore();
      }
    }
  });

  it("removes and verifies macOS ACL entries on every existing vault path class", () => {
    if (process.platform !== "darwin") return;
    resetRuntime();
    const paths = [
      home,
      path.join(home, ".keyclasp.key"),
      dbPath(),
      `${dbPath()}-wal`,
      `${dbPath()}-shm`,
      `${dbPath()}.v1.fixture.bak`,
      `${path.join(home, ".keyclasp.key")}.1.bak`,
    ];
    for (const target of paths.slice(3, 6)) fs.copyFileSync(dbPath(), target);
    fs.copyFileSync(path.join(home, ".keyclasp.key"), paths[6]);
    for (const target of paths) {
      execFileSync("/bin/chmod", ["+a", "everyone allow read", target]);
      expect(execFileSync("/bin/ls", ["-lde", target], { encoding: "utf8" })).toMatch(/^\s*0:\s/m);
    }

    expect(isInitialized()).toBe(true);
    for (const target of paths) {
      expect(execFileSync("/bin/ls", ["-lde", target], { encoding: "utf8" })).not.toMatch(/^\s*\d+:\s/m);
    }
  });
});

describe("invalid vault states", () => {
  it("fails closed when vault.db is missing beside an existing key file", () => {
    resetRuntime();
    fs.rmSync(dbPath(), { force: true });
    expect(() => unlockVault("test-passphrase")).toThrow(/vault database is missing/i);
    expect(fs.existsSync(dbPath())).toBe(false);
  });

  it("closes a cached database handle if vault.db is removed", () => {
    storeSecret("app", "prod", "API_KEY", "value");
    fs.rmSync(dbPath(), { force: true });
    expect(() => storeSecret("app", "prod", "OTHER", "value")).toThrow(/vault database is missing/i);
    expect(fs.existsSync(dbPath())).toBe(false);
  });

  it("rejects an empty database atomically replaced under a live handle", () => {
    storeSecret("app", "prod", "API_KEY", "value");
    const detached = `${dbPath()}.detached`;
    const replacement = `${dbPath()}.replacement`;
    new Database(replacement).close();
    fs.renameSync(dbPath(), detached);
    fs.renameSync(replacement, dbPath());

    expect(() => storeSecret("app", "prod", "OTHER", "value")).toThrow(/replaced while open/i);
    const current = new Database(dbPath(), { readonly: true });
    try {
      expect(current.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table'").get()).toBeUndefined();
    } finally {
      current.close();
    }
  });

  it("does not reveal stale secrets after another vault replaces a live database", () => {
    storeSecret("app", "prod", "ORIGINAL", "original-value");
    const originalHome = home;
    const otherHome = path.join(root, "live-replacement-vault");
    resetRuntime();
    process.env.KEYCLASP_HOME = otherHome;
    initializeVault("replacement-passphrase");
    storeSecret("app", "prod", "REPLACEMENT", "replacement-value");
    closeDb();
    const replacement = path.join(root, "foreign-vault.db");
    fs.copyFileSync(path.join(otherHome, "vault.db"), replacement);

    process.env.KEYCLASP_HOME = originalHome;
    resetRuntime();
    unlockVault("test-passphrase");
    expect(resolveSecret("app", "prod", "ORIGINAL")).toBe("original-value");
    fs.renameSync(replacement, dbPath());

    expect(() => resolveSecret("app", "prod", "ORIGINAL")).toThrow(/replaced while open/i);
  });

  it("rejects an empty replacement database beside an existing v4 key", () => {
    resetRuntime();
    fs.rmSync(dbPath(), { force: true });
    new Database(dbPath()).close();
    expect(() => listSecrets("app", "prod")).toThrow(/empty or replaced/i);
    expect(() => unlockVault("test-passphrase")).toThrow(/does not unlock|empty or replaced/i);
    const replacement = new Database(dbPath(), { readonly: true });
    try {
      expect(replacement.prepare("SELECT 1 FROM sqlite_master WHERE name = 'vault_metadata'").get()).toBeUndefined();
    } finally {
      replacement.close();
    }
  });

  it("rejects a complete database replaced by another vault", () => {
    storeSecret("app", "prod", "ORIGINAL", "original-value");
    const originalHome = home;
    const otherHome = path.join(root, "replacement-vault");
    resetRuntime();
    process.env.KEYCLASP_HOME = otherHome;
    initializeVault("replacement-passphrase");
    storeSecret("app", "prod", "REPLACEMENT", "replacement-value");
    closeDb();
    fs.copyFileSync(path.join(otherHome, "vault.db"), path.join(originalHome, "vault.db"));

    process.env.KEYCLASP_HOME = originalHome;
    resetRuntime();
    expect(() => listSecrets("app", "prod")).toThrow(/does not unlock|same backup/i);
    expect(() => unlockVault("test-passphrase")).toThrow(/does not unlock/i);
  });

  it("rejects current record columns when vault metadata is missing", () => {
    closeDb();
    const db = rawDb();
    try {
      db.exec("DROP TABLE vault_metadata");
    } finally {
      db.close();
    }
    resetRuntime();
    expect(() => unlockVault("test-passphrase")).toThrow(/partially migrated|does not unlock/i);
  });

  it("fails closed when format metadata and the record schema disagree", () => {
    closeDb();
    const db = rawDb();
    try {
      db.exec("DROP TABLE secrets");
      db.exec(`
        CREATE TABLE secrets (
          project TEXT NOT NULL,
          environment TEXT NOT NULL,
          name TEXT NOT NULL,
          encrypted_value BLOB NOT NULL,
          iv BLOB NOT NULL,
          auth_tag BLOB NOT NULL,
          PRIMARY KEY (project, environment, name)
        )
      `);
    } finally {
      db.close();
    }
    resetRuntime();
    expect(isInitialized()).toBe(true);
    expect(() => unlockVault("test-passphrase")).toThrow(/partially migrated|does not unlock/i);
  });
});
