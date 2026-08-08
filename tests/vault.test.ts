import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";

const tmpDir = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-test-")));
const vaultDir = path.join(tmpDir, ".keyclasp");
const previousKeyclaspHome = process.env.KEYCLASP_HOME;
process.env.KEYCLASP_HOME = vaultDir;

import {
  encrypt,
  decrypt,
  initializeVault,
  storeSecret,
  resolveSecret,
  listSecrets,
  deleteSecret,
  isInitialized,
  closeDb,
  clearKey,
  getKey,
  getDb,
  validateScopeName,
  isNewProjectEnvironment,
  projects,
  environments,
  deleteProject,
  deleteEnvironmentInProject,
  deleteEnvironmentAcrossAllProjects,
  snapshotBulkDelete,
  deleteBulkIfUnchanged,
  renameProject,
  renameEnvironmentInProject,
  renameEnvironmentAcrossAllProjects,
  renameScope,
  type ScopedSecret,
} from "../src/vault.js";

// Each scoping/migration/bulk/rename test gets its own throwaway vault home so
// they can't see (or clobber) rows written by the "vault CRUD" suite above,
// which shares the module-level vaultDir.
function withTempVault(passphrase = "scope-test-passphrase"): { home: string; restore: () => void } {
  const previous = process.env.KEYCLASP_HOME;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-scope-"));
  const home = path.join(dir, ".keyclasp");
  closeDb();
  clearKey();
  process.env.KEYCLASP_HOME = home;
  initializeVault(passphrase);
  return {
    home,
    restore: () => {
      closeDb();
      clearKey();
      if (previous === undefined) delete process.env.KEYCLASP_HOME;
      else process.env.KEYCLASP_HOME = previous;
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

beforeAll(() => {
  process.env.KEYCLASP_HOME = vaultDir;
  fs.mkdirSync(tmpDir, { recursive: true });
  fs.mkdirSync(vaultDir, { recursive: true });
});

afterAll(() => {
  closeDb();
  if (previousKeyclaspHome === undefined) {
    delete process.env.KEYCLASP_HOME;
  } else {
    process.env.KEYCLASP_HOME = previousKeyclaspHome;
  }
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("encrypt / decrypt", () => {
  const key = crypto.randomBytes(32);

  it("round-trips a plaintext value", () => {
    const original = "sk-proxy-1234567890abcdef";
    const { encrypted, iv, authTag } = encrypt(original, key);
    const decrypted = decrypt(encrypted, iv, authTag, key);
    expect(decrypted).toBe(original);
  });

  it("produces different ciphertexts for the same plaintext (random IV)", () => {
    const value = "my-secret-token";
    const a = encrypt(value, key);
    const b = encrypt(value, key);
    expect(a.encrypted.equals(b.encrypted)).toBe(false);
  });

  it("fails to decrypt with wrong key", () => {
    const wrongKey = crypto.randomBytes(32);
    const { encrypted, iv, authTag } = encrypt("top-secret", key);
    expect(() => decrypt(encrypted, iv, authTag, wrongKey)).toThrow();
  });

  it("fails to decrypt with tampered auth tag", () => {
    const { encrypted, iv, authTag } = encrypt("top-secret", key);
    const tampered = Buffer.from(authTag);
    tampered[0] = tampered[0] ^ 0xff;
    expect(() => decrypt(encrypted, iv, tampered, key)).toThrow();
  });

  it("handles empty string", () => {
    const { encrypted, iv, authTag } = encrypt("", key);
    expect(decrypt(encrypted, iv, authTag, key)).toBe("");
  });

  it("handles unicode", () => {
    const value = "🔑 secret with émojis and ünicode";
    const { encrypted, iv, authTag } = encrypt(value, key);
    expect(decrypt(encrypted, iv, authTag, key)).toBe(value);
  });

  it("handles very long values", () => {
    const value = "x".repeat(10_000);
    const { encrypted, iv, authTag } = encrypt(value, key);
    expect(decrypt(encrypted, iv, authTag, key)).toBe(value);
  });
});

describe("vault CRUD", () => {
  // Initialize once for the CRUD suite
  beforeAll(() => {
    if (!isInitialized()) {
      initializeVault("test-passphrase");
    }
  });

  it("is initialized after init", () => {
    expect(isInitialized()).toBe(true);
  });

  it("stores and resolves a secret", () => {
    storeSecret("default", "default", "TEST_KEY", "test-value-123");
    expect(resolveSecret("default", "default", "TEST_KEY")).toBe("test-value-123");
  });

  it("uses the newly initialized key after another vault key was cached", () => {
    const originalHome = process.env.KEYCLASP_HOME;
    const firstHome = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-first-")), ".keyclasp");
    const secondHome = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-second-")), ".keyclasp");

    try {
      closeDb();
      clearKey();

      process.env.KEYCLASP_HOME = firstHome;
      initializeVault("first-passphrase");
      storeSecret("default", "default", "FIRST_KEY", "first-value");
      expect(resolveSecret("default", "default", "FIRST_KEY")).toBe("first-value");
      closeDb();

      process.env.KEYCLASP_HOME = secondHome;
      initializeVault("second-passphrase");
      storeSecret("default", "default", "SECOND_KEY", "second-value");
      expect(resolveSecret("default", "default", "SECOND_KEY")).toBe("second-value");

      closeDb();
      clearKey();
      expect(resolveSecret("default", "default", "SECOND_KEY")).toBe("second-value");
    } finally {
      closeDb();
      clearKey();
      if (originalHome === undefined) {
        delete process.env.KEYCLASP_HOME;
      } else {
        process.env.KEYCLASP_HOME = originalHome;
      }
      fs.rmSync(path.dirname(firstHome), { recursive: true, force: true });
      fs.rmSync(path.dirname(secondHome), { recursive: true, force: true });
    }
  });

  it("returns null for missing secret", () => {
    expect(resolveSecret("default", "default", "NONEXISTENT")).toBeNull();
  });

  it("lists secret names", () => {
    storeSecret("default", "default", "LIST_TEST_1", "a");
    storeSecret("default", "default", "LIST_TEST_2", "b");
    const names = listSecrets("default", "default");
    expect(names).toContain("LIST_TEST_1");
    expect(names).toContain("LIST_TEST_2");
  });

  it("hides orphaned internal records from removed features", () => {
    const removedRecords = [
      "_keyclasp_sso:config",
      "_keyclasp_sso:token",
      "_keyclasp_deadman:config",
      "_keyclasp_deadman:last_checkin",
      "__keyclasp_team_check",
    ];

    for (const name of removedRecords) {
      storeSecret("default", "default", name, "removed-feature-value");
    }

    const names = listSecrets("default", "default");
    for (const name of removedRecords) {
      expect(names).not.toContain(name);
      expect(resolveSecret("default", "default", name)).toBeNull();
    }
  });

  it("hides internal double-underscore-prefixed rows from list output", () => {
    storeSecret("default", "default", "__keyclasp_internal__COUNTED", "internal-value");
    expect(listSecrets("default", "default")).not.toContain("__keyclasp_internal__COUNTED");
    expect(resolveSecret("default", "default", "__keyclasp_internal__COUNTED")).toBe("internal-value");
  });

  it("updates an existing secret", () => {
    storeSecret("default", "default", "UPDATE_TEST", "old");
    storeSecret("default", "default", "UPDATE_TEST", "new");
    expect(resolveSecret("default", "default", "UPDATE_TEST")).toBe("new");
  });

  it("deletes a secret", () => {
    storeSecret("default", "default", "DELETE_TEST", "x");
    expect(deleteSecret("default", "default", "DELETE_TEST")).toBe(true);
    expect(resolveSecret("default", "default", "DELETE_TEST")).toBeNull();
    expect(deleteSecret("default", "default", "DELETE_TEST")).toBe(false);
  });
});

describe("scoping isolation", () => {
  let vault: ReturnType<typeof withTempVault>;
  beforeEach(() => { vault = withTempVault(); });
  afterEach(() => vault.restore());

  it("keeps the same secret name independent across project/environment pairs", () => {
    storeSecret("app-a", "prod", "SHARED", "a-prod");
    storeSecret("app-a", "staging", "SHARED", "a-staging");
    storeSecret("app-b", "prod", "SHARED", "b-prod");

    expect(resolveSecret("app-a", "prod", "SHARED")).toBe("a-prod");
    expect(resolveSecret("app-a", "staging", "SHARED")).toBe("a-staging");
    expect(resolveSecret("app-b", "prod", "SHARED")).toBe("b-prod");
    expect(resolveSecret("app-b", "staging", "SHARED")).toBeNull();
  });

  it("scopes listSecrets to an exact (project, environment) pair as a plain name list", () => {
    storeSecret("app-a", "prod", "ONE", "1");
    storeSecret("app-a", "staging", "TWO", "2");
    const names = listSecrets("app-a", "prod");
    expect(names).toEqual(["ONE"]);
  });

  it("listSecrets filters by project only, spanning every environment", () => {
    storeSecret("app-a", "prod", "ONE", "1");
    storeSecret("app-a", "staging", "TWO", "2");
    storeSecret("app-b", "prod", "THREE", "3");

    const rows = listSecrets("app-a") as ScopedSecret[];
    expect(rows.map((r) => `${r.environment}/${r.name}`).sort()).toEqual(["prod/ONE", "staging/TWO"]);
  });

  it("listSecrets filters by environment only, spanning every project", () => {
    storeSecret("app-a", "prod", "ONE", "1");
    storeSecret("app-b", "prod", "THREE", "3");
    storeSecret("app-b", "staging", "FOUR", "4");

    const rows = listSecrets(undefined, "prod") as ScopedSecret[];
    expect(rows.map((r) => `${r.project}/${r.name}`).sort()).toEqual(["app-a/ONE", "app-b/THREE"]);
  });

  it("listSecrets with no axes returns every scoped row", () => {
    storeSecret("app-a", "prod", "ONE", "1");
    storeSecret("app-b", "staging", "TWO", "2");

    const rows = listSecrets() as ScopedSecret[];
    expect(rows.map((r) => `${r.project}/${r.environment}/${r.name}`).sort()).toEqual([
      "app-a/prod/ONE",
      "app-b/staging/TWO",
    ]);
  });

  it("deleteSecret only removes the matching scope", () => {
    storeSecret("app-a", "prod", "SHARED", "a-prod");
    storeSecret("app-a", "staging", "SHARED", "a-staging");

    expect(deleteSecret("app-a", "prod", "SHARED")).toBe(true);
    expect(resolveSecret("app-a", "prod", "SHARED")).toBeNull();
    expect(resolveSecret("app-a", "staging", "SHARED")).toBe("a-staging");
  });
});

describe("isNewProjectEnvironment", () => {
  let vault: ReturnType<typeof withTempVault>;
  beforeEach(() => { vault = withTempVault(); });
  afterEach(() => vault.restore());

  it("is true before any secret exists for the pair, false after", () => {
    expect(isNewProjectEnvironment("app", "prod")).toBe(true);
    storeSecret("app", "prod", "FIRST", "value");
    expect(isNewProjectEnvironment("app", "prod")).toBe(false);
  });

  it("treats different environments in the same project as separately new", () => {
    storeSecret("app", "prod", "FIRST", "value");
    expect(isNewProjectEnvironment("app", "staging")).toBe(true);
  });
});

describe("projects() and environments()", () => {
  let vault: ReturnType<typeof withTempVault>;
  beforeEach(() => { vault = withTempVault(); });
  afterEach(() => vault.restore());

  it("lists distinct project and environment names in sorted order", () => {
    storeSecret("zeta", "prod", "A", "1");
    storeSecret("alpha", "prod", "B", "2");
    storeSecret("alpha", "staging", "C", "3");

    expect(projects()).toEqual(["alpha", "zeta"]);
    expect(environments()).toEqual(["prod", "staging"]);
  });

  it("returns an empty list on an empty vault", () => {
    expect(projects()).toEqual([]);
    expect(environments()).toEqual([]);
  });
});

describe("legacy schema migration", () => {
  let vault: ReturnType<typeof withTempVault>;
  beforeEach(() => { vault = withTempVault(); });
  afterEach(() => vault.restore());

  it("backfills pre-scoping rows under project=default, environment=default", () => {
    const key = getKey();
    closeDb();

    const dbPath = path.join(vault.home, "vault.db");
    const raw = new Database(dbPath);
    try {
      raw.exec("DROP TABLE IF EXISTS secrets");
      raw.exec(`
        CREATE TABLE secrets (
          name TEXT PRIMARY KEY,
          encrypted_value BLOB NOT NULL,
          iv BLOB NOT NULL,
          auth_tag BLOB NOT NULL,
          created_at TEXT NOT NULL DEFAULT (datetime('now')),
          updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
      `);
      const insert = raw.prepare("INSERT INTO secrets (name, encrypted_value, iv, auth_tag) VALUES (?, ?, ?, ?)");
      const legacy = encrypt("legacy-value", key);
      insert.run("LEGACY_ROW", legacy.encrypted, legacy.iv, legacy.authTag);
      const removed = encrypt("removed-feature-value", key);
      insert.run("_keyclasp_sso:config", removed.encrypted, removed.iv, removed.authTag);
    } finally {
      raw.close();
    }

    // Any call through getDb() lazily migrates the legacy table.
    const names = listSecrets("default", "default");
    expect(names).toContain("LEGACY_ROW");
    expect(names).not.toContain("_keyclasp_sso:config");
    expect(resolveSecret("default", "default", "LEGACY_ROW")).toBe("legacy-value");
    expect(resolveSecret("default", "default", "_keyclasp_sso:config")).toBeNull();

    const db = getDb();
    const columns = (db.pragma("table_info(secrets)") as { name: string }[]).map((r) => r.name);
    expect(columns).toEqual(expect.arrayContaining(["project", "environment", "name"]));

    const row = db.prepare("SELECT project, environment FROM secrets WHERE name = ?").get("LEGACY_ROW") as
      | { project: string; environment: string }
      | undefined;
    expect(row).toEqual({ project: "default", environment: "default" });
  });

  it("is idempotent when called again on an already-migrated vault", () => {
    storeSecret("app", "prod", "ALREADY_NEW", "value");
    const before = listSecrets() as ScopedSecret[];
    closeDb();
    const after = listSecrets() as ScopedSecret[];
    expect(after).toEqual(before);
  });
});

describe("bulk delete", () => {
  let vault: ReturnType<typeof withTempVault>;
  beforeEach(() => { vault = withTempVault(); });
  afterEach(() => vault.restore());

  it("deleteProject removes every environment in that project only", () => {
    storeSecret("app-a", "prod", "ONE", "1");
    storeSecret("app-a", "staging", "TWO", "2");
    storeSecret("app-b", "prod", "THREE", "3");

    const result = deleteProject("app-a");
    expect(result.deleted).toBe(2);
    expect(listSecrets("app-a") as ScopedSecret[]).toEqual([]);
    expect(resolveSecret("app-b", "prod", "THREE")).toBe("3");
  });

  it("deleteEnvironmentInProject removes only that project's environment", () => {
    storeSecret("app-a", "prod", "ONE", "1");
    storeSecret("app-a", "staging", "TWO", "2");
    storeSecret("app-b", "prod", "THREE", "3");

    const result = deleteEnvironmentInProject("app-a", "prod");
    expect(result.deleted).toBe(1);
    expect(resolveSecret("app-a", "prod", "ONE")).toBeNull();
    expect(resolveSecret("app-a", "staging", "TWO")).toBe("2");
    expect(resolveSecret("app-b", "prod", "THREE")).toBe("3");
  });

  it("deleteEnvironmentAcrossAllProjects removes that environment from every project", () => {
    storeSecret("app-a", "prod", "ONE", "1");
    storeSecret("app-a", "staging", "TWO", "2");
    storeSecret("app-b", "prod", "THREE", "3");

    const result = deleteEnvironmentAcrossAllProjects("prod");
    expect(result.deleted).toBe(2);
    expect(resolveSecret("app-a", "prod", "ONE")).toBeNull();
    expect(resolveSecret("app-b", "prod", "THREE")).toBeNull();
    expect(resolveSecret("app-a", "staging", "TWO")).toBe("2");
  });

  it("returns zero for a scope with nothing to delete", () => {
    expect(deleteProject("nonexistent")).toEqual({ deleted: 0 });
    expect(deleteEnvironmentInProject("nonexistent", "prod")).toEqual({ deleted: 0 });
    expect(deleteEnvironmentAcrossAllProjects("nonexistent")).toEqual({ deleted: 0 });
  });

  it("aborts when the confirmed scope changes before deletion", () => {
    storeSecret("app", "prod", "FIRST", "1");
    const snapshot = snapshotBulkDelete("app", "prod");
    storeSecret("app", "prod", "SECOND", "2");

    expect(() => deleteBulkIfUnchanged("app", "prod", snapshot)).toThrow(/scope changed/);
    expect(resolveSecret("app", "prod", "FIRST")).toBe("1");
    expect(resolveSecret("app", "prod", "SECOND")).toBe("2");
  });

  it("deletes a confirmed unchanged scope", () => {
    storeSecret("app", "prod", "FIRST", "1");
    storeSecret("app", "prod", "SECOND", "2");
    const snapshot = snapshotBulkDelete("app", "prod");

    expect(deleteBulkIfUnchanged("app", "prod", snapshot)).toEqual({ deleted: 2 });
    expect(listSecrets("app", "prod")).toEqual([]);
  });
});

describe("rename", () => {
  let vault: ReturnType<typeof withTempVault>;
  beforeEach(() => { vault = withTempVault(); });
  afterEach(() => vault.restore());

  it("renameProject moves every environment under a new project name", () => {
    storeSecret("old-app", "prod", "ONE", "1");
    storeSecret("old-app", "staging", "TWO", "2");

    const result = renameProject("old-app", "new-app");
    expect(result.moved).toBe(2);
    expect(resolveSecret("new-app", "prod", "ONE")).toBe("1");
    expect(resolveSecret("new-app", "staging", "TWO")).toBe("2");
    expect(listSecrets("old-app") as ScopedSecret[]).toEqual([]);
  });

  it("renameProject merges into an existing target project when names don't collide", () => {
    storeSecret("old-app", "prod", "ONE", "1");
    storeSecret("existing-app", "staging", "OTHER", "x");

    const result = renameProject("old-app", "existing-app");
    expect(result.moved).toBe(1);
    expect(resolveSecret("existing-app", "prod", "ONE")).toBe("1");
    expect(resolveSecret("existing-app", "staging", "OTHER")).toBe("x");
  });

  it("renameProject aborts entirely on any name collision, with zero writes", () => {
    storeSecret("old-app", "prod", "ONE", "old-value");
    storeSecret("old-app", "staging", "TWO", "2");
    storeSecret("new-app", "prod", "ONE", "existing-value");

    expect(() => renameProject("old-app", "new-app")).toThrow(/prod\/ONE/);

    // Zero writes: nothing moved, nothing overwritten.
    expect(resolveSecret("old-app", "prod", "ONE")).toBe("old-value");
    expect(resolveSecret("old-app", "staging", "TWO")).toBe("2");
    expect(resolveSecret("new-app", "prod", "ONE")).toBe("existing-value");
  });

  it("renameEnvironmentInProject moves one environment within one project", () => {
    storeSecret("app", "stagng", "ONE", "1");
    storeSecret("app", "prod", "TWO", "2");
    storeSecret("other-app", "stagng", "THREE", "3");

    const result = renameEnvironmentInProject("app", "stagng", "staging");
    expect(result.moved).toBe(1);
    expect(resolveSecret("app", "staging", "ONE")).toBe("1");
    expect(resolveSecret("app", "prod", "TWO")).toBe("2");
    expect(resolveSecret("other-app", "stagng", "THREE")).toBe("3");
  });

  it("renameEnvironmentInProject aborts on collision within the same project", () => {
    storeSecret("app", "stagng", "ONE", "old");
    storeSecret("app", "staging", "ONE", "existing");

    expect(() => renameEnvironmentInProject("app", "stagng", "staging")).toThrow(/ONE/);
    expect(resolveSecret("app", "stagng", "ONE")).toBe("old");
    expect(resolveSecret("app", "staging", "ONE")).toBe("existing");
  });

  it("renameEnvironmentAcrossAllProjects moves that environment for every project", () => {
    storeSecret("app-a", "stagng", "ONE", "1");
    storeSecret("app-b", "stagng", "TWO", "2");
    storeSecret("app-a", "prod", "THREE", "3");

    const result = renameEnvironmentAcrossAllProjects("stagng", "staging");
    expect(result.moved).toBe(2);
    expect(result.projectsAffected).toBe(2);
    expect(resolveSecret("app-a", "staging", "ONE")).toBe("1");
    expect(resolveSecret("app-b", "staging", "TWO")).toBe("2");
    expect(resolveSecret("app-a", "prod", "THREE")).toBe("3");
  });

  it("renameEnvironmentAcrossAllProjects aborts entirely if any single project collides", () => {
    storeSecret("app-a", "stagng", "ONE", "a-old");
    storeSecret("app-b", "stagng", "TWO", "b-old");
    storeSecret("app-b", "staging", "TWO", "b-existing");

    expect(() => renameEnvironmentAcrossAllProjects("stagng", "staging")).toThrow(/app-b\/TWO/);

    expect(resolveSecret("app-a", "stagng", "ONE")).toBe("a-old");
    expect(resolveSecret("app-b", "stagng", "TWO")).toBe("b-old");
    expect(resolveSecret("app-b", "staging", "TWO")).toBe("b-existing");
  });

  it("renameScope moves an exact (project, environment) pair to a different pair", () => {
    storeSecret("app", "stagng", "ONE", "1");

    const result = renameScope("app", "stagng", "app", "staging");
    expect(result.moved).toBe(1);
    expect(resolveSecret("app", "staging", "ONE")).toBe("1");
    expect(resolveSecret("app", "stagng", "ONE")).toBeNull();
  });

  it("renameScope aborts on collision at the exact target pair", () => {
    storeSecret("app", "stagng", "ONE", "old");
    storeSecret("app2", "staging", "ONE", "existing");

    expect(() => renameScope("app", "stagng", "app2", "staging")).toThrow(/ONE/);
    expect(resolveSecret("app", "stagng", "ONE")).toBe("old");
    expect(resolveSecret("app2", "staging", "ONE")).toBe("existing");
  });

  it("validates project/environment names before renaming", () => {
    expect(() => renameProject("", "new-app")).toThrow(/Invalid project name/);
    expect(() => validateScopeName("bad name", "environment")).toThrow(/Invalid environment name/);
  });
});
