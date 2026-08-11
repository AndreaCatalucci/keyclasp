import { describe, it, expect, beforeAll, afterAll } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

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
} from "../src/vault.js";

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
    storeSecret("TEST_KEY", "test-value-123");
    expect(resolveSecret("TEST_KEY")).toBe("test-value-123");
  });

  it("isolates the same secret name by project and environment", () => {
    storeSecret("footnote", "dev", "DATABASE_URL", "dev-database");
    storeSecret("footnote", "prod", "DATABASE_URL", "prod-database");
    storeSecret("other", "prod", "DATABASE_URL", "other-database");

    expect(resolveSecret("footnote", "dev", "DATABASE_URL")).toBe("dev-database");
    expect(resolveSecret("footnote", "prod", "DATABASE_URL")).toBe("prod-database");
    expect(resolveSecret("other", "prod", "DATABASE_URL")).toBe("other-database");
    expect(listSecrets("footnote", "prod")).toContain("DATABASE_URL");

    expect(deleteSecret("footnote", "prod", "DATABASE_URL")).toBe(true);
    expect(resolveSecret("footnote", "prod", "DATABASE_URL")).toBeNull();
    expect(resolveSecret("footnote", "dev", "DATABASE_URL")).toBe("dev-database");
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
      storeSecret("FIRST_KEY", "first-value");
      expect(resolveSecret("FIRST_KEY")).toBe("first-value");
      closeDb();

      process.env.KEYCLASP_HOME = secondHome;
      initializeVault("second-passphrase");
      storeSecret("SECOND_KEY", "second-value");
      expect(resolveSecret("SECOND_KEY")).toBe("second-value");

      closeDb();
      clearKey();
      expect(resolveSecret("SECOND_KEY")).toBe("second-value");
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
    expect(resolveSecret("NONEXISTENT")).toBeNull();
  });

  it("lists secret names", () => {
    storeSecret("LIST_TEST_1", "a");
    storeSecret("LIST_TEST_2", "b");
    const names = listSecrets();
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
      storeSecret(name, "removed-feature-value");
    }

    const names = listSecrets();
    for (const name of removedRecords) {
      expect(names).not.toContain(name);
      expect(resolveSecret(name)).toBeNull();
    }
  });

  it("hides internal double-underscore-prefixed rows from list output", () => {
    storeSecret("__keyclasp_internal__COUNTED", "internal-value");
    expect(listSecrets()).not.toContain("__keyclasp_internal__COUNTED");
    expect(resolveSecret("__keyclasp_internal__COUNTED")).toBe("internal-value");
  });

  it("updates an existing secret", () => {
    storeSecret("UPDATE_TEST", "old");
    storeSecret("UPDATE_TEST", "new");
    expect(resolveSecret("UPDATE_TEST")).toBe("new");
  });

  it("deletes a secret", () => {
    storeSecret("DELETE_TEST", "x");
    expect(deleteSecret("DELETE_TEST")).toBe(true);
    expect(resolveSecret("DELETE_TEST")).toBeNull();
    expect(deleteSecret("DELETE_TEST")).toBe(false);
  });
});
