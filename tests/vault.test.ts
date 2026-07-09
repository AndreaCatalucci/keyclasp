import { describe, it, expect, beforeAll, afterAll } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const tmpDir = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "keyblind-test-")));
const vaultDir = path.join(tmpDir, ".keyblind");
const previousKeyblindHome = process.env.KEYBLIND_HOME;
process.env.KEYBLIND_HOME = vaultDir;

import {
  encrypt,
  decrypt,
  initializeVault,
  storeSecret,
  resolveSecret,
  resolveSecretWithAlias,
  listSecrets,
  createAlias,
  deleteAlias,
  listAliases,
  deleteSecret,
  isInitialized,
  closeDb,
  clearKey,
  countSecretsByPrefix,
} from "../src/vault.js";
import { setBackend } from "../src/backends.js";
import { createServer } from "../src/server.js";
import { getSecretHistory, saveHistory } from "../src/sync.js";

beforeAll(() => {
  process.env.KEYBLIND_HOME = vaultDir;
  fs.mkdirSync(tmpDir, { recursive: true });
  fs.mkdirSync(vaultDir, { recursive: true });
});

afterAll(() => {
  closeDb();
  if (previousKeyblindHome === undefined) {
    delete process.env.KEYBLIND_HOME;
  } else {
    process.env.KEYBLIND_HOME = previousKeyblindHome;
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

  it("uses the newly initialized key after another vault key was cached", () => {
    const originalHome = process.env.KEYBLIND_HOME;
    const firstHome = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "keyblind-first-")), ".keyblind");
    const secondHome = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "keyblind-second-")), ".keyblind");

    try {
      closeDb();
      clearKey();

      process.env.KEYBLIND_HOME = firstHome;
      initializeVault("first-passphrase");
      storeSecret("FIRST_KEY", "first-value");
      expect(resolveSecret("FIRST_KEY")).toBe("first-value");
      closeDb();

      process.env.KEYBLIND_HOME = secondHome;
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
        delete process.env.KEYBLIND_HOME;
      } else {
        process.env.KEYBLIND_HOME = originalHome;
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
      "_keyblind_sso:config",
      "_keyblind_sso:token",
      "_keyblind_deadman:config",
      "_keyblind_deadman:last_checkin",
      "__keyblind_team_check",
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

  it("counts internal records by prefix without exposing them in list output", () => {
    storeSecret("__keyblind_sandbox_backup__COUNTED", "backup-value");
    expect(countSecretsByPrefix("__keyblind_sandbox_backup__")).toBeGreaterThanOrEqual(1);
    expect(listSecrets()).not.toContain("__keyblind_sandbox_backup__COUNTED");
  });

  it("updates an existing secret", () => {
    storeSecret("UPDATE_TEST", "old");
    storeSecret("UPDATE_TEST", "new");
    expect(resolveSecret("UPDATE_TEST")).toBe("new");
  });

  it("saves the caller-provided previous value to history", () => {
    const historyName = `HISTORY_FROM_VALUE_${crypto.randomUUID()}`;
    saveHistory(historyName, "previous-external-value");
    const history = getSecretHistory(historyName);
    expect(history).toHaveLength(1);
    expect(history[0].value).toBe("previous-external-value");
  });

  it("rotates secrets through the configured backend", async () => {
    const secretName = `KEYBLIND_ENV_ROTATE_${crypto.randomUUID()}`;
    process.env[secretName] = "from-env-backend";
    setBackend("env");
    try {
      const server = createServer() as any;
      const result = await server._registeredTools.rotate_secret.handler({
        name: secretName,
        value: "new-value",
      });

      expect(result.isError).toBe(true);
      expect(JSON.parse(result.content[0].text).error).toContain("Env backend is read-only");
      expect(getSecretHistory(secretName)).toHaveLength(0);
    } finally {
      setBackend("local");
      delete process.env[secretName];
    }
  });

  it("deletes a secret", () => {
    storeSecret("DELETE_TEST", "x");
    expect(deleteSecret("DELETE_TEST")).toBe(true);
    expect(resolveSecret("DELETE_TEST")).toBeNull();
    expect(deleteSecret("DELETE_TEST")).toBe(false);
  });
});

describe("secret aliases", () => {
  beforeAll(() => {
    if (!isInitialized()) {
      initializeVault("test-passphrase");
    }
  });

  it("resolves an alias without creating a duplicate secret", () => {
    storeSecret("ALIAS_HELLO", "hello-value");
    createAlias("ALIAS_WORLD", "ALIAS_HELLO");

    const resolved = resolveSecretWithAlias("ALIAS_WORLD");

    expect(resolved).toEqual({
      requestedName: "ALIAS_WORLD",
      resolvedName: "ALIAS_HELLO",
      aliasUsed: true,
      value: "hello-value",
    });
    expect(listSecrets()).toContain("ALIAS_HELLO");
    expect(listSecrets()).not.toContain("ALIAS_WORLD");
    expect(listAliases()).toEqual(expect.arrayContaining([
      expect.objectContaining({ alias: "ALIAS_WORLD", target: "ALIAS_HELLO" }),
    ]));
  });

  it("rejects aliases that collide with canonical secrets", () => {
    storeSecret("ALIAS_CANONICAL", "value");
    storeSecret("ALIAS_COLLISION", "existing");

    expect(() => createAlias("ALIAS_COLLISION", "ALIAS_CANONICAL")).toThrow(/already exists as a secret/);
    expect(resolveSecret("ALIAS_COLLISION")).toBe("existing");
  });

  it("rejects alias chains and internal names", () => {
    storeSecret("ALIAS_CHAIN_TARGET", "value");
    createAlias("ALIAS_CHAIN_ONE", "ALIAS_CHAIN_TARGET");

    expect(() => createAlias("ALIAS_CHAIN_TWO", "ALIAS_CHAIN_ONE")).toThrow(/target another alias/);
    expect(() => createAlias("__keyblind_ALIAS", "ALIAS_CHAIN_TARGET")).toThrow(/reserved/);
    expect(() => createAlias("_totp_ALIAS", "ALIAS_CHAIN_TARGET")).toThrow(/reserved/);
    expect(() => createAlias("_keyblind_sso:token", "ALIAS_CHAIN_TARGET")).toThrow(/reserved/);
  });

  it("removes aliases when deleting the target secret", () => {
    storeSecret("ALIAS_DELETE_TARGET", "value");
    createAlias("ALIAS_DELETE_ALIAS", "ALIAS_DELETE_TARGET");

    expect(deleteSecret("ALIAS_DELETE_TARGET")).toBe(true);

    expect(resolveSecretWithAlias("ALIAS_DELETE_ALIAS").value).toBeNull();
    expect(listAliases().map((alias) => alias.alias)).not.toContain("ALIAS_DELETE_ALIAS");
  });

  it("deletes only alias metadata", () => {
    storeSecret("ALIAS_KEEP_TARGET", "value");
    createAlias("ALIAS_REMOVE_ONLY", "ALIAS_KEEP_TARGET");

    expect(deleteAlias("ALIAS_REMOVE_ONLY")).toBe(true);

    expect(resolveSecret("ALIAS_KEEP_TARGET")).toBe("value");
    expect(resolveSecretWithAlias("ALIAS_REMOVE_ONLY").value).toBeNull();
  });
});
