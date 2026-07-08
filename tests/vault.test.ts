import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// We need to intercept the vault path before vault.ts loads its module-level state.
// The vault uses ~/.keyblind/ — we redirect to a temp dir for testing.
const tmpDir = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "keyblind-test-")));
const vaultDir = path.join(tmpDir, ".keyblind");

// Intercept os.homedir so vault.ts creates files in our temp directory
vi.mock("node:os", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:os")>();
  return {
    ...actual,
    homedir: () => tmpDir,
  };
});

// Now we can dynamically import vault after mocking
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
} from "../src/vault.js";

beforeAll(() => {
  // Create temp home so vault init doesn't fail on missing directory
  fs.mkdirSync(tmpDir, { recursive: true });
  fs.mkdirSync(vaultDir, { recursive: true });
});

afterAll(() => {
  closeDb();
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
