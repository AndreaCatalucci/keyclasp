import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const tmpDir = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "keyblind-edge-")));
const vaultDir = path.join(tmpDir, ".keyblind");

import {
  initializeVault,
  storeSecret,
  resolveSecret,
  listSecrets,
  deleteSecret,
  isInitialized,
  closeDb,
} from "../src/vault.js";

beforeAll(() => {
  process.env.KEYBLIND_HOME = vaultDir;
  fs.mkdirSync(tmpDir, { recursive: true });
  fs.mkdirSync(vaultDir, { recursive: true });
  if (!isInitialized()) initializeVault("test-passphrase");
});

afterAll(() => {
  closeDb();
  delete process.env.KEYBLIND_HOME;
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("special characters in secret names", () => {
  it("handles dots in names", () => {
    storeSecret("API.KEY.V1", "dot-value");
    expect(resolveSecret("API.KEY.V1")).toBe("dot-value");
    deleteSecret("API.KEY.V1");
  });

  it("handles hyphens and underscores", () => {
    storeSecret("MY-COOL_SECRET-123", "hyphen-underscore");
    expect(resolveSecret("MY-COOL_SECRET-123")).toBe("hyphen-underscore");
  });

  it("handles special characters in values", () => {
    const value = 'line1\nline2\t"quoted"\nbackslash\\here\n${VAR}';
    storeSecret("MULTILINE", value);
    expect(resolveSecret("MULTILINE")).toBe(value);
  });

  it("handles JSON in values", () => {
    const json = JSON.stringify({ key: "val", nested: { arr: [1, 2, 3] } });
    storeSecret("JSON_SECRET", json);
    expect(resolveSecret("JSON_SECRET")).toBe(json);
  });

  it("handles base64-looking values", () => {
    const b64 = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    storeSecret("JWT_TOKEN", b64);
    expect(resolveSecret("JWT_TOKEN")).toBe(b64);
  });
});

describe("empty and boundary values", () => {
  it("stores and resolves empty string", () => {
    storeSecret("EMPTY_VAL", "");
    expect(resolveSecret("EMPTY_VAL")).toBe("");
  });

  it("stores and resolves single character", () => {
    storeSecret("ONE_CHAR", "x");
    expect(resolveSecret("ONE_CHAR")).toBe("x");
  });

  it("stores and resolves a very long value (100KB)", () => {
    const long = "y".repeat(100_000);
    storeSecret("LONG_VAL", long);
    expect(resolveSecret("LONG_VAL")).toBe(long);
  });

  it("handles null bytes in values", () => {
    const withNull = "before\x00after";
    storeSecret("NULL_BYTE", withNull);
    expect(resolveSecret("NULL_BYTE")).toBe(withNull);
  });

  it("handles leading/trailing whitespace in values", () => {
    storeSecret("PADDED", "  padded-value  ");
    expect(resolveSecret("PADDED")).toBe("  padded-value  ");
  });
});

describe("vault operations on empty vault", () => {
  it("list returns array on populated vault", () => {
    const names = listSecrets();
    expect(Array.isArray(names)).toBe(true);
  });

  it("resolve returns null for any name on empty lookup", () => {
    expect(resolveSecret("DOES_NOT_EXIST_" + Date.now())).toBeNull();
  });

  it("delete returns false for nonexistent", () => {
    expect(deleteSecret("NEVER_STORED_" + Date.now())).toBe(false);
  });
});

describe("many secrets", () => {
  const COUNT = 100;

  beforeAll(() => {
    for (let i = 0; i < COUNT; i++) {
      storeSecret(`BULK_${i}`, `value-${i}`);
    }
  });

  it("lists all stored secrets", () => {
    const names = listSecrets();
    for (let i = 0; i < COUNT; i++) {
      expect(names).toContain(`BULK_${i}`);
    }
  });

  it("resolves any random secret", () => {
    const idx = Math.floor(Math.random() * COUNT);
    expect(resolveSecret(`BULK_${idx}`)).toBe(`value-${idx}`);
  });

  it("overwrites one of many", () => {
    storeSecret("BULK_50", "updated");
    expect(resolveSecret("BULK_50")).toBe("updated");
  });

  afterAll(() => {
    for (let i = 0; i < COUNT; i++) {
      deleteSecret(`BULK_${i}`);
    }
  });
});

describe("overwrite behavior", () => {
  it("preserves only latest value after multiple overwrites", () => {
    const name = "OVERWRITE_TEST";
    storeSecret(name, "v1");
    storeSecret(name, "v2");
    storeSecret(name, "v3");
    expect(resolveSecret(name)).toBe("v3");
    deleteSecret(name);
  });

  it("overwrite with empty string", () => {
    storeSecret("TO_EMPTY", "has-value");
    storeSecret("TO_EMPTY", "");
    expect(resolveSecret("TO_EMPTY")).toBe("");
    deleteSecret("TO_EMPTY");
  });
});

describe("stability: init when already initialized", () => {
  it("isInitialized returns true after init", () => {
    expect(isInitialized()).toBe(true);
  });
});
