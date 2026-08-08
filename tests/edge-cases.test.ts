import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const tmpDir = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-edge-")));
const vaultDir = path.join(tmpDir, ".keyclasp");
const previousKeyclaspHome = process.env.KEYCLASP_HOME;
process.env.KEYCLASP_HOME = vaultDir;

import {
  initializeVault,
  storeSecret,
  resolveSecret,
  listSecrets,
  deleteSecret,
  isInitialized,
  closeDb,
  validateScopeName,
} from "../src/vault.js";

beforeAll(() => {
  fs.mkdirSync(tmpDir, { recursive: true });
  fs.mkdirSync(vaultDir, { recursive: true });
  if (!isInitialized()) initializeVault("test-passphrase");
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

describe("special characters in secret names", () => {
  it("handles dots in names", () => {
    storeSecret("default", "default", "API.KEY.V1", "dot-value");
    expect(resolveSecret("default", "default", "API.KEY.V1")).toBe("dot-value");
    deleteSecret("default", "default", "API.KEY.V1");
  });

  it("handles hyphens and underscores", () => {
    storeSecret("default", "default", "MY-COOL_SECRET-123", "hyphen-underscore");
    expect(resolveSecret("default", "default", "MY-COOL_SECRET-123")).toBe("hyphen-underscore");
  });

  it("handles special characters in values", () => {
    const value = 'line1\nline2\t"quoted"\nbackslash\\here\n${VAR}';
    storeSecret("default", "default", "MULTILINE", value);
    expect(resolveSecret("default", "default", "MULTILINE")).toBe(value);
  });

  it("handles JSON in values", () => {
    const json = JSON.stringify({ key: "val", nested: { arr: [1, 2, 3] } });
    storeSecret("default", "default", "JSON_SECRET", json);
    expect(resolveSecret("default", "default", "JSON_SECRET")).toBe(json);
  });

  it("handles base64-looking values", () => {
    const b64 = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    storeSecret("default", "default", "JWT_TOKEN", b64);
    expect(resolveSecret("default", "default", "JWT_TOKEN")).toBe(b64);
  });
});

describe("empty and boundary values", () => {
  it("stores and resolves empty string", () => {
    storeSecret("default", "default", "EMPTY_VAL", "");
    expect(resolveSecret("default", "default", "EMPTY_VAL")).toBe("");
  });

  it("stores and resolves single character", () => {
    storeSecret("default", "default", "ONE_CHAR", "x");
    expect(resolveSecret("default", "default", "ONE_CHAR")).toBe("x");
  });

  it("stores and resolves a very long value (100KB)", () => {
    const long = "y".repeat(100_000);
    storeSecret("default", "default", "LONG_VAL", long);
    expect(resolveSecret("default", "default", "LONG_VAL")).toBe(long);
  });

  it("handles null bytes in values", () => {
    const withNull = "before\x00after";
    storeSecret("default", "default", "NULL_BYTE", withNull);
    expect(resolveSecret("default", "default", "NULL_BYTE")).toBe(withNull);
  });

  it("handles leading/trailing whitespace in values", () => {
    storeSecret("default", "default", "PADDED", "  padded-value  ");
    expect(resolveSecret("default", "default", "PADDED")).toBe("  padded-value  ");
  });
});

describe("vault operations on empty vault", () => {
  it("list returns array on populated vault", () => {
    const names = listSecrets("default", "default");
    expect(Array.isArray(names)).toBe(true);
  });

  it("resolve returns null for any name on empty lookup", () => {
    expect(resolveSecret("default", "default", "DOES_NOT_EXIST_" + Date.now())).toBeNull();
  });

  it("delete returns false for nonexistent", () => {
    expect(deleteSecret("default", "default", "NEVER_STORED_" + Date.now())).toBe(false);
  });
});

describe("many secrets", () => {
  const COUNT = 100;

  beforeAll(() => {
    for (let i = 0; i < COUNT; i++) {
      storeSecret("default", "default", `BULK_${i}`, `value-${i}`);
    }
  });

  it("lists all stored secrets", () => {
    const names = listSecrets("default", "default");
    for (let i = 0; i < COUNT; i++) {
      expect(names).toContain(`BULK_${i}`);
    }
  });

  it("resolves any random secret", () => {
    const idx = Math.floor(Math.random() * COUNT);
    expect(resolveSecret("default", "default", `BULK_${idx}`)).toBe(`value-${idx}`);
  });

  it("overwrites one of many", () => {
    storeSecret("default", "default", "BULK_50", "updated");
    expect(resolveSecret("default", "default", "BULK_50")).toBe("updated");
  });

  afterAll(() => {
    for (let i = 0; i < COUNT; i++) {
      deleteSecret("default", "default", `BULK_${i}`);
    }
  });
});

describe("overwrite behavior", () => {
  it("preserves only latest value after multiple overwrites", () => {
    const name = "OVERWRITE_TEST";
    storeSecret("default", "default", name, "v1");
    storeSecret("default", "default", name, "v2");
    storeSecret("default", "default", name, "v3");
    expect(resolveSecret("default", "default", name)).toBe("v3");
    deleteSecret("default", "default", name);
  });

  it("overwrite with empty string", () => {
    storeSecret("default", "default", "TO_EMPTY", "has-value");
    storeSecret("default", "default", "TO_EMPTY", "");
    expect(resolveSecret("default", "default", "TO_EMPTY")).toBe("");
    deleteSecret("default", "default", "TO_EMPTY");
  });
});

describe("stability: init when already initialized", () => {
  it("isInitialized returns true after init", () => {
    expect(isInitialized()).toBe(true);
  });
});

describe("project/environment name validation", () => {
  it("accepts single-character names", () => {
    expect(() => validateScopeName("a", "project")).not.toThrow();
  });

  it("accepts dots, hyphens, and underscores after the first character", () => {
    expect(() => validateScopeName("my-app_v1.2", "project")).not.toThrow();
  });

  it("rejects an empty name", () => {
    expect(() => validateScopeName("", "project")).toThrow(/Invalid project name/);
  });

  it("rejects a name with a leading dot, hyphen, or underscore", () => {
    expect(() => validateScopeName(".hidden", "environment")).toThrow(/Invalid environment name/);
    expect(() => validateScopeName("-flag", "environment")).toThrow(/Invalid environment name/);
    expect(() => validateScopeName("_internal", "environment")).toThrow(/Invalid environment name/);
  });

  it("rejects a name containing a null byte", () => {
    expect(() => validateScopeName("bad\0name", "project")).toThrow(/Invalid project name/);
  });

  it("rejects a name with disallowed characters", () => {
    expect(() => validateScopeName("has space", "project")).toThrow(/Invalid project name/);
    expect(() => validateScopeName("has/slash", "project")).toThrow(/Invalid project name/);
  });

  it("scopes the same secret name independently across projects and environments", () => {
    storeSecret("app-a", "prod", "SHARED_NAME", "value-a-prod");
    storeSecret("app-a", "staging", "SHARED_NAME", "value-a-staging");
    storeSecret("app-b", "prod", "SHARED_NAME", "value-b-prod");

    expect(resolveSecret("app-a", "prod", "SHARED_NAME")).toBe("value-a-prod");
    expect(resolveSecret("app-a", "staging", "SHARED_NAME")).toBe("value-a-staging");
    expect(resolveSecret("app-b", "prod", "SHARED_NAME")).toBe("value-b-prod");

    expect(deleteSecret("app-a", "prod", "SHARED_NAME")).toBe(true);
    expect(resolveSecret("app-a", "prod", "SHARED_NAME")).toBeNull();
    expect(resolveSecret("app-a", "staging", "SHARED_NAME")).toBe("value-a-staging");
    expect(resolveSecret("app-b", "prod", "SHARED_NAME")).toBe("value-b-prod");

    deleteSecret("app-a", "staging", "SHARED_NAME");
    deleteSecret("app-b", "prod", "SHARED_NAME");
  });
});
