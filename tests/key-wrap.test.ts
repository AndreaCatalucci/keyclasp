import { afterEach, beforeEach, describe, expect, it } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  clearKey,
  closeDb,
  initializeVault,
  listSecrets,
  resolveSecret,
  setMachineIdentityForTests,
  storeSecret,
  unlockVault,
  vaultHasPassphrase,
  verifyVaultPassphrase,
} from "../src/vault.js";

const KEY_FILE_MAGIC_V3 = Buffer.from("keyclasp:v3\n", "utf8");
const KEY_FILE_MAGIC_V2 = Buffer.from("keyclasp:v2\n", "utf8");

const previousKeyclaspHome = process.env.KEYCLASP_HOME;
let tmpDir: string;
let vaultHome: string;

function resetRuntime(): void {
  closeDb();
  clearKey();
}

function keyPath(): string {
  return path.join(vaultHome, ".keyclasp.key");
}

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-wrap-"));
  vaultHome = path.join(tmpDir, ".keyclasp");
  process.env.KEYCLASP_HOME = vaultHome;
  setMachineIdentityForTests(null);
  resetRuntime();
});

afterEach(() => {
  setMachineIdentityForTests(null);
  resetRuntime();
  if (previousKeyclaspHome === undefined) delete process.env.KEYCLASP_HOME;
  else process.env.KEYCLASP_HOME = previousKeyclaspHome;
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("v3 passphrase wrap", () => {
  it("writes v3 magic and round-trips a secret in the same process", () => {
    initializeVault("wrap-passphrase");
    storeSecret("default", "default", "API_KEY", "sk-live-value");
    expect(fs.readFileSync(keyPath()).subarray(0, KEY_FILE_MAGIC_V3.length).equals(KEY_FILE_MAGIC_V3)).toBe(true);
    expect(resolveSecret("default", "default", "API_KEY")).toBe("sk-live-value");
    expect(vaultHasPassphrase()).toBe(true);
  });

  it("refuses to resolve after clearKey until unlock succeeds", () => {
    initializeVault("wrap-passphrase");
    storeSecret("default", "default", "API_KEY", "sk-live-value");
    resetRuntime();

    expect(() => resolveSecret("default", "default", "API_KEY")).toThrow(/locked|passphrase/i);
    expect(() => unlockVault("wrong-passphrase")).toThrow(/passphrase/i);
    expect(() => resolveSecret("default", "default", "API_KEY")).toThrow(/locked|passphrase/i);

    unlockVault("wrap-passphrase");
    expect(resolveSecret("default", "default", "API_KEY")).toBe("sk-live-value");
  });

  it("fails closed on a wrong passphrase without needing a secret row", () => {
    initializeVault("wrap-passphrase");
    resetRuntime();
    expect(() => unlockVault("nope")).toThrow(/passphrase/i);
  });

  it("fails closed when the wrap tag is truncated or flipped", () => {
    initializeVault("wrap-passphrase");
    storeSecret("default", "default", "API_KEY", "sk-live-value");
    const bytes = fs.readFileSync(keyPath());
    bytes[bytes.length - 1] ^= 0xff;
    fs.writeFileSync(keyPath(), bytes, { mode: 0o600 });
    resetRuntime();
    expect(() => unlockVault("wrap-passphrase")).toThrow();
  });
});

describe("v3 machine wrap", () => {
  it("writes machine mode for an empty init passphrase", () => {
    initializeVault("");
    expect(vaultHasPassphrase()).toBe(false);
    expect(verifyVaultPassphrase("")).toBe(true);
    expect(verifyVaultPassphrase("anything")).toBe(false);
    storeSecret("default", "default", "API_KEY", "machine-value");
    resetRuntime();
    expect(resolveSecret("default", "default", "API_KEY")).toBe("machine-value");
  });

  it("fails machine unwrap when the test identity changes", () => {
    setMachineIdentityForTests({ stable: Buffer.from("stable-machine-id-32-byte-value!") });
    initializeVault("");
    storeSecret("default", "default", "API_KEY", "machine-value");
    resetRuntime();
    setMachineIdentityForTests({ stable: Buffer.from("different-machine-id-32-bytes!!") });
    expect(() => resolveSecret("default", "default", "API_KEY")).toThrow(/does not unlock|machine|identity/i);
  });
});

describe("old key file refusal", () => {
  it("refuses a v2 XOR key file on list and resolve", () => {
    initializeVault("wrap-passphrase");
    storeSecret("default", "default", "API_KEY", "sk-live-value");
    const salt = crypto.randomBytes(32);
    const fakeV2 = Buffer.concat([KEY_FILE_MAGIC_V2, salt, crypto.randomBytes(32)]);
    fs.writeFileSync(keyPath(), fakeV2, { mode: 0o600 });
    resetRuntime();

    expect(() => listSecrets("default", "default")).toThrow(/old|migrate|unsupported|v2/i);
    expect(() => resolveSecret("default", "default", "API_KEY")).toThrow(/old|migrate|unsupported|v2/i);
  });
});
