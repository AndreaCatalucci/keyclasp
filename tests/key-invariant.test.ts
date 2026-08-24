import { describe, expect, it, beforeEach, afterEach } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  clearKey,
  closeDb,
  initializeVault,
  isInitialized,
  listSecrets,
  resolveSecret,
  setMachineIdentityForTests,
  storeSecret,
  unlockVault,
} from "../src/vault.js";

const previousKeyclaspHome = process.env.KEYCLASP_HOME;
const previousHome = process.env.HOME;
let tmpDir: string;
let vaultHome: string;
const keyFileMagic = Buffer.from("keyclasp:v5\n", "utf8");

function resetRuntime(): void {
  closeDb();
  clearKey();
}

function restartRuntime(): void {
  resetRuntime();
}

function keyPath(): string {
  return path.join(vaultHome, ".keyclasp.key");
}

function unlock(passphrase: string): void {
  unlockVault(passphrase);
}

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-key-invariant-"));
  vaultHome = path.join(tmpDir, ".keyclasp");
  process.env.KEYCLASP_HOME = vaultHome;
  setMachineIdentityForTests(null);
  resetRuntime();
});

afterEach(() => {
  setMachineIdentityForTests(null);
  resetRuntime();
  if (previousKeyclaspHome === undefined) {
    delete process.env.KEYCLASP_HOME;
  } else {
    process.env.KEYCLASP_HOME = previousKeyclaspHome;
  }
  if (previousHome === undefined) {
    delete process.env.HOME;
  } else {
    process.env.HOME = previousHome;
  }
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("vault key invariants", () => {
  it("round-trips many secrets after a fresh runtime reload for every read", () => {
    initializeVault("long-lived-passphrase");

    const fixtures = [
      ["PLAIN", "ordinary-value"],
      ["EMPTY", ""],
      ["MULTILINE", "line1\nline2\nline3"],
      ["UNICODE", "secret with unicode cafe"],
      ["NULL_BYTE", "before\x00after"],
      ["JSON", JSON.stringify({ token: "abc", nested: { count: 3 } })],
      ["LONG", crypto.randomBytes(128 * 1024).toString("base64")],
    ] as const;

    for (const [name, value] of fixtures) {
      storeSecret("default", "default", name, value);
      restartRuntime();
      unlock("long-lived-passphrase");
      expect(resolveSecret("default", "default", name)).toBe(value);
    }

    restartRuntime();
    unlock("long-lived-passphrase");
    for (const [name, value] of fixtures) {
      expect(resolveSecret("default", "default", name)).toBe(value);
    }
  });

  it("keeps resolving a repeatedly overwritten secret across runtime restarts", () => {
    initializeVault("overwrite-passphrase");

    for (let i = 0; i < 10; i++) {
      const value = `version-${i}-${crypto.randomBytes(512).toString("hex")}`;
      storeSecret("default", "default", "ROTATING_SECRET", value);
      restartRuntime();
      unlock("overwrite-passphrase");
      expect(resolveSecret("default", "default", "ROTATING_SECRET")).toBe(value);
    }
  });

  it("does not rewrite the key file when init is called on an initialized vault", () => {
    initializeVault("stable-passphrase");
    storeSecret("default", "default", "SURVIVES_REINIT", "stable-value");
    const before = fs.readFileSync(keyPath());

    restartRuntime();
    expect(isInitialized()).toBe(true);
    expect(() => initializeVault("different-passphrase")).toThrow(/already initialized/);

    const after = fs.readFileSync(keyPath());
    expect(after.equals(before)).toBe(true);

    restartRuntime();
    unlock("stable-passphrase");
    expect(resolveSecret("default", "default", "SURVIVES_REINIT")).toBe("stable-value");
  });

  it("does not let a cached key from one vault poison a newly initialized vault", () => {
    const firstHome = path.join(tmpDir, "first-home");
    const secondHome = path.join(tmpDir, "second-home");

    process.env.KEYCLASP_HOME = firstHome;
    initializeVault("first-passphrase");
    storeSecret("default", "default", "FIRST_SECRET", "first-value");
    expect(resolveSecret("default", "default", "FIRST_SECRET")).toBe("first-value");
    const firstKey = fs.readFileSync(path.join(firstHome, ".keyclasp.key"));

    process.env.KEYCLASP_HOME = secondHome;
    initializeVault("second-passphrase");
    storeSecret("default", "default", "SECOND_SECRET", "second-value");
    expect(resolveSecret("default", "default", "SECOND_SECRET")).toBe("second-value");
    const secondKey = fs.readFileSync(path.join(secondHome, ".keyclasp.key"));
    expect(secondKey.equals(firstKey)).toBe(false);

    restartRuntime();
    unlock("second-passphrase");
    expect(resolveSecret("default", "default", "SECOND_SECRET")).toBe("second-value");

    process.env.KEYCLASP_HOME = firstHome;
    restartRuntime();
    unlock("first-passphrase");
    expect(resolveSecret("default", "default", "FIRST_SECRET")).toBe("first-value");
  });

  it("switches vault homes in one process without reusing the previous key or database", () => {
    const homeA = path.join(tmpDir, "switch-a", ".keyclasp");
    const homeB = path.join(tmpDir, "switch-b", ".keyclasp");

    process.env.KEYCLASP_HOME = homeA;
    initializeVault("a-passphrase");
    storeSecret("default", "default", "ONLY_A", "a-value");

    process.env.KEYCLASP_HOME = homeB;
    initializeVault("b-passphrase");
    storeSecret("default", "default", "ONLY_B", "b-value");

    process.env.KEYCLASP_HOME = homeA;
    unlock("a-passphrase");
    expect(resolveSecret("default", "default", "ONLY_A")).toBe("a-value");
    expect(resolveSecret("default", "default", "ONLY_B")).toBeNull();

    process.env.KEYCLASP_HOME = homeB;
    unlock("b-passphrase");
    expect(resolveSecret("default", "default", "ONLY_B")).toBe("b-value");
    expect(resolveSecret("default", "default", "ONLY_A")).toBeNull();
  });

  it("writes v5 key bundles that do not depend on the legacy machine identity", () => {
    setMachineIdentityForTests({
      stable: Buffer.from("stable-machine-id-32-byte-value!"),
      legacy: Buffer.from("legacy-before-change-32-byte-val"),
    });
    initializeVault("stable-machine-passphrase");
    storeSecret("default", "default", "STABLE_MACHINE", "survives-platform-drift");
    expect(fs.readFileSync(keyPath()).subarray(0, keyFileMagic.length).equals(keyFileMagic)).toBe(true);

    restartRuntime();
    setMachineIdentityForTests({
      stable: Buffer.from("stable-machine-id-32-byte-value!"),
      legacy: Buffer.from("legacy-after-change-32-byte-valu"),
    });
    unlock("stable-machine-passphrase");

    expect(resolveSecret("default", "default", "STABLE_MACHINE")).toBe("survives-platform-drift");
  });

  it("uses ~/.keyclasp when KEYCLASP_HOME is unset", () => {
    const preferredHome = path.join(tmpDir, ".keyclasp");
    delete process.env.KEYCLASP_HOME;
    process.env.HOME = tmpDir;
    restartRuntime();

    initializeVault("home-passphrase");
    expect(fs.existsSync(path.join(preferredHome, ".keyclasp.key"))).toBe(true);
  });

  it("refuses to initialize a fresh key over an existing vault database", () => {
    initializeVault("original-passphrase");
    storeSecret("default", "default", "ORPHAN_DB_SECRET", "do-not-overwrite");
    const originalKey = fs.readFileSync(keyPath());
    closeDb();
    clearKey();
    fs.unlinkSync(keyPath());

    expect(() => initializeVault("replacement-passphrase")).toThrow(/database exists without a key file/);
    expect(fs.existsSync(keyPath())).toBe(false);

    fs.writeFileSync(keyPath(), originalKey, { mode: 0o600 });
    restartRuntime();
    unlock("original-passphrase");
    expect(resolveSecret("default", "default", "ORPHAN_DB_SECRET")).toBe("do-not-overwrite");
  });

  it("blocks writes when the key file no longer unlocks existing vault data", () => {
    const homeA = path.join(tmpDir, "drift-a", ".keyclasp");
    const homeB = path.join(tmpDir, "drift-b", ".keyclasp");

    process.env.KEYCLASP_HOME = homeA;
    initializeVault("home-a");
    storeSecret("default", "default", "EXISTING", "existing-value");
    const originalKey = fs.readFileSync(path.join(homeA, ".keyclasp.key"));

    process.env.KEYCLASP_HOME = homeB;
    initializeVault("home-b");
    const wrongKey = fs.readFileSync(path.join(homeB, ".keyclasp.key"));

    fs.writeFileSync(path.join(homeA, ".keyclasp.key"), wrongKey, { mode: 0o600 });
    process.env.KEYCLASP_HOME = homeA;
    restartRuntime();
    expect(() => unlock("home-b")).toThrow(/does not unlock this vault/);

    fs.writeFileSync(path.join(homeA, ".keyclasp.key"), originalKey, { mode: 0o600 });
    restartRuntime();
    unlock("home-a");
    expect(resolveSecret("default", "default", "EXISTING")).toBe("existing-value");
    expect(resolveSecret("default", "default", "NEW_AFTER_DRIFT")).toBeNull();
  });

  it("rejects a mismatched key file even when the vault has no secret rows", () => {
    const homeA = path.join(tmpDir, "empty-a", ".keyclasp");
    const homeB = path.join(tmpDir, "empty-b", ".keyclasp");

    process.env.KEYCLASP_HOME = homeA;
    initializeVault("home-a");
    process.env.KEYCLASP_HOME = homeB;
    initializeVault("home-b");
    const wrongKey = fs.readFileSync(path.join(homeB, ".keyclasp.key"));
    fs.writeFileSync(path.join(homeA, ".keyclasp.key"), wrongKey, { mode: 0o600 });

    process.env.KEYCLASP_HOME = homeA;
    restartRuntime();
    expect(() => unlock("home-b")).toThrow(/does not unlock this vault/);
  });

  it("detects key/vault drift before exposing secret-name metadata", () => {
    const homeA = path.join(tmpDir, "home-a", ".keyclasp");
    const homeB = path.join(tmpDir, "home-b", ".keyclasp");

    process.env.KEYCLASP_HOME = homeA;
    initializeVault("");
    storeSecret("default", "default", "REPRO_SECRET", "not-a-real-secret");
    expect(resolveSecret("default", "default", "REPRO_SECRET")).toBe("not-a-real-secret");

    process.env.KEYCLASP_HOME = homeB;
    restartRuntime();
    initializeVault("");

    fs.copyFileSync(path.join(homeB, ".keyclasp.key"), path.join(homeA, ".keyclasp.key"));

    process.env.KEYCLASP_HOME = homeA;
    restartRuntime();
    expect(() => listSecrets("default", "default")).toThrow(/does not unlock this vault/i);
    expect(() => resolveSecret("default", "default", "REPRO_SECRET")).toThrow(/does not unlock this vault|authenticate data|decrypt/i);
  });
});
