import { describe, it, expect, beforeEach, afterEach } from "vitest";
import crypto from "node:crypto";
import Database from "better-sqlite3";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  clearKey,
  checkVaultDecryptability,
  closeDb,
  encrypt,
  initializeVault,
  isInitialized,
  listSecrets,
  resolveSecret,
  setProjectName,
  setMachineIdentityForTests,
  storeSecret,
} from "../src/vault.js";
import { getSecretHistory, rotateLocalSecret } from "../src/sync.js";
import { runDoctor } from "../src/doctor.js";

const previousKeyblindHome = process.env.KEYBLIND_HOME;
let tmpDir: string;
let vaultHome: string;
const keyFileMagic = Buffer.from("keyblind:v2\n", "utf8");

function resetRuntime(): void {
  closeDb();
  clearKey();
}

function restartRuntime(): void {
  resetRuntime();
}

function keyPath(project?: string): string {
  return project
    ? path.join(vaultHome, "projects", project, ".keyblind.key")
    : path.join(vaultHome, ".keyblind.key");
}

function keyBackupPath(index: number): string {
  return `${keyPath()}.${index}.bak`;
}

function xorWithKey(key: Buffer, wrappingKey: Buffer): Buffer {
  const output = Buffer.alloc(key.length);
  for (let i = 0; i < key.length; i++) {
    output[i] = key[i] ^ wrappingKey[i % wrappingKey.length];
  }
  return output;
}

function writeLegacyVault(secretName: string, secretValue: string, legacyIdentity: Buffer): void {
  fs.mkdirSync(vaultHome, { recursive: true, mode: 0o700 });
  const salt = crypto.randomBytes(32);
  const key = crypto.pbkdf2Sync("legacy-passphrase", salt, 600_000, 32, "sha256");
  fs.writeFileSync(keyPath(), Buffer.concat([salt, xorWithKey(key, legacyIdentity)]), { mode: 0o600 });

  const { encrypted, iv, authTag } = encrypt(secretValue, key);
  const db = new Database(path.join(vaultHome, "vault.db"));
  try {
    db.exec(`
      CREATE TABLE secrets (
        name TEXT PRIMARY KEY,
        encrypted_value BLOB NOT NULL,
        iv BLOB NOT NULL,
        auth_tag BLOB NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `);
    db.prepare("INSERT INTO secrets (name, encrypted_value, iv, auth_tag) VALUES (?, ?, ?, ?)").run(
      secretName,
      encrypted,
      iv,
      authTag,
    );
  } finally {
    db.close();
  }
}

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "keyblind-key-invariant-"));
  vaultHome = path.join(tmpDir, ".keyblind");
  process.env.KEYBLIND_HOME = vaultHome;
  setMachineIdentityForTests(null);
  setProjectName(null);
  resetRuntime();
});

afterEach(() => {
  setMachineIdentityForTests(null);
  setProjectName(null);
  resetRuntime();
  if (previousKeyblindHome === undefined) {
    delete process.env.KEYBLIND_HOME;
  } else {
    process.env.KEYBLIND_HOME = previousKeyblindHome;
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
      storeSecret(name, value);
      restartRuntime();
      expect(resolveSecret(name)).toBe(value);
    }

    restartRuntime();
    for (const [name, value] of fixtures) {
      expect(resolveSecret(name)).toBe(value);
    }
  });

  it("keeps resolving a repeatedly overwritten secret across runtime restarts", () => {
    initializeVault("overwrite-passphrase");

    for (let i = 0; i < 75; i++) {
      const value = `version-${i}-${crypto.randomBytes(512).toString("hex")}`;
      storeSecret("ROTATING_SECRET", value);
      restartRuntime();
      expect(resolveSecret("ROTATING_SECRET")).toBe(value);
    }
  });

  it("does not rewrite the key file when init is called on an initialized vault", () => {
    initializeVault("stable-passphrase");
    storeSecret("SURVIVES_REINIT", "stable-value");
    const before = fs.readFileSync(keyPath());

    restartRuntime();
    expect(isInitialized()).toBe(true);
    expect(() => initializeVault("different-passphrase")).toThrow(/already initialized/);

    const after = fs.readFileSync(keyPath());
    expect(after.equals(before)).toBe(true);

    restartRuntime();
    expect(resolveSecret("SURVIVES_REINIT")).toBe("stable-value");
  });

  it("does not let a cached key from one vault poison a newly initialized vault", () => {
    const firstHome = path.join(tmpDir, "first-home");
    const secondHome = path.join(tmpDir, "second-home");

    process.env.KEYBLIND_HOME = firstHome;
    initializeVault("first-passphrase");
    storeSecret("FIRST_SECRET", "first-value");
    expect(resolveSecret("FIRST_SECRET")).toBe("first-value");
    const firstKey = fs.readFileSync(path.join(firstHome, ".keyblind.key"));

    process.env.KEYBLIND_HOME = secondHome;
    initializeVault("second-passphrase");
    storeSecret("SECOND_SECRET", "second-value");
    expect(resolveSecret("SECOND_SECRET")).toBe("second-value");
    const secondKey = fs.readFileSync(path.join(secondHome, ".keyblind.key"));
    expect(secondKey.equals(firstKey)).toBe(false);

    restartRuntime();
    expect(resolveSecret("SECOND_SECRET")).toBe("second-value");

    process.env.KEYBLIND_HOME = firstHome;
    restartRuntime();
    expect(resolveSecret("FIRST_SECRET")).toBe("first-value");
  });

  it("switches vault homes in one process without reusing the previous key or database", () => {
    const homeA = path.join(tmpDir, "switch-a", ".keyblind");
    const homeB = path.join(tmpDir, "switch-b", ".keyblind");

    process.env.KEYBLIND_HOME = homeA;
    initializeVault("a-passphrase");
    storeSecret("ONLY_A", "a-value");

    process.env.KEYBLIND_HOME = homeB;
    initializeVault("b-passphrase");
    storeSecret("ONLY_B", "b-value");

    process.env.KEYBLIND_HOME = homeA;
    expect(resolveSecret("ONLY_A")).toBe("a-value");
    expect(resolveSecret("ONLY_B")).toBeNull();

    process.env.KEYBLIND_HOME = homeB;
    expect(resolveSecret("ONLY_B")).toBe("b-value");
    expect(resolveSecret("ONLY_A")).toBeNull();
  });

  it("writes stable v2 key files that survive legacy machine identity changes", () => {
    setMachineIdentityForTests({
      stable: Buffer.from("stable-machine-id-32-byte-value!"),
      legacy: Buffer.from("legacy-before-change-32-byte-val"),
    });
    initializeVault("stable-machine-passphrase");
    storeSecret("STABLE_MACHINE", "survives-platform-drift");
    expect(fs.readFileSync(keyPath()).subarray(0, keyFileMagic.length).equals(keyFileMagic)).toBe(true);

    restartRuntime();
    setMachineIdentityForTests({
      stable: Buffer.from("stable-machine-id-32-byte-value!"),
      legacy: Buffer.from("legacy-after-change-32-byte-valu"),
    });

    expect(resolveSecret("STABLE_MACHINE")).toBe("survives-platform-drift");
  });

  it("migrates legacy key files after a successful read so future legacy identity drift cannot break them", () => {
    const stableIdentity = Buffer.from("stable-legacy-migration-identity");
    const originalLegacyIdentity = Buffer.from("legacy-migration-before-change");
    writeLegacyVault("LEGACY_SECRET", "legacy-still-readable", originalLegacyIdentity);
    const legacyKeyFile = fs.readFileSync(keyPath());
    const existingBackup = Buffer.from("existing backup should not be overwritten");
    fs.writeFileSync(keyBackupPath(1), existingBackup, { mode: 0o600 });

    setMachineIdentityForTests({
      stable: stableIdentity,
      legacy: originalLegacyIdentity,
    });
    expect(resolveSecret("LEGACY_SECRET")).toBe("legacy-still-readable");
    expect(fs.readFileSync(keyPath()).subarray(0, keyFileMagic.length).equals(keyFileMagic)).toBe(true);
    expect(fs.readFileSync(keyBackupPath(1)).equals(existingBackup)).toBe(true);
    expect(fs.readFileSync(keyBackupPath(2)).equals(legacyKeyFile)).toBe(true);

    restartRuntime();
    setMachineIdentityForTests({
      stable: stableIdentity,
      legacy: Buffer.from("legacy-migration-after-change!"),
    });
    expect(resolveSecret("LEGACY_SECRET")).toBe("legacy-still-readable");
  });

  it("refuses to initialize a fresh key over an existing vault database", () => {
    initializeVault("original-passphrase");
    storeSecret("ORPHAN_DB_SECRET", "do-not-overwrite");
    const originalKey = fs.readFileSync(keyPath());
    closeDb();
    clearKey();
    fs.unlinkSync(keyPath());

    expect(() => initializeVault("replacement-passphrase")).toThrow(/database exists without a key file/);
    expect(fs.existsSync(keyPath())).toBe(false);

    fs.writeFileSync(keyPath(), originalKey, { mode: 0o600 });
    restartRuntime();
    expect(resolveSecret("ORPHAN_DB_SECRET")).toBe("do-not-overwrite");
  });

  it("blocks writes when the key file no longer unlocks existing vault data", () => {
    const homeA = path.join(tmpDir, "drift-a", ".keyblind");
    const homeB = path.join(tmpDir, "drift-b", ".keyblind");

    process.env.KEYBLIND_HOME = homeA;
    initializeVault("home-a");
    storeSecret("EXISTING", "existing-value");
    const originalKey = fs.readFileSync(path.join(homeA, ".keyblind.key"));

    process.env.KEYBLIND_HOME = homeB;
    initializeVault("home-b");
    const wrongKey = fs.readFileSync(path.join(homeB, ".keyblind.key"));

    fs.writeFileSync(path.join(homeA, ".keyblind.key"), wrongKey, { mode: 0o600 });
    process.env.KEYBLIND_HOME = homeA;
    restartRuntime();

    expect(() => storeSecret("NEW_AFTER_DRIFT", "new-value")).toThrow(/does not unlock this vault/);

    fs.writeFileSync(path.join(homeA, ".keyblind.key"), originalKey, { mode: 0o600 });
    restartRuntime();
    expect(resolveSecret("EXISTING")).toBe("existing-value");
    expect(resolveSecret("NEW_AFTER_DRIFT")).toBeNull();
  });

  it("saves rotation history before replacing a local secret", () => {
    initializeVault("rotation-passphrase");
    storeSecret("ROTATE_WITH_HISTORY", "before-rotation");

    expect(rotateLocalSecret("ROTATE_WITH_HISTORY", "after-rotation")).toBe(true);

    expect(resolveSecret("ROTATE_WITH_HISTORY")).toBe("after-rotation");
    expect(getSecretHistory("ROTATE_WITH_HISTORY")).toEqual([
      expect.objectContaining({ value: "before-rotation" }),
    ]);
  });

  it("keeps project vault keys isolated across project switches and restarts", () => {
    setProjectName("alpha");
    initializeVault("alpha-passphrase");
    storeSecret("PROJECT_SECRET", "alpha-value");
    const alphaKey = fs.readFileSync(keyPath("alpha"));

    setProjectName("beta");
    initializeVault("beta-passphrase");
    storeSecret("PROJECT_SECRET", "beta-value");
    const betaKey = fs.readFileSync(keyPath("beta"));
    expect(betaKey.equals(alphaKey)).toBe(false);

    setProjectName("alpha");
    restartRuntime();
    expect(resolveSecret("PROJECT_SECRET")).toBe("alpha-value");

    setProjectName("beta");
    restartRuntime();
    expect(resolveSecret("PROJECT_SECRET")).toBe("beta-value");
  });

  it("detects key/vault drift when names are visible but values are unrecoverable", () => {
    const homeA = path.join(tmpDir, "home-a", ".keyblind");
    const homeB = path.join(tmpDir, "home-b", ".keyblind");

    process.env.KEYBLIND_HOME = homeA;
    initializeVault("");
    storeSecret("REPRO_SECRET", "not-a-real-secret");
    expect(resolveSecret("REPRO_SECRET")).toBe("not-a-real-secret");

    process.env.KEYBLIND_HOME = homeB;
    restartRuntime();
    initializeVault("");

    fs.copyFileSync(path.join(homeB, ".keyblind.key"), path.join(homeA, ".keyblind.key"));

    process.env.KEYBLIND_HOME = homeA;
    restartRuntime();
    expect(listSecrets()).toContain("REPRO_SECRET");
    expect(() => resolveSecret("REPRO_SECRET")).toThrow(/does not unlock this vault|authenticate data|decrypt/i);

    const decryptability = checkVaultDecryptability();
    expect(decryptability.checked).toBe(1);
    expect(decryptability.failures).toEqual([
      expect.objectContaining({ name: "REPRO_SECRET" }),
    ]);

    const checks = runDoctor();
    expect(checks).toEqual(expect.arrayContaining([
      expect.objectContaining({
        name: "Secret decryptability",
        status: "error",
      }),
    ]));
  });
});
