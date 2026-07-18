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
  getVaultLocation,
} from "../src/vault.js";
import { getSecretHistory, rotateLocalSecret } from "../src/sync.js";
import { runDoctor } from "../src/doctor.js";

const previousKeyclaspHome = process.env.KEYCLASP_HOME;
const previousKeyblindHome = process.env.KEYBLIND_HOME;
const previousHome = process.env.HOME;
let tmpDir: string;
let vaultHome: string;
const keyFileMagic = Buffer.from("keyclasp:v2\n", "utf8");
const legacyKeyFileMagic = Buffer.from("keyblind:v2\n", "utf8");

function resetRuntime(): void {
  closeDb();
  clearKey();
}

function restartRuntime(): void {
  resetRuntime();
}

function keyPath(project?: string): string {
  return project
    ? path.join(vaultHome, "projects", project, ".keyclasp.key")
    : path.join(vaultHome, ".keyclasp.key");
}

function legacyKeyPath(): string {
  return path.join(vaultHome, ".keyblind.key");
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
  fs.writeFileSync(legacyKeyPath(), Buffer.concat([salt, xorWithKey(key, legacyIdentity)]), { mode: 0o600 });

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

function writeKeyblindV2Vault(secretName: string, secretValue: string, stableIdentity: Buffer): void {
  fs.mkdirSync(vaultHome, { recursive: true, mode: 0o700 });
  const salt = crypto.randomBytes(32);
  const key = crypto.pbkdf2Sync("keyblind-v2-passphrase", salt, 600_000, 32, "sha256");
  const wrappingKey = crypto.createHash("sha256")
    .update(legacyKeyFileMagic)
    .update(salt)
    .update(stableIdentity)
    .digest();
  const legacyPath = path.join(vaultHome, ".keyblind.key");
  fs.writeFileSync(legacyPath, Buffer.concat([legacyKeyFileMagic, salt, xorWithKey(key, wrappingKey)]), { mode: 0o600 });

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
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-key-invariant-"));
  vaultHome = path.join(tmpDir, ".keyclasp");
  process.env.KEYCLASP_HOME = vaultHome;
  setMachineIdentityForTests(null);
  setProjectName(null);
  resetRuntime();
});

afterEach(() => {
  setMachineIdentityForTests(null);
  setProjectName(null);
  resetRuntime();
  if (previousKeyclaspHome === undefined) {
    delete process.env.KEYCLASP_HOME;
  } else {
    process.env.KEYCLASP_HOME = previousKeyclaspHome;
  }
  if (previousKeyblindHome === undefined) {
    delete process.env.KEYBLIND_HOME;
  } else {
    process.env.KEYBLIND_HOME = previousKeyblindHome;
  }
  if (previousHome === undefined) {
    delete process.env.HOME;
  } else {
    process.env.HOME = previousHome;
  }
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("vault key invariants", () => {
  it("opens Keyblind v2 vaults through the legacy home, key filename, and key header", () => {
    const stableIdentity = Buffer.from("stable-keyblind-v2-identity-value");
    setMachineIdentityForTests({ stable: stableIdentity });
    writeKeyblindV2Vault("LEGACY_V2", "still-readable", stableIdentity);

    restartRuntime();
    expect(resolveSecret("LEGACY_V2")).toBe("still-readable");
  });

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

    process.env.KEYCLASP_HOME = firstHome;
    initializeVault("first-passphrase");
    storeSecret("FIRST_SECRET", "first-value");
    expect(resolveSecret("FIRST_SECRET")).toBe("first-value");
    const firstKey = fs.readFileSync(path.join(firstHome, ".keyclasp.key"));

    process.env.KEYCLASP_HOME = secondHome;
    initializeVault("second-passphrase");
    storeSecret("SECOND_SECRET", "second-value");
    expect(resolveSecret("SECOND_SECRET")).toBe("second-value");
    const secondKey = fs.readFileSync(path.join(secondHome, ".keyclasp.key"));
    expect(secondKey.equals(firstKey)).toBe(false);

    restartRuntime();
    expect(resolveSecret("SECOND_SECRET")).toBe("second-value");

    process.env.KEYCLASP_HOME = firstHome;
    restartRuntime();
    expect(resolveSecret("FIRST_SECRET")).toBe("first-value");
  });

  it("switches vault homes in one process without reusing the previous key or database", () => {
    const homeA = path.join(tmpDir, "switch-a", ".keyclasp");
    const homeB = path.join(tmpDir, "switch-b", ".keyclasp");

    process.env.KEYCLASP_HOME = homeA;
    initializeVault("a-passphrase");
    storeSecret("ONLY_A", "a-value");

    process.env.KEYCLASP_HOME = homeB;
    initializeVault("b-passphrase");
    storeSecret("ONLY_B", "b-value");

    process.env.KEYCLASP_HOME = homeA;
    expect(resolveSecret("ONLY_A")).toBe("a-value");
    expect(resolveSecret("ONLY_B")).toBeNull();

    process.env.KEYCLASP_HOME = homeB;
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

  it("adds a Keyclasp key beside a headerless Keyblind key without breaking rollback", () => {
    const stableIdentity = Buffer.from("stable-legacy-migration-identity");
    const originalLegacyIdentity = Buffer.from("legacy-migration-before-change");
    writeLegacyVault("LEGACY_SECRET", "legacy-still-readable", originalLegacyIdentity);
    const legacyKeyFile = fs.readFileSync(legacyKeyPath());

    setMachineIdentityForTests({
      stable: stableIdentity,
      legacy: originalLegacyIdentity,
    });
    expect(resolveSecret("LEGACY_SECRET")).toBe("legacy-still-readable");
    expect(fs.readFileSync(keyPath()).subarray(0, keyFileMagic.length).equals(keyFileMagic)).toBe(true);
    expect(fs.readFileSync(legacyKeyPath()).equals(legacyKeyFile)).toBe(true);

    restartRuntime();
    setMachineIdentityForTests({
      stable: stableIdentity,
      legacy: Buffer.from("legacy-migration-after-change!"),
    });
    expect(resolveSecret("LEGACY_SECRET")).toBe("legacy-still-readable");

    fs.unlinkSync(keyPath());
    restartRuntime();
    setMachineIdentityForTests({
      stable: stableIdentity,
      legacy: originalLegacyIdentity,
    });
    expect(resolveSecret("LEGACY_SECRET")).toBe("legacy-still-readable");
    expect(fs.readFileSync(legacyKeyPath()).equals(legacyKeyFile)).toBe(true);
  });

  it("uses a complete legacy home when the preferred home is empty or partial", () => {
    const stableIdentity = Buffer.from("stable-home-selection-identity!");
    const preferredHome = path.join(tmpDir, ".keyclasp");
    const legacyHome = path.join(tmpDir, ".keyblind");
    vaultHome = legacyHome;
    writeKeyblindV2Vault("LEGACY_HOME_SECRET", "legacy-home-value", stableIdentity);
    fs.mkdirSync(preferredHome, { recursive: true });
    fs.writeFileSync(path.join(preferredHome, ".keyclasp.key"), Buffer.from("partial"));

    delete process.env.KEYCLASP_HOME;
    delete process.env.KEYBLIND_HOME;
    process.env.HOME = tmpDir;
    setMachineIdentityForTests({ stable: stableIdentity });
    restartRuntime();

    expect(getVaultLocation()).toBe(legacyHome);
    expect(resolveSecret("LEGACY_HOME_SECRET")).toBe("legacy-home-value");
  });

  it("requires an explicit home when both default homes contain vaults", () => {
    const preferredHome = path.join(tmpDir, ".keyclasp");
    const legacyHome = path.join(tmpDir, ".keyblind");
    for (const home of [preferredHome, legacyHome]) {
      fs.mkdirSync(home, { recursive: true });
      fs.writeFileSync(path.join(home, ".keyclasp.key"), Buffer.from("recognizable"));
      fs.writeFileSync(path.join(home, "vault.db"), Buffer.alloc(0));
    }

    delete process.env.KEYCLASP_HOME;
    delete process.env.KEYBLIND_HOME;
    process.env.HOME = tmpDir;
    restartRuntime();

    expect(() => getVaultLocation()).toThrow(/Both ~\/\.keyclasp and ~\/\.keyblind contain vault data/);
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
    const homeA = path.join(tmpDir, "drift-a", ".keyclasp");
    const homeB = path.join(tmpDir, "drift-b", ".keyclasp");

    process.env.KEYCLASP_HOME = homeA;
    initializeVault("home-a");
    storeSecret("EXISTING", "existing-value");
    const originalKey = fs.readFileSync(path.join(homeA, ".keyclasp.key"));

    process.env.KEYCLASP_HOME = homeB;
    initializeVault("home-b");
    const wrongKey = fs.readFileSync(path.join(homeB, ".keyclasp.key"));

    fs.writeFileSync(path.join(homeA, ".keyclasp.key"), wrongKey, { mode: 0o600 });
    process.env.KEYCLASP_HOME = homeA;
    restartRuntime();

    expect(() => storeSecret("NEW_AFTER_DRIFT", "new-value")).toThrow(/does not unlock this vault/);

    fs.writeFileSync(path.join(homeA, ".keyclasp.key"), originalKey, { mode: 0o600 });
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
    const homeA = path.join(tmpDir, "home-a", ".keyclasp");
    const homeB = path.join(tmpDir, "home-b", ".keyclasp");

    process.env.KEYCLASP_HOME = homeA;
    initializeVault("");
    storeSecret("REPRO_SECRET", "not-a-real-secret");
    expect(resolveSecret("REPRO_SECRET")).toBe("not-a-real-secret");

    process.env.KEYCLASP_HOME = homeB;
    restartRuntime();
    initializeVault("");

    fs.copyFileSync(path.join(homeB, ".keyclasp.key"), path.join(homeA, ".keyclasp.key"));

    process.env.KEYCLASP_HOME = homeA;
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
