import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import {
  clearKey,
  closeDb,
  encrypt,
  listSecrets,
  resolveSecret,
  unlockVault,
} from "../src/vault.js";

const scriptPath = path.join(process.cwd(), "scripts", "migrate-vault-key-wrap.mjs");
const V2_MAGIC = Buffer.from("keyclasp:v2\n", "utf8");

function xorWithKey(key: Buffer, wrappingKey: Buffer): Buffer {
  const output = Buffer.alloc(key.length);
  for (let i = 0; i < key.length; i++) output[i] = key[i] ^ wrappingKey[i % wrappingKey.length];
  return output;
}

function currentStableIdentity(): Buffer {
  const platform = os.platform();
  if (platform === "darwin") {
    const output = spawnSync("/usr/sbin/ioreg", ["-rd1", "-c", "IOPlatformExpertDevice"], { encoding: "utf8" }).stdout ?? "";
    const uuid = output.match(/"IOPlatformUUID"\s=\s"([^"]+)"/)?.[1];
    if (uuid) return crypto.createHash("sha256").update(`stable:${platform}:${uuid}`).digest();
  }
  return crypto.createHash("sha256")
    .update([os.hostname(), os.userInfo().username, os.platform(), os.arch()].join(":"))
    .digest();
}

function writeV2Vault(home: string, secretValue: string): void {
  fs.mkdirSync(home, { recursive: true, mode: 0o700 });
  const salt = crypto.randomBytes(32);
  const dek = crypto.randomBytes(32);
  const wrapping = crypto.createHash("sha256").update(V2_MAGIC).update(salt).update(currentStableIdentity()).digest();
  fs.writeFileSync(path.join(home, ".keyclasp.key"), Buffer.concat([V2_MAGIC, salt, xorWithKey(dek, wrapping)]), { mode: 0o600 });
  const { encrypted, iv, authTag } = encrypt(secretValue, dek);
  const db = new Database(path.join(home, "vault.db"));
  try {
    db.exec(`
      CREATE TABLE secrets (
        project TEXT NOT NULL,
        environment TEXT NOT NULL,
        name TEXT NOT NULL,
        encrypted_value BLOB NOT NULL,
        iv BLOB NOT NULL,
        auth_tag BLOB NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        PRIMARY KEY (project, environment, name)
      )
    `);
    db.prepare("INSERT INTO secrets (project, environment, name, encrypted_value, iv, auth_tag) VALUES (?, ?, ?, ?, ?, ?)").run(
      "default",
      "default",
      "API_KEY",
      encrypted,
      iv,
      authTag,
    );
  } finally {
    db.close();
  }
}

const previousHome = process.env.KEYCLASP_HOME;
let tmpDir: string;
let home: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-migrate-"));
  home = path.join(tmpDir, ".keyclasp");
  process.env.KEYCLASP_HOME = home;
  closeDb();
  clearKey();
});

afterEach(() => {
  closeDb();
  clearKey();
  if (previousHome === undefined) delete process.env.KEYCLASP_HOME;
  else process.env.KEYCLASP_HOME = previousHome;
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("migrate-vault-key-wrap", () => {
  it("rewrites a v2 XOR key as a passphrase v3 wrap without changing secret rows", () => {
    writeV2Vault(home, "migrated-secret");
    const beforeDb = fs.readFileSync(path.join(home, "vault.db"));

    const passphraseFile = path.join(tmpDir, "wrap-passphrase");
    fs.writeFileSync(passphraseFile, "new-wrap\n", { mode: 0o600 });
    const result = spawnSync(process.execPath, [scriptPath, "--yes", "--passphrase-file", passphraseFile], {
      encoding: "utf8",
      env: { ...process.env, KEYCLASP_HOME: home },
    });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Migrated");
    expect(fs.readFileSync(path.join(home, "vault.db")).equals(beforeDb)).toBe(true);
    expect(fs.existsSync(path.join(home, ".keyclasp.key.1.bak"))).toBe(true);

    unlockVault("new-wrap");
    expect(listSecrets("default", "default")).toContain("API_KEY");
    expect(resolveSecret("default", "default", "API_KEY")).toBe("migrated-secret");
  });

  it("refuses a vault that is already v3", () => {
    writeV2Vault(home, "migrated-secret");
    const first = spawnSync(process.execPath, [scriptPath, "--yes", "--machine"], {
      encoding: "utf8",
      env: { ...process.env, KEYCLASP_HOME: home },
    });
    expect(first.status).toBe(0);

    const second = spawnSync(process.execPath, [scriptPath, "--yes", "--machine"], {
      encoding: "utf8",
      env: { ...process.env, KEYCLASP_HOME: home },
    });
    expect(second.status).not.toBe(0);
    expect(second.stderr).toMatch(/already the current format/);
  });

  it("refuses a non-interactive invoke without --yes", () => {
    writeV2Vault(home, "migrated-secret");
    const result = spawnSync(process.execPath, [scriptPath, "--machine"], {
      encoding: "utf8",
      env: { ...process.env, KEYCLASP_HOME: home },
    });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/requires a TTY/);
  });
});
