import Database from "better-sqlite3";
import crypto from "node:crypto";
import path from "node:path";
import fs from "node:fs";
import { encrypt, decrypt, storeSecret, listSecrets, resolveSecret } from "./vault.js";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 32;
const PBKDF2_ITERATIONS = 600_000;
const SALT_LENGTH = 32;

function getTeamVaultPath(filePath?: string): string {
  if (filePath) return path.resolve(filePath);
  const dir = path.join(process.cwd(), ".keyblind");
  return path.join(dir, "team.vault");
}

function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return crypto.pbkdf2Sync(passphrase, salt, PBKDF2_ITERATIONS, KEY_LENGTH, "sha256");
}

function openTeamDb(filePath?: string): { db: Database.Database; key: Buffer; vaultPath: string } {
  const vaultPath = getTeamVaultPath(filePath);
  if (!fs.existsSync(vaultPath)) {
    throw new Error(`Team vault not found at ${vaultPath}. Run: keyblind team init`);
  }

  const dir = path.dirname(vaultPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { mode: 0o700, recursive: true });
  }

  // Read salt from the vault file metadata (stored as a separate .salt file)
  const saltPath = vaultPath.replace(/\.vault$/, ".salt");
  if (!fs.existsSync(saltPath)) {
    throw new Error(`Team vault salt not found at ${saltPath}. Vault may be corrupted.`);
  }

  return { db: null as any, key: null as any, vaultPath };
}

function openTeamDbWithPassphrase(passphrase: string, filePath?: string): { db: Database.Database; key: Buffer; vaultPath: string } {
  const vaultPath = getTeamVaultPath(filePath);
  if (!fs.existsSync(vaultPath)) {
    throw new Error(`Team vault not found at ${vaultPath}. Run: keyblind team init`);
  }

  const saltPath = vaultPath.replace(/\.vault$/, ".salt");
  if (!fs.existsSync(saltPath)) {
    throw new Error(`Team vault salt not found at ${saltPath}. Vault may be corrupted.`);
  }

  const salt = fs.readFileSync(saltPath);
  const key = deriveKey(passphrase, salt);

  const db = new Database(vaultPath);
  db.pragma("journal_mode = WAL");

  // Verify the key works by trying to read the __keyblind_meta table
  try {
    const row = db.prepare("SELECT encrypted_value, iv, auth_tag FROM secrets WHERE name = '__keyblind_team_check'").get() as
      | { encrypted_value: Buffer; iv: Buffer; auth_tag: Buffer }
      | undefined;
    if (row) {
      decrypt(row.encrypted_value, row.iv, row.auth_tag, key);
    }
  } catch {
    db.close();
    throw new Error("Incorrect passphrase or corrupted vault.");
  }

  return { db, key, vaultPath };
}

export function teamInit(passphrase: string, filePath?: string): string {
  const vaultPath = getTeamVaultPath(filePath);

  if (fs.existsSync(vaultPath)) {
    throw new Error(`Team vault already exists at ${vaultPath}.`);
  }

  const dir = path.dirname(vaultPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { mode: 0o700, recursive: true });
  }

  const salt = crypto.randomBytes(SALT_LENGTH);
  const key = deriveKey(passphrase, salt);

  const db = new Database(vaultPath);
  db.pragma("journal_mode = WAL");
  db.exec(`
    CREATE TABLE IF NOT EXISTS secrets (
      name TEXT PRIMARY KEY,
      encrypted_value BLOB NOT NULL,
      iv BLOB NOT NULL,
      auth_tag BLOB NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  // Store a verification token so we can detect wrong passphrases on open
  const { encrypted, iv, authTag } = encrypt("keyblind-team-vault-ok", key);
  db.prepare("INSERT INTO secrets (name, encrypted_value, iv, auth_tag) VALUES (?, ?, ?, ?)").run(
    "__keyblind_team_check", encrypted, iv, authTag,
  );

  db.close();

  // Write salt file
  const saltPath = vaultPath.replace(/\.vault$/, ".salt");
  fs.writeFileSync(saltPath, salt, { mode: 0o600 });

  return vaultPath;
}

export function teamPush(name: string, value: string, passphrase: string, filePath?: string): void {
  const { db, key } = openTeamDbWithPassphrase(passphrase, filePath);

  try {
    const { encrypted, iv, authTag } = encrypt(value, key);
    db.prepare(`
      INSERT INTO secrets (name, encrypted_value, iv, auth_tag, updated_at)
      VALUES (?, ?, ?, ?, datetime('now'))
      ON CONFLICT(name) DO UPDATE SET
        encrypted_value = excluded.encrypted_value,
        iv = excluded.iv,
        auth_tag = excluded.auth_tag,
        updated_at = datetime('now')
    `).run(name, encrypted, iv, authTag);
  } finally {
    db.close();
  }
}

export function teamPull(passphrase: string, filePath?: string): string[] {
  const { db, key } = openTeamDbWithPassphrase(passphrase, filePath);

  try {
    const rows = db.prepare("SELECT name, encrypted_value, iv, auth_tag FROM secrets WHERE name != '__keyblind_team_check' ORDER BY name").all() as
      { name: string; encrypted_value: Buffer; iv: Buffer; auth_tag: Buffer }[];

    const imported: string[] = [];
    for (const row of rows) {
      const value = decrypt(row.encrypted_value, row.iv, row.auth_tag, key);
      storeSecret(row.name, value);
      imported.push(row.name);
    }
    return imported;
  } finally {
    db.close();
  }
}

export function teamList(passphrase: string, filePath?: string): string[] {
  const { db, key } = openTeamDbWithPassphrase(passphrase, filePath);

  try {
    const rows = db.prepare("SELECT name FROM secrets WHERE name != '__keyblind_team_check' ORDER BY name").all() as { name: string }[];
    return rows.map((r) => r.name);
  } finally {
    db.close();
  }
}

export function teamResolve(name: string, passphrase: string, filePath?: string): string | null {
  const { db, key } = openTeamDbWithPassphrase(passphrase, filePath);

  try {
    const row = db.prepare("SELECT encrypted_value, iv, auth_tag FROM secrets WHERE name = ?").get(name) as
      | { encrypted_value: Buffer; iv: Buffer; auth_tag: Buffer }
      | undefined;
    if (!row) return null;
    return decrypt(row.encrypted_value, row.iv, row.auth_tag, key);
  } finally {
    db.close();
  }
}

export function teamDelete(name: string, passphrase: string, filePath?: string): boolean {
  const { db } = openTeamDbWithPassphrase(passphrase, filePath);

  try {
    const result = db.prepare("DELETE FROM secrets WHERE name = ? AND name != '__keyblind_team_check'").run(name);
    return result.changes > 0;
  } finally {
    db.close();
  }
}
