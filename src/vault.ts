import Database from "better-sqlite3";
import crypto from "node:crypto";
import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { sessionActive } from "./auth.js";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 32;
const PBKDF2_ITERATIONS = 600_000;
const SALT_LENGTH = 32;

let _projectName: string | null = null;

export function setProjectName(name: string | null): void {
  _projectName = name;
  // Clear caches so they reload from the new project directory
  _key = null;
  closeDb();
}

export function getProjectName(): string | null {
  return _projectName;
}

function getVaultDir(): string {
  const base = path.join(os.homedir(), ".keyblind");
  if (_projectName) {
    return path.join(base, "projects", _projectName);
  }
  return base;
}

function getVaultPath(): string {
  return path.join(getVaultDir(), "vault.db");
}

function getKeyPath(): string {
  return path.join(getVaultDir(), ".keyblind.key");
}

function deriveMachineIdentity(): Buffer {
  const parts = [os.hostname(), os.userInfo().username, os.platform(), os.arch()];
  return crypto.createHash("sha256").update(parts.join(":")).digest();
}

function deriveKey(salt: Buffer, passphrase: string): Buffer {
  return crypto.pbkdf2Sync(passphrase, salt, PBKDF2_ITERATIONS, KEY_LENGTH, "sha256");
}

export function encrypt(value: string, key: Buffer): { encrypted: Buffer; iv: Buffer; authTag: Buffer } {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { encrypted, iv, authTag };
}

export function decrypt(encrypted: Buffer, iv: Buffer, authTag: Buffer, key: Buffer): string {
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
}

let _db: Database.Database | null = null;
let _key: Buffer | null = null;
let _requireSession = false;

export function setRequireSession(requireSession: boolean): void {
  _requireSession = requireSession;
}

export function getKey(): Buffer {
  if (_key) return _key;

  if (_requireSession && !sessionActive()) {
    throw new Error("Biometric session expired or not started. Run: keyblind unlock");
  }

  const keyDir = getVaultDir();
  if (!fs.existsSync(keyDir)) {
    throw new Error("Keyblind vault not initialized. Run: keyblind init");
  }

  const keyPath = getKeyPath();
  if (!fs.existsSync(keyPath)) {
    throw new Error("Keyblind key not found. Run: keyblind init");
  }

  const keyData = fs.readFileSync(keyPath);
  const salt = keyData.subarray(0, SALT_LENGTH);
  const wrappedKey = keyData.subarray(SALT_LENGTH);

  const machineId = deriveMachineIdentity();
  const unwrappedKey = Buffer.alloc(wrappedKey.length);
  for (let i = 0; i < wrappedKey.length; i++) {
    unwrappedKey[i] = wrappedKey[i] ^ machineId[i % machineId.length];
  }

  _key = unwrappedKey;
  return _key;
}

export function initializeVault(passphrase: string): void {
  const vaultDir = getVaultDir();
  if (!fs.existsSync(vaultDir)) {
    fs.mkdirSync(vaultDir, { mode: 0o700, recursive: true });
  }

  if (fs.existsSync(getKeyPath())) {
    throw new Error("Keyblind is already initialized. To reset, delete ~/.keyblind/");
  }

  const salt = crypto.randomBytes(SALT_LENGTH);
  const key = deriveKey(salt, passphrase);

  const machineId = deriveMachineIdentity();
  const wrappedKey = Buffer.alloc(key.length);
  for (let i = 0; i < key.length; i++) {
    wrappedKey[i] = key[i] ^ machineId[i % machineId.length];
  }

  fs.writeFileSync(getKeyPath(), Buffer.concat([salt, wrappedKey]), { mode: 0o600 });

  // Pre-create the database so isInitialized() passes
  getDb();
}

export function isInitialized(): boolean {
  return fs.existsSync(getKeyPath());
}

export function getDb(): Database.Database {
  if (_db) return _db;

  const dbPath = getVaultPath();
  _db = new Database(dbPath);
  _db.pragma("journal_mode = WAL");
  _db.pragma("foreign_keys = ON");
  _db.exec(`
    CREATE TABLE IF NOT EXISTS secrets (
      name TEXT PRIMARY KEY,
      encrypted_value BLOB NOT NULL,
      iv BLOB NOT NULL,
      auth_tag BLOB NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  return _db;
}

export function storeSecret(name: string, value: string): void {
  const db = getDb();
  const key = getKey();
  const { encrypted, iv, authTag } = encrypt(value, key);

  const stmt = db.prepare(`
    INSERT INTO secrets (name, encrypted_value, iv, auth_tag, updated_at)
    VALUES (?, ?, ?, ?, datetime('now'))
    ON CONFLICT(name) DO UPDATE SET
      encrypted_value = excluded.encrypted_value,
      iv = excluded.iv,
      auth_tag = excluded.auth_tag,
      updated_at = datetime('now')
  `);
  stmt.run(name, encrypted, iv, authTag);
}

export function resolveSecret(name: string): string | null {
  const db = getDb();
  const key = getKey();
  const row = db.prepare("SELECT encrypted_value, iv, auth_tag FROM secrets WHERE name = ?").get(name) as
    | { encrypted_value: Buffer; iv: Buffer; auth_tag: Buffer }
    | undefined;

  if (!row) return null;
  return decrypt(row.encrypted_value, row.iv, row.auth_tag, key);
}

export function listSecrets(): string[] {
  const db = getDb();
  const rows = db.prepare("SELECT name FROM secrets ORDER BY name").all() as { name: string }[];
  return rows.map((r) => r.name);
}

export function deleteSecret(name: string): boolean {
  const db = getDb();
  const result = db.prepare("DELETE FROM secrets WHERE name = ?").run(name);
  return result.changes > 0;
}

export function closeDb(): void {
  if (_db) {
    _db.close();
    _db = null;
  }
}

export function clearKey(): void {
  _key = null;
}
