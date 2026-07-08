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
const REMOVED_INTERNAL_SECRET_NAMES = new Set([
  "_keyblind_sso:config",
  "_keyblind_sso:token",
  "_keyblind_deadman:config",
  "_keyblind_deadman:last_checkin",
  "__keyblind_team_check",
]);

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
  const base = process.env.KEYBLIND_HOME
    ? path.resolve(process.env.KEYBLIND_HOME)
    : path.join(os.homedir(), ".keyblind");
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
  _db.pragma("busy_timeout = 5000");
  try {
    _db.pragma("journal_mode = WAL");
  } catch {
    // journal_mode change can fail with SQLITE_BUSY on Windows CI
    // when the DB file is newly created. This is non-fatal — the
    // vault is fully functional with the default journal mode.
  }
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
  _db.exec(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      secret_name TEXT NOT NULL,
      action TEXT NOT NULL CHECK(action IN ('resolve','store','delete')),
      client_info TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  _db.exec(`
    CREATE INDEX IF NOT EXISTS idx_audit_log_secret ON audit_log(secret_name);
  `);
  _db.exec(`
    CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at);
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
  auditLog(name, "store");
}

export function resolveSecret(name: string): string | null {
  if (REMOVED_INTERNAL_SECRET_NAMES.has(name)) return null;

  const db = getDb();
  const key = getKey();
  const row = db.prepare("SELECT encrypted_value, iv, auth_tag FROM secrets WHERE name = ?").get(name) as
    | { encrypted_value: Buffer; iv: Buffer; auth_tag: Buffer }
    | undefined;

  if (!row) return null;
  auditLog(name, "resolve");
  return decrypt(row.encrypted_value, row.iv, row.auth_tag, key);
}

export function listSecrets(): string[] {
  const db = getDb();
  const rows = db.prepare("SELECT name FROM secrets WHERE name NOT LIKE '@_@_%' ESCAPE '@' ORDER BY name").all() as { name: string }[];
  return rows.map((r) => r.name).filter((name) => !REMOVED_INTERNAL_SECRET_NAMES.has(name));
}

export function countSecretsByPrefix(prefix: string): number {
  const db = getDb();
  const row = db.prepare("SELECT COUNT(*) as count FROM secrets WHERE substr(name, 1, ?) = ?").get(prefix.length, prefix) as { count: number };
  return row.count;
}

export function deleteSecret(name: string): boolean {
  const db = getDb();
  auditLog(name, "delete");
  const result = db.prepare("DELETE FROM secrets WHERE name = ? AND name NOT LIKE '@_@_expiry:%' ESCAPE '@' AND name NOT LIKE '@_@_keyblind%' ESCAPE '@'").run(name);
  // Also delete any expiry entry
  db.prepare("DELETE FROM secrets WHERE name = ?").run(`__expiry:${name}`);
  return result.changes > 0;
}

// --- Audit Log ---

let _clientInfo: string | null = null;

export function setClientInfo(info: string | null): void {
  _clientInfo = info;
}

function auditLog(secretName: string, action: "resolve" | "store" | "delete"): void {
  const db = getDb();
  db.prepare("INSERT INTO audit_log (secret_name, action, client_info) VALUES (?, ?, ?)").run(
    secretName, action, _clientInfo,
  );
}

export function getAuditLog(limit: number = 50): { secretName: string; action: string; clientInfo: string | null; timestamp: string }[] {
  const db = getDb();
  const rows = db.prepare("SELECT secret_name, action, client_info, created_at FROM audit_log ORDER BY id DESC LIMIT ?").all(limit) as { secret_name: string; action: string; client_info: string | null; created_at: string }[];
  return rows.map((r) => ({
    secretName: r.secret_name,
    action: r.action,
    clientInfo: r.client_info,
    timestamp: r.created_at,
  }));
}

// --- Secret Expiry ---

export function setExpiry(name: string, expiresAt: string): boolean {
  const db = getDb();
  const row = db.prepare("SELECT name FROM secrets WHERE name = ?").get(name) as { name: string } | undefined;
  if (!row) return false;
  // Store expiry in a __keyblind_meta style - using a separate metadata approach
  // For now, we store expiry as a special prefixed secret
  db.prepare("DELETE FROM secrets WHERE name = ?").run(`__keyblind_expiry:${name}`);
  // We'll use a simpler approach: store expiry as a separate row in a metadata approach
  // Actually, let's store it directly in the audit or use a simple approach
  // Store in a meta row
  const key = getKey();
  const { encrypted, iv, authTag } = encrypt(expiresAt, key);
  db.prepare("INSERT INTO secrets (name, encrypted_value, iv, auth_tag) VALUES (?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET encrypted_value = excluded.encrypted_value, iv = excluded.iv, auth_tag = excluded.auth_tag").run(`__expiry:${name}`, encrypted, iv, authTag);
  return true;
}

export function getExpiry(name: string): string | null {
  const db = getDb();
  const key = getKey();
  const row = db.prepare("SELECT encrypted_value, iv, auth_tag FROM secrets WHERE name = ?").get(`__expiry:${name}`) as
    | { encrypted_value: Buffer; iv: Buffer; auth_tag: Buffer }
    | undefined;
  if (!row) return null;
  return decrypt(row.encrypted_value, row.iv, row.auth_tag, key);
}

export function checkExpired(): string[] {
  const db = getDb();
  const key = getKey();
  const rows = db.prepare("SELECT name, encrypted_value, iv, auth_tag FROM secrets WHERE name LIKE '@_@_expiry:%' ESCAPE '@'").all() as
    { name: string; encrypted_value: Buffer; iv: Buffer; auth_tag: Buffer }[];
  const now = new Date();
  const expired: string[] = [];
  for (const row of rows) {
    const secretName = row.name.replace("__expiry:", "");
    const expiresAt = new Date(decrypt(row.encrypted_value, row.iv, row.auth_tag, key));
    if (expiresAt <= now) {
      expired.push(secretName);
    }
  }
  return expired;
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
