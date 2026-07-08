import { getDb, getKey, encrypt, decrypt } from "./vault.js";
import { getBackend, setBackend, listAvailableBackends } from "./backends.js";
import os from "node:os";
import crypto from "node:crypto";

// --- Secret Versioning ---

export interface SecretVersion {
  version: number;
  value: string;
  createdAt: string;
}

export function ensureHistoryTable(): void {
  const db = getDb();
  db.exec(`
    CREATE TABLE IF NOT EXISTS secret_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      encrypted_value BLOB NOT NULL,
      iv BLOB NOT NULL,
      auth_tag BLOB NOT NULL,
      version INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_secret_history_name ON secret_history(name);
  `);
}

export function saveHistory(name: string, value: string): void {
  const db = getDb();
  ensureHistoryTable();
  const key = getKey();
  const { encrypted, iv, authTag } = encrypt(value, key);

  const nextVersion = (db.prepare("SELECT MAX(version) as maxv FROM secret_history WHERE name = ?").get(name) as { maxv: number | null }).maxv ?? 0;

  db.prepare("INSERT INTO secret_history (name, encrypted_value, iv, auth_tag, version) VALUES (?, ?, ?, ?, ?)").run(
    name, encrypted, iv, authTag, nextVersion + 1
  );
}

export function getSecretHistory(name: string, limit: number = 10): SecretVersion[] {
  const db = getDb();
  ensureHistoryTable();
  const key = getKey();

  const rows = db.prepare(
    "SELECT version, encrypted_value, iv, auth_tag, created_at FROM secret_history WHERE name = ? ORDER BY version DESC LIMIT ?"
  ).all(name, limit) as { version: number; encrypted_value: Buffer; iv: Buffer; auth_tag: Buffer; created_at: string }[];

  return rows.map(r => ({
    version: r.version,
    value: decrypt(r.encrypted_value, r.iv, r.auth_tag, key),
    createdAt: r.created_at,
  }));
}

export function rollbackSecret(name: string, version?: number): boolean {
  const db = getDb();
  ensureHistoryTable();
  const key = getKey();

  // If no version specified, get the most recent history entry
  const row = (version
    ? db.prepare("SELECT encrypted_value, iv, auth_tag FROM secret_history WHERE name = ? AND version = ?").get(name, version)
    : db.prepare("SELECT encrypted_value, iv, auth_tag FROM secret_history WHERE name = ? ORDER BY version DESC LIMIT 1").get(name)
  ) as { encrypted_value: Buffer; iv: Buffer; auth_tag: Buffer } | undefined;

  if (!row) return false;

  const value = decrypt(row.encrypted_value, row.iv, row.auth_tag, key);

  // Restore this version as current
  const { encrypted, iv, authTag } = encrypt(value, key);
  db.prepare("UPDATE secrets SET encrypted_value = ?, iv = ?, auth_tag = ?, updated_at = datetime('now') WHERE name = ?").run(
    encrypted, iv, authTag, name
  );

  return true;
}

// --- Expiry Notifications ---

export interface ExpiryWarning {
  name: string;
  expiresAt: string;
  daysLeft: number;
}

export function getExpiringSoon(daysThreshold: number = 30): ExpiryWarning[] {
  const db = getDb();
  const key = getKey();
  const rows = db.prepare("SELECT name, encrypted_value, iv, auth_tag FROM secrets WHERE name LIKE '@_@_expiry:%' ESCAPE '@'").all() as
    { name: string; encrypted_value: Buffer; iv: Buffer; auth_tag: Buffer }[];

  const now = new Date();
  const threshold = new Date(now.getTime() + daysThreshold * 24 * 60 * 60 * 1000);
  const warnings: ExpiryWarning[] = [];

  for (const row of rows) {
    const secretName = row.name.replace("__expiry:", "");
    const expiresAt = decrypt(row.encrypted_value, row.iv, row.auth_tag, key);
    const expDate = new Date(expiresAt);
    const daysLeft = Math.ceil((expDate.getTime() - now.getTime()) / (24 * 60 * 60 * 1000));

    if (expDate <= threshold && expDate > now) {
      warnings.push({ name: secretName, expiresAt, daysLeft });
    }
  }

  return warnings.sort((a, b) => a.daysLeft - b.daysLeft);
}

// --- Encrypted Sync ---

const SYNC_FILE = ".keyblind-sync.json";

function encryptSyncPayload(data: Buffer, key: Buffer): { encrypted: Buffer; iv: Buffer; authTag: Buffer } {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { encrypted, iv, authTag };
}

function decryptSyncPayload(encrypted: Buffer, iv: Buffer, authTag: Buffer, key: Buffer): Buffer {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

export function createSyncBundle(): string {
  const db = getDb();
  const key = getKey();

  const rows = db.prepare("SELECT name, encrypted_value, iv, auth_tag, updated_at FROM secrets WHERE name NOT LIKE '@_@_expiry:%' ESCAPE '@' AND name NOT LIKE '@_@_%' ESCAPE '@'").all() as {
    name: string; encrypted_value: Buffer; iv: Buffer; auth_tag: Buffer; updated_at: string;
  }[];

  const payload = JSON.stringify({
    version: 1,
    createdAt: new Date().toISOString(),
    hostname: os.hostname(),
    secrets: rows.map(r => ({
      name: r.name,
      value: r.encrypted_value.toString("base64"),
      iv: r.iv.toString("base64"),
      authTag: r.auth_tag.toString("base64"),
      updatedAt: r.updated_at,
    })),
  });

  // Encrypt the bundle with a derived sync key (different from vault key)
  const syncKey = crypto.createHash("sha256").update(key.toString("hex") + ":sync").digest();
  const { encrypted, iv, authTag } = encryptSyncPayload(Buffer.from(payload), syncKey);

  return JSON.stringify({
    format: "keyblind-sync-v1",
    iv: iv.toString("base64"),
    authTag: authTag.toString("base64"),
    data: encrypted.toString("base64"),
  });
}

export function applySyncBundle(bundleJson: string): { imported: number; skipped: number } {
  const db = getDb();
  const key = getKey();

  let bundle: any;
  try {
    bundle = JSON.parse(bundleJson);
  } catch {
    throw new Error("Invalid sync bundle: not valid JSON");
  }

  if (bundle.format !== "keyblind-sync-v1") {
    throw new Error("Invalid sync bundle: unknown format");
  }

  const syncKey = crypto.createHash("sha256").update(key.toString("hex") + ":sync").digest();
  const decrypted = decryptSyncPayload(
    Buffer.from(bundle.data, "base64"),
    Buffer.from(bundle.iv, "base64"),
    Buffer.from(bundle.authTag, "base64"),
    syncKey
  );

  const payload = JSON.parse(decrypted.toString());

  if (payload.version !== 1) {
    throw new Error(`Unsupported sync version: ${payload.version}`);
  }

  let imported = 0;
  let skipped = 0;

  for (const secret of payload.secrets) {
    const existing = db.prepare("SELECT updated_at FROM secrets WHERE name = ?").get(secret.name) as { updated_at: string } | undefined;

    if (existing && existing.updated_at >= secret.updatedAt) {
      skipped++;
      continue;
    }

    db.prepare(`
      INSERT INTO secrets (name, encrypted_value, iv, auth_tag, updated_at)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(name) DO UPDATE SET
        encrypted_value = excluded.encrypted_value,
        iv = excluded.iv,
        auth_tag = excluded.auth_tag,
        updated_at = excluded.updated_at
    `).run(
      secret.name,
      Buffer.from(secret.value, "base64"),
      Buffer.from(secret.iv, "base64"),
      Buffer.from(secret.authTag, "base64"),
      secret.updatedAt
    );
    imported++;
  }

  return { imported, skipped };
}

// --- Vault Migration ---

export function migrateSecrets(fromBackend: string, toBackend: string): { migrated: number; failed: string[] } {
  const backends = listAvailableBackends();
  const fromB = backends.find(b => b.name === fromBackend);
  const toB = backends.find(b => b.name === toBackend);

  if (!fromB || !fromB.available) throw new Error(`Source backend "${fromBackend}" is not available.`);
  if (!toB || !toB.available) throw new Error(`Target backend "${toBackend}" is not available.`);

  // Switch to source backend and list
  setBackend(fromBackend);
  const sourceBackend = getBackend();
  const names = sourceBackend.list();

  // Switch to target backend and store
  setBackend(toBackend);
  const targetBackend = getBackend();

  let migrated = 0;
  const failed: string[] = [];

  for (const name of names) {
    try {
      setBackend(fromBackend);
      const value = sourceBackend.resolve(name);
      if (value === null) {
        failed.push(name);
        continue;
      }
      setBackend(toBackend);
      targetBackend.store(name, value);
      migrated++;
    } catch {
      failed.push(name);
    }
  }

  return { migrated, failed };
}
