import Database from "better-sqlite3";
import crypto from "node:crypto";
import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { execFileSync } from "node:child_process";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 32;
const PBKDF2_ITERATIONS = 600_000;
const SALT_LENGTH = 32;
const KEY_FILE_MAGIC = Buffer.from("keyblind:v2\n", "utf8");
const KEY_FILE_CORRUPT_ERROR = "Keyblind key file is corrupted or incomplete.";
const KEY_VAULT_MISMATCH_ERROR = "Keyblind key file does not unlock this vault database. Restore the matching .keyblind.key before reading or writing secrets.";
const REMOVED_INTERNAL_SECRET_NAMES = new Set([
  "_keyblind_sso:config",
  "_keyblind_sso:token",
  "_keyblind_deadman:config",
  "_keyblind_deadman:last_checkin",
  "__keyblind_team_check",
]);
const RESERVED_ALIAS_PREFIXES = ["__keyblind", "__expiry:", "_totp", "_keyblind"];

export interface SecretAlias {
  alias: string;
  target: string;
  createdAt: string;
  updatedAt: string;
}

export interface AliasResolution {
  requestedName: string;
  resolvedName: string;
  aliasUsed: boolean;
  value: string | null;
}

export interface DecryptabilityCheck {
  checked: number;
  failures: { name: string; error: string }[];
}

type EncryptedVaultRow = { encrypted_value: Buffer; iv: Buffer; auth_tag: Buffer };
type NamedEncryptedVaultRow = EncryptedVaultRow & { name: string };
type FileStamp = { mtimeMs: number; size: number } | null;
type KeyValidationStamp = {
  keyPath: string;
  key: FileStamp;
  dbPath: string;
  db: FileStamp;
  wal: FileStamp;
};

let _projectName: string | null = null;
let _machineIdentityForTests: { stable?: Buffer; legacy?: Buffer } | null = null;

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

function deriveLegacyMachineIdentity(): Buffer {
  const parts = [os.hostname(), os.userInfo().username, os.platform(), os.arch()];
  return crypto.createHash("sha256").update(parts.join(":")).digest();
}

function deriveStableMachineIdentity(): Buffer {
  return deriveStableMachineIdentities()[0];
}

function deriveStableMachineIdentities(): Buffer[] {
  if (_machineIdentityForTests?.stable) return [_machineIdentityForTests.stable];

  const platform = os.platform();
  const probes: (() => string | null)[] = [];

  if (platform === "darwin") {
    probes.push(() => {
      try {
        const output = execFileSync("/usr/sbin/ioreg", ["-rd1", "-c", "IOPlatformExpertDevice"], {
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"],
          timeout: 2000,
        });
        return output.match(/"IOPlatformUUID"\s=\s"([^"]+)"/)?.[1] ?? null;
      } catch {
        return null;
      }
    });
  }

  probes.push(() => readFirstExistingFile([
    "/etc/machine-id",
    "/var/lib/dbus/machine-id",
    "/var/db/db.uuid",
  ]));

  if (platform === "win32") {
    probes.push(() => {
      try {
        const output = execFileSync("reg", [
          "query",
          "HKLM\\SOFTWARE\\Microsoft\\Cryptography",
          "/v",
          "MachineGuid",
        ], {
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"],
          timeout: 2000,
        });
        return output.match(/MachineGuid\s+REG_SZ\s+([^\r\n]+)/)?.[1]?.trim() ?? null;
      } catch {
        return null;
      }
    });
  }

  const identities: Buffer[] = [];
  const seen = new Set<string>();
  for (const probe of probes) {
    const value = probe();
    if (value) {
      const identity = crypto.createHash("sha256").update(`stable:${platform}:${value}`).digest();
      const hex = identity.toString("hex");
      if (!seen.has(hex)) {
        seen.add(hex);
        identities.push(identity);
      }
    }
  }

  identities.push(deriveLegacyMachineIdentity());
  return identities;
}

function readFirstExistingFile(paths: string[]): string | null {
  for (const candidate of paths) {
    try {
      const value = fs.readFileSync(candidate, "utf8").trim();
      if (value) return value;
    } catch {
      // Keep probing platform-specific machine-id locations.
    }
  }
  return null;
}

function deriveKey(salt: Buffer, passphrase: string): Buffer {
  return crypto.pbkdf2Sync(passphrase, salt, PBKDF2_ITERATIONS, KEY_LENGTH, "sha256");
}

function deriveWrappingKey(salt: Buffer, machineIdentity: Buffer): Buffer {
  return crypto.createHash("sha256")
    .update(KEY_FILE_MAGIC)
    .update(salt)
    .update(machineIdentity)
    .digest();
}

function xorWithKey(key: Buffer, wrappingKey: Buffer): Buffer {
  const output = Buffer.alloc(key.length);
  for (let i = 0; i < key.length; i++) {
    output[i] = key[i] ^ wrappingKey[i % wrappingKey.length];
  }
  return output;
}

function loadKeyFile(keyData: Buffer, keyPath: string): Buffer {
  if (keyData.subarray(0, KEY_FILE_MAGIC.length).equals(KEY_FILE_MAGIC)) {
    const expectedLength = KEY_FILE_MAGIC.length + SALT_LENGTH + KEY_LENGTH;
    if (keyData.length !== expectedLength) {
      throw new Error(KEY_FILE_CORRUPT_ERROR);
    }

    const salt = keyData.subarray(KEY_FILE_MAGIC.length, KEY_FILE_MAGIC.length + SALT_LENGTH);
    const wrappedKey = keyData.subarray(KEY_FILE_MAGIC.length + SALT_LENGTH);
    return unwrapWithAnyStableIdentity(salt, wrappedKey);
  }

  if (keyData.length !== SALT_LENGTH + KEY_LENGTH) {
    throw new Error(KEY_FILE_CORRUPT_ERROR);
  }

  const salt = keyData.subarray(0, SALT_LENGTH);
  const wrappedKey = keyData.subarray(SALT_LENGTH);
  const legacyIdentity = _machineIdentityForTests?.legacy ?? deriveLegacyMachineIdentity();
  const key = xorWithKey(wrappedKey, legacyIdentity);
  assertKeyUnlocksVault(key);
  writeKeyFile(keyPath, salt, key);
  return key;
}

function unwrapWithAnyStableIdentity(salt: Buffer, wrappedKey: Buffer): Buffer {
  const identities = deriveStableMachineIdentities();
  for (const identity of identities) {
    const key = xorWithKey(wrappedKey, deriveWrappingKey(salt, identity));
    if (canDecryptVaultRows(key)) return key;
  }

  throw new Error(KEY_VAULT_MISMATCH_ERROR);
}

function writeKeyFile(keyPath: string, salt: Buffer, key: Buffer): void {
  const wrappedKey = xorWithKey(key, deriveWrappingKey(salt, deriveStableMachineIdentity()));
  const tmpPath = `${keyPath}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmpPath, Buffer.concat([KEY_FILE_MAGIC, salt, wrappedKey]), { mode: 0o600 });
  backupExistingKeyFile(keyPath);
  fs.renameSync(tmpPath, keyPath);
  fs.chmodSync(keyPath, 0o600);
}

function backupExistingKeyFile(keyPath: string): void {
  try {
    fs.renameSync(keyPath, nextKeyBackupPath(keyPath));
  } catch (err: any) {
    if (err?.code === "ENOENT") return;
    throw err;
  }
}

function nextKeyBackupPath(keyPath: string): string {
  for (let index = 1; ; index++) {
    const backupPath = `${keyPath}.${index}.bak`;
    if (!fs.existsSync(backupPath)) return backupPath;
  }
}

function assertKeyUnlocksVault(key: Buffer): void {
  if (keyValidationCurrent()) return;
  if (canDecryptVaultRows(key)) return;
  throw new Error(KEY_VAULT_MISMATCH_ERROR);
}

function rememberKeyValidation(): void {
  _keyValidationStamp = currentKeyValidationStamp();
}

function keyValidationCurrent(): boolean {
  const current = currentKeyValidationStamp();
  return current !== null && _keyValidationStamp !== null && validationStampEquals(current, _keyValidationStamp);
}

function currentKeyValidationStamp(): KeyValidationStamp | null {
  const keyPath = getKeyPath();
  const key = fileStamp(keyPath);
  if (!key) return null;

  const dbPath = getVaultPath();
  return {
    keyPath,
    key,
    dbPath,
    db: fileStamp(dbPath),
    wal: fileStamp(`${dbPath}-wal`),
  };
}

function fileStamp(filePath: string): FileStamp {
  try {
    const stat = fs.statSync(filePath);
    return { mtimeMs: stat.mtimeMs, size: stat.size };
  } catch {
    return null;
  }
}

function validationStampEquals(a: KeyValidationStamp, b: KeyValidationStamp): boolean {
  return a.keyPath === b.keyPath &&
    a.dbPath === b.dbPath &&
    fileStampEquals(a.key, b.key) &&
    fileStampEquals(a.db, b.db) &&
    fileStampEquals(a.wal, b.wal);
}

function fileStampEquals(a: FileStamp, b: FileStamp): boolean {
  if (a === null || b === null) return a === b;
  return a.mtimeMs === b.mtimeMs && a.size === b.size;
}

function canDecryptVaultRows(key: Buffer): boolean {
  const dbPath = getVaultPath();
  if (!fs.existsSync(dbPath)) return true;

  const db = _db ?? new Database(dbPath, { readonly: true, fileMustExist: true });
  const closeAfter = db !== _db;
  try {
    for (const row of iterateEncryptedVaultRows(db)) {
      decrypt(row.encrypted_value, row.iv, row.auth_tag, key);
    }
    return true;
  } catch {
    return false;
  } finally {
    if (closeAfter) db.close();
  }
}

function* iterateEncryptedVaultRows(db: Database.Database): IterableIterator<EncryptedVaultRow> {
  for (const row of iterateNamedEncryptedVaultRows(db)) {
    yield row;
  }
}

function* iterateNamedEncryptedVaultRows(db: Database.Database): IterableIterator<NamedEncryptedVaultRow> {
  if (tableExists(db, "secrets")) {
    yield* db.prepare("SELECT name, encrypted_value, iv, auth_tag FROM secrets ORDER BY name").iterate() as IterableIterator<NamedEncryptedVaultRow>;
  }
  if (tableExists(db, "secret_history")) {
    yield* db.prepare(`
      SELECT name || ' history v' || version AS name, encrypted_value, iv, auth_tag
      FROM secret_history
      ORDER BY name, version
    `).iterate() as IterableIterator<NamedEncryptedVaultRow>;
  }
}

function tableExists(db: Database.Database, table: string): boolean {
  const row = db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(table);
  return row !== undefined;
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
let _dbPath: string | null = null;
let _key: Buffer | null = null;
let _keyCachePath: string | null = null;
let _keyCacheStat: { mtimeMs: number; size: number } | null = null;
let _keyValidationStamp: KeyValidationStamp | null = null;
export function getKey(): Buffer {
  const keyDir = getVaultDir();
  if (!fs.existsSync(keyDir)) {
    throw new Error("Keyblind vault not initialized. Run: keyblind init");
  }

  const keyPath = getKeyPath();
  if (!fs.existsSync(keyPath)) {
    throw new Error("Keyblind key not found. Run: keyblind init");
  }

  const keyStat = fs.statSync(keyPath);
  if (
    _key &&
    _keyCachePath === keyPath &&
    _keyCacheStat?.mtimeMs === keyStat.mtimeMs &&
    _keyCacheStat.size === keyStat.size
  ) {
    return _key;
  }

  const keyData = fs.readFileSync(keyPath);
  const loaded = loadKeyFile(keyData, keyPath);
  const refreshedStat = fs.statSync(keyPath);
  _key = loaded;
  _keyCachePath = keyPath;
  _keyCacheStat = { mtimeMs: refreshedStat.mtimeMs, size: refreshedStat.size };
  rememberKeyValidation();
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

  if (fs.existsSync(getVaultPath())) {
    throw new Error("Keyblind vault database exists without a key file. Restore the matching .keyblind.key or remove the vault directory before reinitializing.");
  }

  const salt = crypto.randomBytes(SALT_LENGTH);
  const key = deriveKey(salt, passphrase);

  writeKeyFile(getKeyPath(), salt, key);
  const keyStat = fs.statSync(getKeyPath());
  _key = key;
  _keyCachePath = getKeyPath();
  _keyCacheStat = { mtimeMs: keyStat.mtimeMs, size: keyStat.size };
  rememberKeyValidation();

  // Pre-create the database so isInitialized() passes
  closeDb();
  getDb();
}

export function isInitialized(): boolean {
  return fs.existsSync(getKeyPath());
}

export function getDb(): Database.Database {
  const dbPath = getVaultPath();
  if (_db && _dbPath === dbPath) return _db;
  if (_db) closeDb();

  _db = new Database(dbPath);
  _dbPath = dbPath;
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
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  _db.exec(`
    CREATE TABLE IF NOT EXISTS secret_aliases (
      alias_name TEXT PRIMARY KEY,
      target_name TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY(target_name) REFERENCES secrets(name) ON DELETE CASCADE
    )
  `);
  _db.exec(`
    CREATE INDEX IF NOT EXISTS idx_secret_aliases_target ON secret_aliases(target_name);
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
  if (getAliasTarget(name)) {
    throw new Error(`Cannot store secret "${name}" because it already exists as an alias.`);
  }

  const key = getKey();
  assertKeyUnlocksVault(key);
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
  rememberKeyValidation();
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

export function resolveSecretWithAlias(name: string): AliasResolution {
  const target = getAliasTarget(name);
  const resolvedName = target ?? name;
  return {
    requestedName: name,
    resolvedName,
    aliasUsed: target !== null,
    value: resolveSecret(resolvedName),
  };
}

export function listSecrets(): string[] {
  const db = getDb();
  const rows = db.prepare("SELECT name FROM secrets WHERE name NOT LIKE '@_@_%' ESCAPE '@' ORDER BY name").all() as { name: string }[];
  return rows.map((r) => r.name).filter((name) => !REMOVED_INTERNAL_SECRET_NAMES.has(name));
}

export function checkVaultDecryptability(): DecryptabilityCheck {
  const db = getDb();
  const rows = [...iterateNamedEncryptedVaultRows(db)];
  const failures: DecryptabilityCheck["failures"] = [];
  let checked = 0;
  let key: Buffer;

  try {
    key = getKey();
  } catch (err: any) {
    for (const row of rows) {
      if (REMOVED_INTERNAL_SECRET_NAMES.has(row.name)) continue;
      checked++;
      failures.push({ name: row.name, error: err?.message ?? "Unable to load key" });
    }
    return { checked, failures };
  }

  for (const row of rows) {
    if (REMOVED_INTERNAL_SECRET_NAMES.has(row.name)) continue;
    checked++;
    try {
      decrypt(row.encrypted_value, row.iv, row.auth_tag, key);
    } catch (err: any) {
      failures.push({ name: row.name, error: err?.message ?? "Unable to decrypt" });
    }
  }

  return { checked, failures };
}

export function createAlias(alias: string, target: string): SecretAlias {
  validateAliasName(alias, "alias");
  validateAliasName(target, "target");
  if (alias === target) throw new Error("Alias cannot target itself.");
  if (secretExists(alias)) throw new Error(`Cannot create alias "${alias}" because it already exists as a secret.`);
  if (getAliasTarget(alias)) throw new Error(`Alias "${alias}" already exists. Delete it before recreating it.`);
  if (getAliasTarget(target)) throw new Error(`Alias "${alias}" cannot target another alias "${target}".`);
  if (!secretExists(target)) throw new Error(`Target secret "${target}" not found.`);

  const db = getDb();
  db.prepare(`
    INSERT INTO secret_aliases (alias_name, target_name, updated_at)
    VALUES (?, ?, datetime('now'))
  `).run(alias, target);
  return getAlias(alias)!;
}

export function deleteAlias(alias: string): boolean {
  const db = getDb();
  const result = db.prepare("DELETE FROM secret_aliases WHERE alias_name = ?").run(alias);
  return result.changes > 0;
}

export function listAliases(): SecretAlias[] {
  const db = getDb();
  const rows = db.prepare(`
    SELECT alias_name, target_name, created_at, updated_at
    FROM secret_aliases
    ORDER BY alias_name
  `).all() as { alias_name: string; target_name: string; created_at: string; updated_at: string }[];
  return rows.map((row) => ({
    alias: row.alias_name,
    target: row.target_name,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }));
}

export function countSecretsByPrefix(prefix: string): number {
  const db = getDb();
  const row = db.prepare("SELECT COUNT(*) as count FROM secrets WHERE substr(name, 1, ?) = ?").get(prefix.length, prefix) as { count: number };
  return row.count;
}

export function deleteSecret(name: string): boolean {
  const db = getDb();
  auditLog(name, "delete");
  db.prepare("DELETE FROM secret_aliases WHERE target_name = ?").run(name);
  const result = db.prepare("DELETE FROM secrets WHERE name = ? AND name NOT LIKE '@_@_expiry:%' ESCAPE '@' AND name NOT LIKE '@_@_keyblind%' ESCAPE '@'").run(name);
  // Also delete any expiry entry
  db.prepare("DELETE FROM secrets WHERE name = ?").run(`__expiry:${name}`);
  return result.changes > 0;
}

function getAlias(alias: string): SecretAlias | null {
  const db = getDb();
  const row = db.prepare(`
    SELECT alias_name, target_name, created_at, updated_at
    FROM secret_aliases
    WHERE alias_name = ?
  `).get(alias) as { alias_name: string; target_name: string; created_at: string; updated_at: string } | undefined;
  if (!row) return null;
  return {
    alias: row.alias_name,
    target: row.target_name,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function getAliasTarget(alias: string): string | null {
  const db = getDb();
  const row = db.prepare("SELECT target_name FROM secret_aliases WHERE alias_name = ?").get(alias) as
    | { target_name: string }
    | undefined;
  return row?.target_name ?? null;
}

function secretExists(name: string): boolean {
  const db = getDb();
  const row = db.prepare("SELECT 1 FROM secrets WHERE name = ?").get(name);
  return row !== undefined;
}

function validateAliasName(name: string, label: "alias" | "target"): void {
  if (name.length === 0 || name.includes("\0")) {
    throw new Error(`Invalid ${label} name.`);
  }
  if (isReservedAliasName(name)) {
    throw new Error(`Cannot use reserved ${label} name "${name}".`);
  }
}

function isReservedAliasName(name: string): boolean {
  return REMOVED_INTERNAL_SECRET_NAMES.has(name) || RESERVED_ALIAS_PREFIXES.some((prefix) => name.startsWith(prefix));
}

// --- Audit Log ---

function auditLog(secretName: string, action: "resolve" | "store" | "delete"): void {
  const db = getDb();
  db.prepare("INSERT INTO audit_log (secret_name, action) VALUES (?, ?)").run(secretName, action);
}

export function getAuditLog(limit: number = 50): { secretName: string; action: string; timestamp: string }[] {
  const db = getDb();
  const rows = db.prepare("SELECT secret_name, action, created_at FROM audit_log ORDER BY id DESC LIMIT ?").all(limit) as { secret_name: string; action: string; created_at: string }[];
  return rows.map((r) => ({
    secretName: r.secret_name,
    action: r.action,
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
  assertKeyUnlocksVault(key);
  const { encrypted, iv, authTag } = encrypt(expiresAt, key);
  db.prepare("INSERT INTO secrets (name, encrypted_value, iv, auth_tag) VALUES (?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET encrypted_value = excluded.encrypted_value, iv = excluded.iv, auth_tag = excluded.auth_tag").run(`__expiry:${name}`, encrypted, iv, authTag);
  rememberKeyValidation();
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
    _dbPath = null;
  }
}

export function clearKey(): void {
  _key = null;
  _keyCachePath = null;
  _keyCacheStat = null;
  _keyValidationStamp = null;
}

export function setMachineIdentityForTests(identity: { stable?: Buffer; legacy?: Buffer } | null): void {
  _machineIdentityForTests = identity;
  clearKey();
}
