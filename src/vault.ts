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
const KEY_FILE_MAGIC = Buffer.from("keyclasp:v3\n", "utf8");
const KEY_FILE_MODE_PASSPHRASE = 0x50;
const KEY_FILE_MODE_MACHINE = 0x4d;
const KEY_FILE_KDF_PBKDF2_SHA256 = 0x01;
const KEY_FILE_V3_LENGTH = KEY_FILE_MAGIC.length + 1 + 1 + 4 + SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH + KEY_LENGTH;
const KEY_FILE_CORRUPT_ERROR = "Keyclasp key file is corrupted or incomplete.";
const KEY_FILE_OLD_FORMAT_ERROR = "Keyclasp key file uses an unsupported format. Clone the keyclasp repository and run scripts/migrate-vault-key-wrap.mjs against this vault.";
const KEY_LOCKED_ERROR = "Keyclasp vault is locked. Unlock with the vault passphrase in an interactive terminal, or use a machine-only vault.";
const KEY_VAULT_MISMATCH_ERROR = "Keyclasp key file does not unlock this vault database. Restore the matching .keyclasp.key before reading or writing secrets.";

export { KEY_FILE_OLD_FORMAT_ERROR, KEY_LOCKED_ERROR };
// Names written by features that have since been removed. Guarded against so
// vaults created by earlier versions never resurface stale, unreadable rows.
const REMOVED_INTERNAL_SECRET_NAMES = new Set([
  "_keyclasp_sso:config",
  "_keyclasp_sso:token",
  "_keyclasp_deadman:config",
  "_keyclasp_deadman:last_checkin",
  "__keyclasp_team_check",
]);

export interface DecryptabilityCheck {
  checked: number;
  failures: { name: string; error: string }[];
}

export const SCOPE_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

export function validateScopeName(value: string, label: "project" | "environment"): void {
  if (!value || value.includes("\0") || !SCOPE_NAME_PATTERN.test(value)) {
    throw new Error(`Invalid ${label} name "${value}".`);
  }
}

export interface ScopedSecret {
  project: string;
  environment: string;
  name: string;
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

let _machineIdentityForTests: { stable?: Buffer; legacy?: Buffer } | null = null;
let _vaultHomeCache: { signature: string; path: string } | null = null;
let _keyPathCache: { vaultDir: string; path: string } | null = null;

function getVaultDir(): string {
  return resolveVaultHome();
}

function resolveVaultHome(): string {
  const signature = process.env.KEYCLASP_HOME ?? "";
  if (_vaultHomeCache?.signature === signature) return _vaultHomeCache.path;

  const resolved = process.env.KEYCLASP_HOME
    ? path.resolve(process.env.KEYCLASP_HOME)
    : path.join(os.homedir(), ".keyclasp");

  _vaultHomeCache = { signature, path: resolved };
  return resolved;
}

export function getVaultLocation(): string {
  return getVaultDir();
}

function getVaultPath(): string {
  return path.join(getVaultDir(), "vault.db");
}

function getKeyPath(): string {
  const vaultDir = getVaultDir();
  if (_keyPathCache?.vaultDir === vaultDir) return _keyPathCache.path;

  const resolved = path.join(vaultDir, ".keyclasp.key");
  _keyPathCache = { vaultDir, path: resolved };
  return resolved;
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

function deriveWrappingKey(salt: Buffer, machineIdentity: Buffer, magic: Buffer = KEY_FILE_MAGIC): Buffer {
  return crypto.createHash("sha256")
    .update(magic)
    .update(salt)
    .update(machineIdentity)
    .digest();
}

type KeyFileMode = "passphrase" | "machine";

interface ParsedV3KeyFile {
  mode: KeyFileMode;
  salt: Buffer;
  iv: Buffer;
  authTag: Buffer;
  wrappedKey: Buffer;
  aad: Buffer;
}

function parseV3KeyFile(keyData: Buffer): ParsedV3KeyFile {
  if (!keyData.subarray(0, KEY_FILE_MAGIC.length).equals(KEY_FILE_MAGIC)) {
    throw new Error(KEY_FILE_OLD_FORMAT_ERROR);
  }
  if (keyData.length !== KEY_FILE_V3_LENGTH) {
    throw new Error(KEY_FILE_CORRUPT_ERROR);
  }

  let offset = KEY_FILE_MAGIC.length;
  const modeByte = keyData[offset];
  offset += 1;
  const kdfByte = keyData[offset];
  offset += 1;
  const iterations = keyData.readUInt32BE(offset);
  offset += 4;
  const salt = keyData.subarray(offset, offset + SALT_LENGTH);
  offset += SALT_LENGTH;
  const iv = keyData.subarray(offset, offset + IV_LENGTH);
  offset += IV_LENGTH;
  const authTag = keyData.subarray(offset, offset + AUTH_TAG_LENGTH);
  offset += AUTH_TAG_LENGTH;
  const wrappedKey = keyData.subarray(offset);

  if (kdfByte !== KEY_FILE_KDF_PBKDF2_SHA256 || iterations !== PBKDF2_ITERATIONS) {
    throw new Error(KEY_FILE_CORRUPT_ERROR);
  }
  if (modeByte !== KEY_FILE_MODE_PASSPHRASE && modeByte !== KEY_FILE_MODE_MACHINE) {
    throw new Error(KEY_FILE_CORRUPT_ERROR);
  }

  const aad = Buffer.concat([
    KEY_FILE_MAGIC,
    Buffer.from([modeByte, kdfByte]),
    keyData.subarray(KEY_FILE_MAGIC.length + 2, KEY_FILE_MAGIC.length + 6),
    salt,
  ]);

  return {
    mode: modeByte === KEY_FILE_MODE_PASSPHRASE ? "passphrase" : "machine",
    salt,
    iv,
    authTag,
    wrappedKey,
    aad,
  };
}

function wrapDek(dek: Buffer, kek: Buffer, aad: Buffer): { iv: Buffer; authTag: Buffer; wrapped: Buffer } {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, kek, iv, { authTagLength: AUTH_TAG_LENGTH });
  cipher.setAAD(aad);
  const wrapped = Buffer.concat([cipher.update(dek), cipher.final()]);
  return { iv, authTag: cipher.getAuthTag(), wrapped };
}

function unwrapDek(parsed: ParsedV3KeyFile, kek: Buffer): Buffer {
  const decipher = crypto.createDecipheriv(ALGORITHM, kek, parsed.iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAAD(parsed.aad);
  decipher.setAuthTag(parsed.authTag);
  return Buffer.concat([decipher.update(parsed.wrappedKey), decipher.final()]);
}

function unwrapWithAnyStableIdentity(parsed: ParsedV3KeyFile): Buffer {
  const identities = deriveStableMachineIdentities();
  for (const identity of identities) {
    try {
      const dek = unwrapDek(parsed, deriveWrappingKey(parsed.salt, identity));
      assertKeyUnlocksVault(dek);
      return dek;
    } catch {
      // Try the next machine-identity candidate.
    }
  }

  throw new Error(KEY_VAULT_MISMATCH_ERROR);
}

function writeKeyFile(keyPath: string, dek: Buffer, mode: KeyFileMode, passphrase: string): void {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const modeByte = mode === "passphrase" ? KEY_FILE_MODE_PASSPHRASE : KEY_FILE_MODE_MACHINE;
  const iterations = Buffer.alloc(4);
  iterations.writeUInt32BE(PBKDF2_ITERATIONS);
  const aad = Buffer.concat([
    KEY_FILE_MAGIC,
    Buffer.from([modeByte, KEY_FILE_KDF_PBKDF2_SHA256]),
    iterations,
    salt,
  ]);
  const kek = mode === "passphrase"
    ? deriveKey(salt, passphrase)
    : deriveWrappingKey(salt, deriveStableMachineIdentity());
  const { iv, authTag, wrapped } = wrapDek(dek, kek, aad);
  const tmpPath = `${keyPath}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmpPath, Buffer.concat([
    KEY_FILE_MAGIC,
    Buffer.from([modeByte, KEY_FILE_KDF_PBKDF2_SHA256]),
    iterations,
    salt,
    iv,
    authTag,
    wrapped,
  ]), { mode: 0o600 });
  backupExistingKeyFile(keyPath);
  fs.renameSync(tmpPath, keyPath);
  fs.chmodSync(keyPath, 0o600);
}

function backupExistingKeyFile(keyPath: string): void {
  if (!fs.existsSync(keyPath)) return;
  const backupPath = nextKeyBackupPath(keyPath);
  fs.copyFileSync(keyPath, backupPath);
  fs.chmodSync(backupPath, 0o600);
}

function readParsedKeyFile(): ParsedV3KeyFile {
  const keyPath = getKeyPath();
  if (!fs.existsSync(keyPath)) {
    throw new Error("Keyclasp key not found. Run: keyclasp init");
  }
  return parseV3KeyFile(fs.readFileSync(keyPath));
}

function assertSupportedKeyFile(): void {
  const keyPath = getKeyPath();
  if (!fs.existsSync(keyPath)) return;
  parseV3KeyFile(fs.readFileSync(keyPath));
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
    for (const row of iterateNamedEncryptedVaultRows(db)) {
      decrypt(row.encrypted_value, row.iv, row.auth_tag, key);
    }
    return true;
  } catch {
    return false;
  } finally {
    if (closeAfter) db.close();
  }
}

function* iterateNamedEncryptedVaultRows(db: Database.Database): IterableIterator<NamedEncryptedVaultRow> {
  if (!tableExists(db, "secrets")) return;
  yield* db.prepare("SELECT name, encrypted_value, iv, auth_tag FROM secrets ORDER BY name").iterate() as IterableIterator<NamedEncryptedVaultRow>;
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
    throw new Error("Keyclasp vault not initialized. Run: keyclasp init");
  }

  const keyPath = getKeyPath();
  if (!fs.existsSync(keyPath)) {
    throw new Error("Keyclasp key not found. Run: keyclasp init");
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

  const parsed = parseV3KeyFile(fs.readFileSync(keyPath));
  const loaded = parsed.mode === "machine"
    ? unwrapWithAnyStableIdentity(parsed)
    : (() => { throw new Error(KEY_LOCKED_ERROR); })();
  cacheLoadedKey(loaded, keyPath);
  return loaded;
}

function cacheLoadedKey(key: Buffer, keyPath: string): void {
  const stat = fs.statSync(keyPath);
  _key = key;
  _keyCachePath = keyPath;
  _keyCacheStat = { mtimeMs: stat.mtimeMs, size: stat.size };
  rememberKeyValidation();
}

export function unlockVault(passphrase: string): void {
  if (!passphrase) {
    throw new Error("Vault passphrase is required.");
  }
  const parsed = readParsedKeyFile();
  if (parsed.mode !== "passphrase") {
    throw new Error("This vault is machine-only and does not use a passphrase.");
  }
  try {
    const dek = unwrapDek(parsed, deriveKey(parsed.salt, passphrase));
    cacheLoadedKey(dek, getKeyPath());
  } catch {
    throw new Error("Vault passphrase is incorrect.");
  }
}

export function initializeVault(passphrase: string): void {
  const vaultDir = getVaultDir();
  if (!fs.existsSync(vaultDir)) {
    fs.mkdirSync(vaultDir, { mode: 0o700, recursive: true });
  }

  if (fs.existsSync(getKeyPath())) {
    throw new Error("Keyclasp is already initialized. To reset, delete the active vault directory.");
  }

  if (fs.existsSync(getVaultPath())) {
    throw new Error("Keyclasp vault database exists without a key file. Restore the matching .keyclasp.key or remove the vault directory before reinitializing.");
  }

  const dek = crypto.randomBytes(KEY_LENGTH);
  const mode: KeyFileMode = passphrase ? "passphrase" : "machine";
  writeKeyFile(getKeyPath(), dek, mode, passphrase);
  cacheLoadedKey(dek, getKeyPath());

  closeDb();
  getDb();
}

export function isInitialized(): boolean {
  return fs.existsSync(getKeyPath());
}

export function verifyVaultPassphrase(passphrase: string): boolean {
  const parsed = readParsedKeyFile();
  if (parsed.mode === "machine") return passphrase === "";
  if (!passphrase) return false;
  try {
    const dek = unwrapDek(parsed, deriveKey(parsed.salt, passphrase));
    cacheLoadedKey(dek, getKeyPath());
    return true;
  } catch {
    return false;
  }
}

export function vaultHasPassphrase(): boolean {
  return readParsedKeyFile().mode === "passphrase";
}

const CREATE_SECRETS_TABLE_SQL = `
  CREATE TABLE IF NOT EXISTS secrets (
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
`;

function secretsTableColumns(db: Database.Database): string[] {
  return (db.pragma("table_info(secrets)") as { name: string }[]).map((r) => r.name);
}

// Retrofits the pre-project/environment schema (single "name" primary key)
// into the composite (project, environment, name) schema, backfilling
// existing rows under project="default", environment="default". Runs lazily
// on every getDb() call but no-ops once migrated. Uses an IMMEDIATE
// transaction so a second process racing to open the same legacy vault
// blocks on the write lock (busy_timeout=5000) rather than double-migrating.
function ensureSecretsSchema(db: Database.Database): void {
  if (secretsTableColumns(db).includes("project")) return;

  const migrate = db.transaction(() => {
    if (secretsTableColumns(db).includes("project")) return;

    if (!tableExists(db, "secrets")) {
      db.exec(CREATE_SECRETS_TABLE_SQL);
      return;
    }

    db.exec(`ALTER TABLE secrets RENAME TO secrets_legacy_migrate`);
    db.exec(CREATE_SECRETS_TABLE_SQL);
    db.exec(`
      INSERT INTO secrets (project, environment, name, encrypted_value, iv, auth_tag, created_at, updated_at)
      SELECT 'default', 'default', name, encrypted_value, iv, auth_tag, created_at, updated_at
      FROM secrets_legacy_migrate
    `);
    db.exec(`DROP TABLE secrets_legacy_migrate`);
  });

  migrate.immediate();
}

export function getDb(): Database.Database {
  assertSupportedKeyFile();
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
    // when the DB file is newly created. This is non-fatal: the
    // vault is fully functional with the default journal mode.
  }
  ensureSecretsSchema(_db);
  return _db;
}

export function storeSecret(project: string, environment: string, name: string, value: string): void {
  validateScopeName(project, "project");
  validateScopeName(environment, "environment");
  const db = getDb();
  const key = getKey();
  assertKeyUnlocksVault(key);
  const { encrypted, iv, authTag } = encrypt(value, key);

  const stmt = db.prepare(`
    INSERT INTO secrets (project, environment, name, encrypted_value, iv, auth_tag, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(project, environment, name) DO UPDATE SET
      encrypted_value = excluded.encrypted_value,
      iv = excluded.iv,
      auth_tag = excluded.auth_tag,
      updated_at = datetime('now')
  `);
  stmt.run(project, environment, name, encrypted, iv, authTag);
  rememberKeyValidation();
}

export function resolveSecret(project: string, environment: string, name: string): string | null {
  if (REMOVED_INTERNAL_SECRET_NAMES.has(name)) return null;

  const db = getDb();
  const key = getKey();
  const row = db.prepare(
    "SELECT encrypted_value, iv, auth_tag FROM secrets WHERE project = ? AND environment = ? AND name = ?"
  ).get(project, environment, name) as
    | { encrypted_value: Buffer; iv: Buffer; auth_tag: Buffer }
    | undefined;

  if (!row) return null;
  return decrypt(row.encrypted_value, row.iv, row.auth_tag, key);
}

export function isNewProjectEnvironment(project: string, environment: string): boolean {
  const db = getDb();
  const row = db.prepare("SELECT 1 FROM secrets WHERE project = ? AND environment = ? LIMIT 1").get(project, environment);
  return row === undefined;
}

export function projects(): string[] {
  const db = getDb();
  const rows = db.prepare("SELECT DISTINCT project FROM secrets ORDER BY project").all() as { project: string }[];
  return rows.map((r) => r.project);
}

export function environments(): string[] {
  const db = getDb();
  const rows = db.prepare("SELECT DISTINCT environment FROM secrets ORDER BY environment").all() as { environment: string }[];
  return rows.map((r) => r.environment);
}

export function listSecrets(project?: string, environment?: string): string[] | ScopedSecret[] {
  const db = getDb();
  const conditions: string[] = ["name NOT LIKE '@_@_%' ESCAPE '@'"];
  const params: string[] = [];
  if (project !== undefined) {
    conditions.push("project = ?");
    params.push(project);
  }
  if (environment !== undefined) {
    conditions.push("environment = ?");
    params.push(environment);
  }

  const rows = db.prepare(
    `SELECT project, environment, name FROM secrets WHERE ${conditions.join(" AND ")} ORDER BY project, environment, name`
  ).all(...params) as ScopedSecret[];
  const filtered = rows.filter((r) => !REMOVED_INTERNAL_SECRET_NAMES.has(r.name));

  if (project !== undefined && environment !== undefined) {
    return filtered.map((r) => r.name);
  }
  return filtered;
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

export function deleteSecret(project: string, environment: string, name: string): boolean {
  const db = getDb();
  const result = db.prepare("DELETE FROM secrets WHERE project = ? AND environment = ? AND name = ?").run(project, environment, name);
  return result.changes > 0;
}

export function deleteProject(project: string): { deleted: number } {
  validateScopeName(project, "project");
  const db = getDb();
  const result = db.prepare("DELETE FROM secrets WHERE project = ?").run(project);
  return { deleted: result.changes };
}

export function deleteEnvironmentInProject(project: string, environment: string): { deleted: number } {
  validateScopeName(project, "project");
  validateScopeName(environment, "environment");
  const db = getDb();
  const result = db.prepare("DELETE FROM secrets WHERE project = ? AND environment = ?").run(project, environment);
  return { deleted: result.changes };
}

export function deleteEnvironmentAcrossAllProjects(environment: string): { deleted: number } {
  validateScopeName(environment, "environment");
  const db = getDb();
  const result = db.prepare("DELETE FROM secrets WHERE environment = ?").run(environment);
  return { deleted: result.changes };
}

function bulkDeletePredicate(project?: string, environment?: string): { where: string; params: string[] } {
  if (project === undefined && environment === undefined) {
    throw new Error("A project or environment is required for bulk deletion.");
  }
  if (project !== undefined) validateScopeName(project, "project");
  if (environment !== undefined) validateScopeName(environment, "environment");

  if (project !== undefined && environment !== undefined) {
    return { where: "project = ? AND environment = ?", params: [project, environment] };
  }
  if (project !== undefined) return { where: "project = ?", params: [project] };
  return { where: "environment = ?", params: [environment!] };
}

export function snapshotBulkDelete(project?: string, environment?: string): ScopedSecret[] {
  const db = getDb();
  const { where, params } = bulkDeletePredicate(project, environment);
  return db.prepare(
    `SELECT project, environment, name FROM secrets WHERE ${where} ORDER BY project, environment, name`,
  ).all(...params) as ScopedSecret[];
}

function sameScopedSecrets(left: ScopedSecret[], right: ScopedSecret[]): boolean {
  return left.length === right.length && left.every((row, index) => {
    const other = right[index];
    return row.project === other.project && row.environment === other.environment && row.name === other.name;
  });
}

export function deleteBulkIfUnchanged(
  project: string | undefined,
  environment: string | undefined,
  expected: ScopedSecret[],
): { deleted: number } {
  const db = getDb();
  const { where, params } = bulkDeletePredicate(project, environment);
  const tx = db.transaction(() => {
    const current = db.prepare(
      `SELECT project, environment, name FROM secrets WHERE ${where} ORDER BY project, environment, name`,
    ).all(...params) as ScopedSecret[];
    if (!sameScopedSecrets(expected, current)) {
      throw new Error("Bulk delete aborted because the selected scope changed while awaiting confirmation. Review it and try again.");
    }
    return db.prepare(`DELETE FROM secrets WHERE ${where}`).run(...params).changes;
  });
  return { deleted: tx.immediate() };
}

function collisionMessage(scopeLabel: string, collisions: { environment?: string; name: string }[]): string {
  const list = collisions
    .map((c) => (c.environment !== undefined ? `${c.environment}/${c.name}` : c.name))
    .join("\n  ");
  return `Rename aborted. ${collisions.length} secret(s) already exist in ${scopeLabel}:\n  ${list}`;
}

export function renameProject(fromProject: string, toProject: string): { moved: number } {
  validateScopeName(fromProject, "project");
  validateScopeName(toProject, "project");
  const db = getDb();
  const tx = db.transaction(() => {
    const collisions = db.prepare(`
      SELECT s1.environment as environment, s1.name as name
      FROM secrets s1
      JOIN secrets s2 ON s2.project = ? AND s2.environment = s1.environment AND s2.name = s1.name
      WHERE s1.project = ?
      ORDER BY s1.environment, s1.name
    `).all(toProject, fromProject) as { environment: string; name: string }[];
    if (collisions.length > 0) {
      throw new Error(collisionMessage(`"${toProject}"`, collisions));
    }
    return db.prepare("UPDATE secrets SET project = ?, updated_at = datetime('now') WHERE project = ?")
      .run(toProject, fromProject).changes;
  });
  return { moved: tx.immediate() };
}

export function renameEnvironmentInProject(project: string, fromEnvironment: string, toEnvironment: string): { moved: number } {
  validateScopeName(project, "project");
  validateScopeName(fromEnvironment, "environment");
  validateScopeName(toEnvironment, "environment");
  const db = getDb();
  const tx = db.transaction(() => {
    const collisions = db.prepare(`
      SELECT s1.name as name
      FROM secrets s1
      JOIN secrets s2 ON s2.project = ? AND s2.environment = ? AND s2.name = s1.name
      WHERE s1.project = ? AND s1.environment = ?
      ORDER BY s1.name
    `).all(project, toEnvironment, project, fromEnvironment) as { name: string }[];
    if (collisions.length > 0) {
      throw new Error(collisionMessage(`"${project}/${toEnvironment}"`, collisions));
    }
    return db.prepare("UPDATE secrets SET environment = ?, updated_at = datetime('now') WHERE project = ? AND environment = ?")
      .run(toEnvironment, project, fromEnvironment).changes;
  });
  return { moved: tx.immediate() };
}

export function renameEnvironmentAcrossAllProjects(fromEnvironment: string, toEnvironment: string): { moved: number; projectsAffected: number } {
  validateScopeName(fromEnvironment, "environment");
  validateScopeName(toEnvironment, "environment");
  const db = getDb();
  const tx = db.transaction(() => {
    const collisions = db.prepare(`
      SELECT s1.project as project, s1.name as name
      FROM secrets s1
      JOIN secrets s2 ON s2.project = s1.project AND s2.environment = ? AND s2.name = s1.name
      WHERE s1.environment = ?
      ORDER BY s1.project, s1.name
    `).all(toEnvironment, fromEnvironment) as { project: string; name: string }[];
    if (collisions.length > 0) {
      const list = collisions.map((c) => `${c.project}/${c.name}`).join("\n  ");
      throw new Error(`Rename aborted. ${collisions.length} secret(s) already exist in environment "${toEnvironment}":\n  ${list}`);
    }
    const affectedProjects = db.prepare("SELECT DISTINCT project FROM secrets WHERE environment = ?").all(fromEnvironment) as { project: string }[];
    const moved = db.prepare("UPDATE secrets SET environment = ?, updated_at = datetime('now') WHERE environment = ?")
      .run(toEnvironment, fromEnvironment).changes;
    return { moved, projectsAffected: affectedProjects.length };
  });
  return tx.immediate();
}

export function renameScope(
  fromProject: string,
  fromEnvironment: string,
  toProject: string,
  toEnvironment: string,
): { moved: number } {
  validateScopeName(fromProject, "project");
  validateScopeName(fromEnvironment, "environment");
  validateScopeName(toProject, "project");
  validateScopeName(toEnvironment, "environment");
  const db = getDb();
  const tx = db.transaction(() => {
    const collisions = db.prepare(`
      SELECT s1.name as name
      FROM secrets s1
      JOIN secrets s2 ON s2.project = ? AND s2.environment = ? AND s2.name = s1.name
      WHERE s1.project = ? AND s1.environment = ?
      ORDER BY s1.name
    `).all(toProject, toEnvironment, fromProject, fromEnvironment) as { name: string }[];
    if (collisions.length > 0) {
      throw new Error(collisionMessage(`"${toProject}/${toEnvironment}"`, collisions));
    }
    return db.prepare(
      "UPDATE secrets SET project = ?, environment = ?, updated_at = datetime('now') WHERE project = ? AND environment = ?"
    ).run(toProject, toEnvironment, fromProject, fromEnvironment).changes;
  });
  return { moved: tx.immediate() };
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
  _vaultHomeCache = null;
  _keyPathCache = null;
}

export function setMachineIdentityForTests(identity: { stable?: Buffer; legacy?: Buffer } | null): void {
  _machineIdentityForTests = identity;
  clearKey();
}
