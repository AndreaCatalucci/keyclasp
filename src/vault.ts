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
const KEY_FILE_MAGIC = Buffer.from("keyclasp:v2\n", "utf8");
const LEGACY_KEY_FILE_MAGIC = Buffer.from("keyblind:v2\n", "utf8");
const KEY_FILE_CORRUPT_ERROR = "Keyclasp key file is corrupted or incomplete.";
const KEY_VAULT_MISMATCH_ERROR = "Keyclasp key file does not unlock this vault database. Restore the matching .keyclasp.key before reading or writing secrets.";
const VAULT_HOME_CONFLICT_ERROR = "Both ~/.keyclasp and ~/.keyblind contain vault data. Set KEYCLASP_HOME explicitly to choose one before continuing.";
// Names written by features that have since been removed. Guarded against so
// vaults created by earlier versions never resurface stale, unreadable rows.
const REMOVED_INTERNAL_SECRET_NAMES = new Set([
  "_keyclasp_sso:config",
  "_keyclasp_sso:token",
  "_keyclasp_deadman:config",
  "_keyclasp_deadman:last_checkin",
  "__keyclasp_team_check",
  "_keyblind_sso:config",
  "_keyblind_sso:token",
  "_keyblind_deadman:config",
  "_keyblind_deadman:last_checkin",
  "__keyblind_team_check",
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
  const signature = `${process.env.KEYCLASP_HOME ?? ""}\0${process.env.KEYBLIND_HOME ?? ""}`;
  if (_vaultHomeCache?.signature === signature) return _vaultHomeCache.path;

  let resolved: string;
  if (process.env.KEYCLASP_HOME) {
    resolved = path.resolve(process.env.KEYCLASP_HOME);
  } else if (process.env.KEYBLIND_HOME) {
    resolved = path.resolve(process.env.KEYBLIND_HOME);
  } else {
    const preferredHome = path.join(os.homedir(), ".keyclasp");
    const legacyHome = path.join(os.homedir(), ".keyblind");
    const preferredHasVault = hasCompleteVaultAt(preferredHome);
    const legacyHasVault = hasCompleteVaultAt(legacyHome);
    if (preferredHasVault && legacyHasVault) throw new Error(VAULT_HOME_CONFLICT_ERROR);
    resolved = legacyHasVault ? legacyHome : preferredHome;
  }

  _vaultHomeCache = { signature, path: resolved };
  return resolved;
}

function hasCompleteVaultAt(vaultDir: string): boolean {
  if (!fs.existsSync(path.join(vaultDir, "vault.db"))) return false;
  return fs.existsSync(path.join(vaultDir, ".keyclasp.key")) ||
    fs.existsSync(path.join(vaultDir, ".keyblind.key"));
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

  const preferredPath = path.join(vaultDir, ".keyclasp.key");
  const legacyPath = path.join(vaultDir, ".keyblind.key");
  const resolved = !fs.existsSync(preferredPath) && fs.existsSync(legacyPath) ? legacyPath : preferredPath;
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

function xorWithKey(key: Buffer, wrappingKey: Buffer): Buffer {
  const output = Buffer.alloc(key.length);
  for (let i = 0; i < key.length; i++) {
    output[i] = key[i] ^ wrappingKey[i % wrappingKey.length];
  }
  return output;
}

function loadKeyFile(keyData: Buffer, keyPath: string): Buffer {
  const magic = [KEY_FILE_MAGIC, LEGACY_KEY_FILE_MAGIC].find((candidate) =>
    keyData.subarray(0, candidate.length).equals(candidate)
  );
  if (magic) {
    const expectedLength = magic.length + SALT_LENGTH + KEY_LENGTH;
    if (keyData.length !== expectedLength) {
      throw new Error(KEY_FILE_CORRUPT_ERROR);
    }

    const salt = keyData.subarray(magic.length, magic.length + SALT_LENGTH);
    const wrappedKey = keyData.subarray(magic.length + SALT_LENGTH);
    return unwrapWithAnyStableIdentity(salt, wrappedKey, magic);
  }

  if (keyData.length !== SALT_LENGTH + KEY_LENGTH) {
    throw new Error(KEY_FILE_CORRUPT_ERROR);
  }

  const salt = keyData.subarray(0, SALT_LENGTH);
  const wrappedKey = keyData.subarray(SALT_LENGTH);
  const legacyIdentity = _machineIdentityForTests?.legacy ?? deriveLegacyMachineIdentity();
  const key = xorWithKey(wrappedKey, legacyIdentity);
  assertKeyUnlocksVault(key);
  const upgradedKeyPath = path.basename(keyPath) === ".keyblind.key"
    ? path.join(path.dirname(keyPath), ".keyclasp.key")
    : keyPath;
  writeKeyFile(upgradedKeyPath, salt, key);
  _keyPathCache = null;
  return key;
}

function unwrapWithAnyStableIdentity(salt: Buffer, wrappedKey: Buffer, magic: Buffer): Buffer {
  const identities = deriveStableMachineIdentities();
  for (const identity of identities) {
    const key = xorWithKey(wrappedKey, deriveWrappingKey(salt, identity, magic));
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

  const keyData = fs.readFileSync(keyPath);
  const loaded = loadKeyFile(keyData, keyPath);
  const refreshedKeyPath = getKeyPath();
  const refreshedStat = fs.statSync(refreshedKeyPath);
  _key = loaded;
  _keyCachePath = refreshedKeyPath;
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
    throw new Error("Keyclasp is already initialized. To reset, delete the active vault directory.");
  }

  if (fs.existsSync(getVaultPath())) {
    throw new Error("Keyclasp vault database exists without a key file. Restore the matching .keyclasp.key or remove the vault directory before reinitializing.");
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

function collisionMessage(scopeLabel: string, collisions: { environment?: string; name: string }[]): string {
  const list = collisions
    .map((c) => (c.environment !== undefined ? `${c.environment}/${c.name}` : c.name))
    .join("\n  ");
  return `Rename aborted — ${collisions.length} secret(s) already exist in ${scopeLabel}:\n  ${list}`;
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
      throw new Error(`Rename aborted — ${collisions.length} secret(s) already exist in environment "${toEnvironment}":\n  ${list}`);
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
