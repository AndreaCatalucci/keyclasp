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
const KEY_FILE_MAGIC_V3 = Buffer.from("keyclasp:v3\n", "utf8");
const KEY_FILE_MAGIC_V4 = Buffer.from("keyclasp:v4\n", "utf8");
const KEY_FILE_MODE_PASSPHRASE = 0x50;
const KEY_FILE_MODE_MACHINE = 0x4d;
const KEY_FILE_KDF_PBKDF2_SHA256 = 0x01;
const KEY_FILE_STATE_ACTIVE = 0x41;
const KEY_FILE_STATE_MIGRATION_PENDING = 0x50;
const KEY_FILE_V3_LENGTH = KEY_FILE_MAGIC_V3.length + 1 + 1 + 4 + SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH + KEY_LENGTH;
const KEY_FILE_V4_LENGTH = KEY_FILE_MAGIC_V4.length + 1 + 1 + 1 + 4 + SALT_LENGTH + 16 + IV_LENGTH + AUTH_TAG_LENGTH + KEY_LENGTH;
const KEY_FILE_CORRUPT_ERROR = "Keyclasp key file is corrupted or incomplete.";
const KEY_FILE_OLD_FORMAT_ERROR = "Keyclasp key file uses an unsupported format. Clone the keyclasp repository and run scripts/migrate-vault-key-wrap.mjs against this vault.";
const KEY_LOCKED_ERROR = "Keyclasp vault is locked. Unlock with the vault passphrase in an interactive terminal, or use a machine-only vault.";
const KEY_VAULT_MISMATCH_ERROR = "Keyclasp key file does not unlock this vault database. Restore the matching .keyclasp.key before reading or writing secrets.";
const VAULT_DATABASE_MISSING_ERROR = "Keyclasp vault database is missing. Restore vault.db and its matching .keyclasp.key from the same backup.";
const VAULT_DATABASE_REPLACED_ERROR = "Keyclasp vault database was replaced while open. Restart Keyclasp only after restoring vault.db and its matching .keyclasp.key from the same backup.";
const VAULT_FORMAT_VERSION = 2;
const RECORD_KIND_SECRET = "secret";
const RECORD_AAD_MAGIC = Buffer.from("keyclasp:record-aad:v1\0", "utf8");
const VAULT_KEY_CHECK_AAD = Buffer.from("keyclasp:vault-key-check:v1\0", "utf8");

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
type NamedEncryptedVaultRow = EncryptedVaultRow & {
  project: string;
  environment: string;
  name: string;
  record_id?: Buffer;
  record_kind?: string;
};
type FileStamp = { mtimeMs: number; size: number } | null;
type FileIdentity = { device: number; inode: number };
type KeyValidationStamp = {
  keyPath: string;
  key: FileStamp;
  dbPath: string;
  db: FileStamp;
  wal: FileStamp;
};

let _machineIdentityForTests: { stable?: Buffer; legacy?: Buffer } | null = null;
let _migrationFaultForTests: "after-backup" | "before-commit" | "after-commit" | null = null;
let _migrationBackupHookForTests: ((backupPath: string) => void) | null = null;
let _initializingVault = false;
let _vaultHomeCache: { signature: string; path: string } | null = null;
let _keyPathCache: { vaultDir: string; path: string } | null = null;

function getVaultDir(): string {
  return resolveVaultHome();
}

function enforceOwnerOnlyVaultPermissions(): void {
  const vaultDir = getVaultDir();
  if (!fs.existsSync(vaultDir)) return;
  enforceOwnerOnlyPath(vaultDir, 0o700, "vault directory");
  for (const entry of fs.readdirSync(vaultDir)) {
    if (entry === ".initialize.db" || entry.startsWith(".initialize.db-") ||
        entry === ".keyclasp.key" || entry.startsWith(".keyclasp.key.") ||
        entry === "vault.db" || entry.startsWith("vault.db-" ) || entry.startsWith("vault.db.")) {
      const entryPath = path.join(vaultDir, entry);
      try {
        enforceOwnerOnlyPath(entryPath, 0o600, `vault file "${entry}"`);
      } catch (err: any) {
        if (err?.code === "ENOENT" || !fs.existsSync(entryPath)) continue;
        throw err;
      }
    }
  }
}

function enforceOwnerOnlyPath(filePath: string, mode: number, label: string): void {
  const before = fs.lstatSync(filePath);
  if (before.isSymbolicLink()) {
    throw new Error(`Unsafe ${label}: symbolic links are not allowed.`);
  }
  if (process.platform === "win32") {
    throw new Error(`Cannot verify owner-only Windows ACLs for ${label}; Keyclasp vault access is blocked on this host.`);
  }
  const currentUid = process.getuid?.();
  if (currentUid !== undefined && before.uid !== currentUid) {
    throw new Error(`Unsafe ${label}: owner UID ${before.uid} does not match the current UID ${currentUid}.`);
  }
  if (process.platform === "darwin") repairMacOsAcl(filePath, label);
  if ((before.mode & 0o777) === mode) return;
  try {
    fs.chmodSync(filePath, mode);
  } catch (err: any) {
    throw new Error(`Cannot repair owner-only permissions for ${label}: ${err?.message ?? "permission change failed"}`);
  }
  const actual = fs.statSync(filePath).mode & 0o777;
  if (actual !== mode) {
    throw new Error(`Cannot verify owner-only permissions for ${label}; expected ${mode.toString(8)}, found ${actual.toString(8)}.`);
  }
}

function repairMacOsAcl(filePath: string, label: string): void {
  if (macOsAclEntries(filePath).length === 0) return;
  try {
    execFileSync("/bin/chmod", ["-N", filePath], { stdio: ["ignore", "ignore", "pipe"] });
  } catch (err: any) {
    throw new Error(`Cannot remove macOS ACL entries from ${label}: ${err?.message ?? "ACL repair failed"}`);
  }
  if (macOsAclEntries(filePath).length > 0) {
    throw new Error(`Cannot verify an empty macOS ACL for ${label}.`);
  }
}

function macOsAclEntries(filePath: string): string[] {
  let output: string;
  try {
    output = execFileSync("/bin/ls", ["-lde", filePath], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err: any) {
    throw new Error(`Cannot inspect the macOS ACL for "${filePath}": ${err?.message ?? "ACL inspection failed"}`);
  }
  return output.split("\n").filter((line) => /^\s*\d+:\s/.test(line));
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

function deriveWrappingKey(salt: Buffer, machineIdentity: Buffer, magic: Buffer = KEY_FILE_MAGIC_V4): Buffer {
  return crypto.createHash("sha256")
    .update(magic)
    .update(salt)
    .update(machineIdentity)
    .digest();
}

type KeyFileMode = "passphrase" | "machine";

interface ParsedKeyFile {
  format: 3 | 4;
  magic: Buffer;
  mode: KeyFileMode;
  salt: Buffer;
  iv: Buffer;
  authTag: Buffer;
  wrappedKey: Buffer;
  aad: Buffer;
  vaultId: Buffer | null;
  state: "active" | "migration-pending";
}

function parseKeyFile(keyData: Buffer): ParsedKeyFile {
  const isV3 = keyData.subarray(0, KEY_FILE_MAGIC_V3.length).equals(KEY_FILE_MAGIC_V3);
  const isV4 = keyData.subarray(0, KEY_FILE_MAGIC_V4.length).equals(KEY_FILE_MAGIC_V4);
  if (!isV3 && !isV4) {
    throw new Error(KEY_FILE_OLD_FORMAT_ERROR);
  }
  const format = isV4 ? 4 : 3;
  const magic = isV4 ? KEY_FILE_MAGIC_V4 : KEY_FILE_MAGIC_V3;
  if (keyData.length !== (isV4 ? KEY_FILE_V4_LENGTH : KEY_FILE_V3_LENGTH)) {
    throw new Error(KEY_FILE_CORRUPT_ERROR);
  }

  let offset = magic.length;
  const modeByte = keyData[offset];
  offset += 1;
  const kdfByte = keyData[offset];
  offset += 1;
  const stateByte = isV4 ? keyData[offset] : KEY_FILE_STATE_ACTIVE;
  if (isV4) offset += 1;
  const iterations = keyData.readUInt32BE(offset);
  offset += 4;
  const salt = keyData.subarray(offset, offset + SALT_LENGTH);
  offset += SALT_LENGTH;
  const vaultId = isV4 ? keyData.subarray(offset, offset + 16) : null;
  if (isV4) offset += 16;
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
  if (stateByte !== KEY_FILE_STATE_ACTIVE && stateByte !== KEY_FILE_STATE_MIGRATION_PENDING) {
    throw new Error(KEY_FILE_CORRUPT_ERROR);
  }

  const aad = Buffer.concat([
    magic,
    Buffer.from([modeByte, kdfByte]),
    ...(isV4 ? [Buffer.from([stateByte])] : []),
    keyData.subarray(magic.length + 2 + (isV4 ? 1 : 0), magic.length + 6 + (isV4 ? 1 : 0)),
    salt,
    ...(vaultId ? [vaultId] : []),
  ]);

  return {
    format,
    magic,
    mode: modeByte === KEY_FILE_MODE_PASSPHRASE ? "passphrase" : "machine",
    salt,
    iv,
    authTag,
    wrappedKey,
    aad,
    vaultId,
    state: stateByte === KEY_FILE_STATE_MIGRATION_PENDING ? "migration-pending" : "active",
  };
}

function wrapDek(dek: Buffer, kek: Buffer, aad: Buffer): { iv: Buffer; authTag: Buffer; wrapped: Buffer } {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, kek, iv, { authTagLength: AUTH_TAG_LENGTH });
  cipher.setAAD(aad);
  const wrapped = Buffer.concat([cipher.update(dek), cipher.final()]);
  return { iv, authTag: cipher.getAuthTag(), wrapped };
}

function unwrapDek(parsed: ParsedKeyFile, kek: Buffer): Buffer {
  const decipher = crypto.createDecipheriv(ALGORITHM, kek, parsed.iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAAD(parsed.aad);
  decipher.setAuthTag(parsed.authTag);
  return Buffer.concat([decipher.update(parsed.wrappedKey), decipher.final()]);
}

function unwrapWithAnyStableIdentity(parsed: ParsedKeyFile): Buffer {
  const identities = deriveStableMachineIdentities();
  for (const identity of identities) {
    try {
      const dek = unwrapDek(parsed, deriveWrappingKey(parsed.salt, identity, parsed.magic));
      assertKeyUnlocksVault(dek, parsed.vaultId, parsed.state === "migration-pending");
      return dek;
    } catch {
      // Try the next machine-identity candidate.
    }
  }

  throw new Error(KEY_VAULT_MISMATCH_ERROR);
}

function writeKeyFile(
  keyPath: string,
  dek: Buffer,
  mode: KeyFileMode,
  passphrase: string,
  vaultId: Buffer,
  state: "active" | "migration-pending" = "active",
): void {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const modeByte = mode === "passphrase" ? KEY_FILE_MODE_PASSPHRASE : KEY_FILE_MODE_MACHINE;
  const iterations = Buffer.alloc(4);
  iterations.writeUInt32BE(PBKDF2_ITERATIONS);
  const stateByte = state === "active" ? KEY_FILE_STATE_ACTIVE : KEY_FILE_STATE_MIGRATION_PENDING;
  const aad = Buffer.concat([
    KEY_FILE_MAGIC_V4,
    Buffer.from([modeByte, KEY_FILE_KDF_PBKDF2_SHA256]),
    Buffer.from([stateByte]),
    iterations,
    salt,
    vaultId,
  ]);
  const kek = mode === "passphrase"
    ? deriveKey(salt, passphrase)
    : deriveWrappingKey(salt, deriveStableMachineIdentity(), KEY_FILE_MAGIC_V4);
  const { iv, authTag, wrapped } = wrapDek(dek, kek, aad);
  const tmpPath = `${keyPath}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmpPath, Buffer.concat([
    KEY_FILE_MAGIC_V4,
    Buffer.from([modeByte, KEY_FILE_KDF_PBKDF2_SHA256]),
    Buffer.from([stateByte]),
    iterations,
    salt,
    vaultId,
    iv,
    authTag,
    wrapped,
  ]), { mode: 0o600 });
  backupExistingKeyFile(keyPath);
  fs.renameSync(tmpPath, keyPath);
  fs.chmodSync(keyPath, 0o600);
}

export function writeLegacyV3KeyFileForTests(dek: Buffer, passphrase: string): void {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const mode: KeyFileMode = passphrase ? "passphrase" : "machine";
  const modeByte = mode === "passphrase" ? KEY_FILE_MODE_PASSPHRASE : KEY_FILE_MODE_MACHINE;
  const iterations = Buffer.alloc(4);
  iterations.writeUInt32BE(PBKDF2_ITERATIONS);
  const aad = Buffer.concat([
    KEY_FILE_MAGIC_V3,
    Buffer.from([modeByte, KEY_FILE_KDF_PBKDF2_SHA256]),
    iterations,
    salt,
  ]);
  const kek = mode === "passphrase"
    ? deriveKey(salt, passphrase)
    : deriveWrappingKey(salt, deriveStableMachineIdentity(), KEY_FILE_MAGIC_V3);
  const { iv, authTag, wrapped } = wrapDek(dek, kek, aad);
  fs.writeFileSync(getKeyPath(), Buffer.concat([
    KEY_FILE_MAGIC_V3,
    Buffer.from([modeByte, KEY_FILE_KDF_PBKDF2_SHA256]),
    iterations,
    salt,
    iv,
    authTag,
    wrapped,
  ]), { mode: 0o600 });
  clearKey();
}

function backupExistingKeyFile(keyPath: string): void {
  if (!fs.existsSync(keyPath)) return;
  const backupPath = nextKeyBackupPath(keyPath);
  fs.copyFileSync(keyPath, backupPath);
  fs.chmodSync(backupPath, 0o600);
}

function readParsedKeyFile(): ParsedKeyFile {
  const keyPath = getKeyPath();
  if (!fs.existsSync(keyPath)) {
    throw new Error("Keyclasp key not found. Run: keyclasp init");
  }
  return parseKeyFile(fs.readFileSync(keyPath));
}

function assertSupportedKeyFile(): void {
  const keyPath = getKeyPath();
  if (!fs.existsSync(keyPath)) return;
  parseKeyFile(fs.readFileSync(keyPath));
}

function nextKeyBackupPath(keyPath: string): string {
  for (let index = 1; ; index++) {
    const backupPath = `${keyPath}.${index}.bak`;
    if (!fs.existsSync(backupPath)) return backupPath;
  }
}

function assertKeyUnlocksVault(
  key: Buffer,
  expectedVaultId: Buffer | null = null,
  allowPendingLegacy = false,
): void {
  if (keyValidationCurrent()) return;
  if (canDecryptVaultRows(key, expectedVaultId, allowPendingLegacy)) return;
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

function readFileIdentity(filePath: string): FileIdentity | null {
  try {
    const stat = fs.statSync(filePath);
    return { device: stat.dev, inode: stat.ino };
  } catch (err: any) {
    if (err?.code === "ENOENT") return null;
    throw err;
  }
}

function assertCachedDatabaseStillCurrent(): void {
  if (!_db || !_dbPath) return;
  const current = readFileIdentity(_dbPath);
  if (!current) {
    closeDb();
    throw new Error(VAULT_DATABASE_MISSING_ERROR);
  }
  if (!_dbFileIdentity || current.device !== _dbFileIdentity.device || current.inode !== _dbFileIdentity.inode) {
    closeDb();
    throw new Error(VAULT_DATABASE_REPLACED_ERROR);
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

function canDecryptVaultRows(
  key: Buffer,
  expectedVaultId: Buffer | null = null,
  allowPendingLegacy = false,
): boolean {
  const dbPath = getVaultPath();
  if (!fs.existsSync(dbPath)) return true;

  const db = _db && _dbPath === dbPath
    ? _db
    : new Database(dbPath, { readonly: true, fileMustExist: true });
  const closeAfter = db !== _db;
  try {
    const vaultId = readCurrentVaultId(db);
    if (expectedVaultId && vaultId && !vaultId.equals(expectedVaultId)) return false;
    if (expectedVaultId && !vaultId && !allowPendingLegacy) return false;
    if (vaultId) {
      verifyVaultKeyCheck(db, key, vaultId);
      return true;
    }
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
  const current = readCurrentVaultId(db) !== null;
  const columns = current
    ? "project, environment, name, record_id, record_kind, encrypted_value, iv, auth_tag"
    : `${secretsTableColumns(db).includes("project") ? "project, environment" : "'default' AS project, 'default' AS environment"}, name, encrypted_value, iv, auth_tag`;
  yield* db.prepare(`SELECT ${columns} FROM secrets ORDER BY project, environment, name`).iterate() as IterableIterator<NamedEncryptedVaultRow>;
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

function canonicalField(value: Buffer | string): Buffer {
  const bytes = typeof value === "string" ? Buffer.from(value, "utf8") : value;
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

export function buildRecordAssociatedData(identity: {
  vaultId: Buffer;
  recordId: Buffer;
  project: string;
  environment: string;
  name: string;
  recordKind?: string;
  formatVersion?: number;
}): Buffer {
  const version = Buffer.alloc(4);
  version.writeUInt32BE(identity.formatVersion ?? VAULT_FORMAT_VERSION);
  return Buffer.concat([
    RECORD_AAD_MAGIC,
    version,
    canonicalField(identity.vaultId),
    canonicalField(identity.recordId),
    canonicalField(identity.project),
    canonicalField(identity.environment),
    canonicalField(identity.name),
    canonicalField(identity.recordKind ?? RECORD_KIND_SECRET),
  ]);
}

function encryptRecord(value: string, key: Buffer, identity: Parameters<typeof buildRecordAssociatedData>[0]): ReturnType<typeof encrypt> {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  cipher.setAAD(buildRecordAssociatedData(identity));
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return { encrypted, iv, authTag: cipher.getAuthTag() };
}

function decryptRecord(row: NamedEncryptedVaultRow, key: Buffer, vaultId: Buffer): string {
  if (!row.record_id || row.record_id.length !== 16 || row.record_kind !== RECORD_KIND_SECRET) {
    throw new Error("Keyclasp vault record identity is missing or invalid.");
  }
  const decipher = crypto.createDecipheriv(ALGORITHM, key, row.iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAAD(buildRecordAssociatedData({
    vaultId,
    recordId: row.record_id,
    project: row.project,
    environment: row.environment,
    name: row.name,
    recordKind: row.record_kind,
  }));
  decipher.setAuthTag(row.auth_tag);
  return Buffer.concat([decipher.update(row.encrypted_value), decipher.final()]).toString("utf8");
}

function createVaultKeyCheck(key: Buffer, vaultId: Buffer): { iv: Buffer; authTag: Buffer } {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  cipher.setAAD(Buffer.concat([VAULT_KEY_CHECK_AAD, vaultId]));
  cipher.final();
  return { iv, authTag: cipher.getAuthTag() };
}

function verifyVaultKeyCheck(db: Database.Database, key: Buffer, vaultId: Buffer): void {
  const row = db.prepare("SELECT key_check_iv, key_check_tag FROM vault_metadata WHERE singleton = 1").get() as
    | { key_check_iv: Buffer; key_check_tag: Buffer }
    | undefined;
  if (!row || !Buffer.isBuffer(row.key_check_iv) || row.key_check_iv.length !== IV_LENGTH ||
      !Buffer.isBuffer(row.key_check_tag) || row.key_check_tag.length !== AUTH_TAG_LENGTH) {
    throw new Error("Keyclasp vault key-check metadata is corrupt or incomplete.");
  }
  const decipher = crypto.createDecipheriv(ALGORITHM, key, row.key_check_iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAAD(Buffer.concat([VAULT_KEY_CHECK_AAD, vaultId]));
  decipher.setAuthTag(row.key_check_tag);
  decipher.final();
}

export function decrypt(encrypted: Buffer, iv: Buffer, authTag: Buffer, key: Buffer): string {
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
}

let _db: Database.Database | null = null;
let _dbPath: string | null = null;
let _dbFileIdentity: FileIdentity | null = null;
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
  enforceOwnerOnlyVaultPermissions();
  assertCachedDatabaseStillCurrent();

  const keyStat = fs.statSync(keyPath);
  if (
    _key &&
    _keyCachePath === keyPath &&
    _keyCacheStat?.mtimeMs === keyStat.mtimeMs &&
    _keyCacheStat.size === keyStat.size
  ) {
    return _key;
  }

  const parsed = parseKeyFile(fs.readFileSync(keyPath));
  const loaded = parsed.mode === "machine"
    ? unwrapWithAnyStableIdentity(parsed)
    : (() => { throw new Error(KEY_LOCKED_ERROR); })();
  completeVaultOpen(parsed, loaded, "");
  cacheLoadedKey(loaded, keyPath);
  rememberKeyValidation();
  return loaded;
}

function completeVaultOpen(parsed: ParsedKeyFile, key: Buffer, passphrase: string): Buffer {
  const db = getDb();
  const vaultId = ensureCurrentVaultFormat(db, key, parsed.vaultId, {
    allowPendingLegacy: parsed.state === "migration-pending",
    markMigrationPending: parsed.format === 3
      ? (pendingVaultId) => writeKeyFile(getKeyPath(), key, parsed.mode, passphrase, pendingVaultId, "migration-pending")
      : undefined,
  });
  if (parsed.format === 3 || parsed.state === "migration-pending") {
    writeKeyFile(getKeyPath(), key, parsed.mode, passphrase, vaultId);
  }
  return vaultId;
}

function ensureVaultFormatMatchesKey(db: Database.Database, key: Buffer): Buffer {
  return ensureCurrentVaultFormat(db, key, readParsedKeyFile().vaultId);
}

function cacheLoadedKey(key: Buffer, keyPath: string): void {
  const stat = fs.statSync(keyPath);
  _key = key;
  _keyCachePath = keyPath;
  _keyCacheStat = { mtimeMs: stat.mtimeMs, size: stat.size };
}

export function unlockVault(passphrase: string): void {
  if (!passphrase) {
    throw new Error("Vault passphrase is required.");
  }
  const parsed = readParsedKeyFile();
  if (parsed.mode !== "passphrase") {
    throw new Error("This vault is machine-only and does not use a passphrase.");
  }
  let dek: Buffer;
  try {
    dek = unwrapDek(parsed, deriveKey(parsed.salt, passphrase));
  } catch {
    throw new Error("Vault passphrase is incorrect.");
  }
  assertKeyUnlocksVault(dek, parsed.vaultId, parsed.state === "migration-pending");
  completeVaultOpen(parsed, dek, passphrase);
  cacheLoadedKey(dek, getKeyPath());
  rememberKeyValidation();
}

export function initializeVault(passphrase: string): void {
  const vaultDir = getVaultDir();
  if (!fs.existsSync(vaultDir)) {
    fs.mkdirSync(vaultDir, { mode: 0o700, recursive: true });
  }
  enforceOwnerOnlyVaultPermissions();
  const lockPath = path.join(vaultDir, ".initialize.db");
  const lockDb = new Database(lockPath);
  fs.chmodSync(lockPath, 0o600);
  lockDb.pragma("busy_timeout = 1");
  try {
    lockDb.exec("BEGIN EXCLUSIVE");
  } catch (err: any) {
    lockDb.close();
    if (err?.code === "SQLITE_BUSY") {
      throw new Error("Keyclasp initialization is already in progress. Retry after the other process finishes.");
    }
    throw err;
  }

  try {
    if (fs.existsSync(getKeyPath())) {
      throw new Error("Keyclasp is already initialized. To reset, delete the active vault directory.");
    }

    if (fs.existsSync(getVaultPath())) {
      throw new Error("Keyclasp vault database exists without a key file. Restore the matching .keyclasp.key or remove the vault directory before reinitializing.");
    }

    const dek = crypto.randomBytes(KEY_LENGTH);
    const vaultId = crypto.randomBytes(16);
    const mode: KeyFileMode = passphrase ? "passphrase" : "machine";
    writeKeyFile(getKeyPath(), dek, mode, passphrase, vaultId);

    closeDb();
    let db: Database.Database;
    _initializingVault = true;
    try {
      db = getDb();
      ensureCurrentVaultFormat(db, dek, vaultId);
    } finally {
      _initializingVault = false;
    }
    cacheLoadedKey(dek, getKeyPath());
    rememberKeyValidation();
  } finally {
    if (lockDb.inTransaction) lockDb.exec("ROLLBACK");
    lockDb.close();
  }
}

export function isInitialized(): boolean {
  enforceOwnerOnlyVaultPermissions();
  return fs.existsSync(getKeyPath());
}

export function verifyVaultPassphrase(passphrase: string): boolean {
  const parsed = readParsedKeyFile();
  if (parsed.mode === "machine") return passphrase === "";
  if (!passphrase) return false;
  try {
    const dek = unwrapDek(parsed, deriveKey(parsed.salt, passphrase));
    assertKeyUnlocksVault(dek, parsed.vaultId, parsed.state === "migration-pending");
    completeVaultOpen(parsed, dek, passphrase);
    cacheLoadedKey(dek, getKeyPath());
    rememberKeyValidation();
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

function createCurrentSecretsTableSql(tableName: "secrets" | "secrets_current_migrate"): string {
  return `
  CREATE TABLE ${tableName} (
    project TEXT NOT NULL,
    environment TEXT NOT NULL,
    name TEXT NOT NULL,
    record_id BLOB NOT NULL UNIQUE CHECK(length(record_id) = 16),
    record_kind TEXT NOT NULL CHECK(record_kind = 'secret'),
    encrypted_value BLOB NOT NULL,
    iv BLOB NOT NULL CHECK(length(iv) = 12),
    auth_tag BLOB NOT NULL CHECK(length(auth_tag) = 16),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (project, environment, name)
  )
`;
}

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

function readCurrentVaultId(db: Database.Database): Buffer | null {
  if (!tableExists(db, "vault_metadata")) return null;
  const row = db.prepare("SELECT format_version, vault_id FROM vault_metadata WHERE singleton = 1").get() as
    | { format_version: number; vault_id: Buffer }
    | undefined;
  if (!row || row.format_version !== VAULT_FORMAT_VERSION || !Buffer.isBuffer(row.vault_id) || row.vault_id.length !== 16) {
    throw new Error("Keyclasp vault format metadata is corrupt or unsupported.");
  }
  const columns = secretsTableColumns(db);
  if (!columns.includes("record_id") || !columns.includes("record_kind")) {
    throw new Error("Keyclasp vault is partially migrated: format metadata and record schema disagree. Restore a pre-migration backup.");
  }
  const metadataColumns = (db.pragma("table_info(vault_metadata)") as { name: string }[]).map((column) => column.name);
  if (!metadataColumns.includes("key_check_iv") || !metadataColumns.includes("key_check_tag")) {
    throw new Error("Keyclasp vault format metadata is incomplete. Restore a pre-migration backup.");
  }
  return row.vault_id;
}

function nextVaultBackupPath(dbPath: string): string {
  return `${dbPath}.v1.${process.pid}.${crypto.randomBytes(6).toString("hex")}.bak`;
}

function ensureCurrentVaultFormat(
  db: Database.Database,
  key: Buffer,
  expectedVaultId: Buffer | null = null,
  options: {
    allowPendingLegacy?: boolean;
    markMigrationPending?: (vaultId: Buffer) => void;
  } = {},
): Buffer {
  const current = readCurrentVaultId(db);
  if (current) {
    if (expectedVaultId && !current.equals(expectedVaultId)) throw new Error(KEY_VAULT_MISMATCH_ERROR);
    verifyVaultKeyCheck(db, key, current);
    return current;
  }

  if (!tableExists(db, "secrets")) {
    if (!_initializingVault || !expectedVaultId) {
      throw new Error("Keyclasp vault database is empty or replaced. Restore vault.db and its matching .keyclasp.key from the same backup.");
    }
    const create = db.transaction(() => {
      const raced = readCurrentVaultId(db);
      if (raced) {
        if (!raced.equals(expectedVaultId)) throw new Error(KEY_VAULT_MISMATCH_ERROR);
        return raced;
      }
      const vaultId = expectedVaultId;
      db.exec(createCurrentSecretsTableSql("secrets"));
      createVaultMetadata(db, key, vaultId);
      return vaultId;
    });
    return create.immediate();
  }
  const existingColumns = secretsTableColumns(db);
  if (existingColumns.includes("record_id") || existingColumns.includes("record_kind")) {
    throw new Error("Keyclasp vault is partially migrated: record identity exists without format metadata. Restore a pre-migration backup.");
  }
  if (expectedVaultId && !options.allowPendingLegacy) {
    throw new Error("Keyclasp vault database is replaced or rolled back to a legacy format. Restore the matching current database.");
  }

  const migrate = db.transaction(() => {
    const raced = readCurrentVaultId(db);
    if (raced) {
      if (expectedVaultId && !raced.equals(expectedVaultId)) throw new Error(KEY_VAULT_MISMATCH_ERROR);
      return raced;
    }
    const dbPath = getVaultPath();
    const backupPath = nextVaultBackupPath(dbPath);
    const snapshot = new Database(dbPath, { readonly: true, fileMustExist: true });
    try {
      snapshot.prepare("VACUUM INTO ?").run(backupPath);
    } finally {
      snapshot.close();
    }
    enforceOwnerOnlyPath(backupPath, 0o600, "vault migration backup");
    _migrationBackupHookForTests?.(backupPath);
    if (_migrationFaultForTests === "after-backup") throw new Error("Injected migration interruption after backup.");
    const vaultId = expectedVaultId ?? crypto.randomBytes(16);
    options.markMigrationPending?.(vaultId);
    ensureSecretsSchema(db);
    const rows = db.prepare(`
      SELECT project, environment, name, encrypted_value, iv, auth_tag, created_at, updated_at
      FROM secrets ORDER BY project, environment, name
    `).all() as (NamedEncryptedVaultRow & { created_at: string; updated_at: string })[];

    db.exec("DROP TABLE IF EXISTS secrets_current_migrate");
    db.exec(createCurrentSecretsTableSql("secrets_current_migrate"));
    const insert = db.prepare(`
      INSERT INTO secrets_current_migrate
        (project, environment, name, record_id, record_kind, encrypted_value, iv, auth_tag, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    for (const row of rows) {
      const value = decrypt(row.encrypted_value, row.iv, row.auth_tag, key);
      const recordId = crypto.randomBytes(16);
      const encrypted = encryptRecord(value, key, {
        vaultId,
        recordId,
        project: row.project,
        environment: row.environment,
        name: row.name,
      });
      insert.run(
        row.project,
        row.environment,
        row.name,
        recordId,
        RECORD_KIND_SECRET,
        encrypted.encrypted,
        encrypted.iv,
        encrypted.authTag,
        row.created_at,
        row.updated_at,
      );
    }
    db.exec("DROP TABLE secrets");
    db.exec("ALTER TABLE secrets_current_migrate RENAME TO secrets");
    createVaultMetadata(db, key, vaultId);
    if (_migrationFaultForTests === "before-commit") throw new Error("Injected migration interruption before commit.");
    return vaultId;
  });

  const migrated = migrate.immediate();
  if (_migrationFaultForTests === "after-commit") throw new Error("Injected migration interruption after commit.");
  return migrated;
}

function createVaultMetadata(db: Database.Database, key: Buffer, vaultId: Buffer): void {
  db.exec(`
    CREATE TABLE vault_metadata (
      singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
      format_version INTEGER NOT NULL,
      vault_id BLOB NOT NULL CHECK(length(vault_id) = 16),
      key_check_iv BLOB NOT NULL CHECK(length(key_check_iv) = 12),
      key_check_tag BLOB NOT NULL CHECK(length(key_check_tag) = 16)
    )
  `);
  const keyCheck = createVaultKeyCheck(key, vaultId);
  db.prepare(`
    INSERT INTO vault_metadata (singleton, format_version, vault_id, key_check_iv, key_check_tag)
    VALUES (1, ?, ?, ?, ?)
  `).run(VAULT_FORMAT_VERSION, vaultId, keyCheck.iv, keyCheck.authTag);
  db.pragma(`user_version = ${VAULT_FORMAT_VERSION}`);
}

function validateDatabaseStateForKeyFile(db: Database.Database, parsed: ParsedKeyFile): void {
  const current = readCurrentVaultId(db);
  if (current) {
    if (parsed.format === 3) {
      throw new Error("Keyclasp key file is older than the current vault database. Restore both files from the same backup.");
    }
    if (!parsed.vaultId?.equals(current)) throw new Error(KEY_VAULT_MISMATCH_ERROR);
    return;
  }

  if (!tableExists(db, "secrets")) {
    throw new Error("Keyclasp vault database is empty or replaced. Restore vault.db and its matching .keyclasp.key from the same backup.");
  }
  const columns = secretsTableColumns(db);
  if (columns.includes("record_id") || columns.includes("record_kind")) {
    throw new Error("Keyclasp vault is partially migrated: record identity exists without format metadata. Restore a pre-migration backup.");
  }
  if (parsed.format === 4 && parsed.state === "active") {
    throw new Error("Keyclasp vault database is replaced or rolled back to a legacy format. Restore the matching current database.");
  }
}

export function getDb(): Database.Database {
  assertSupportedKeyFile();
  enforceOwnerOnlyVaultPermissions();
  const dbPath = getVaultPath();
  if (!_initializingVault && fs.existsSync(getKeyPath()) && !fs.existsSync(dbPath)) {
    if (_db && _dbPath === dbPath) closeDb();
    throw new Error(VAULT_DATABASE_MISSING_ERROR);
  }
  if (_db && _dbPath === dbPath) {
    assertCachedDatabaseStillCurrent();
    return _db!;
  }
  if (_db) closeDb();

  const identityBeforeOpen = readFileIdentity(dbPath);
  _db = _initializingVault
    ? new Database(dbPath)
    : new Database(dbPath, { fileMustExist: true });
  _dbPath = dbPath;
  const identityAfterOpen = readFileIdentity(dbPath);
  if (identityBeforeOpen && identityAfterOpen &&
      (identityBeforeOpen.device !== identityAfterOpen.device || identityBeforeOpen.inode !== identityAfterOpen.inode)) {
    closeDb();
    throw new Error(VAULT_DATABASE_REPLACED_ERROR);
  }
  _dbFileIdentity = identityAfterOpen;
  _db.pragma("busy_timeout = 5000");
  try {
    _db.pragma("journal_mode = WAL");
  } catch {
    // journal_mode change can fail with SQLITE_BUSY on Windows CI
    // when the DB file is newly created. This is non-fatal: the
    // vault is fully functional with the default journal mode.
  }
  if (!_initializingVault) {
    try {
      validateDatabaseStateForKeyFile(_db, readParsedKeyFile());
    } catch (err) {
      closeDb();
      throw err;
    }
  }
  enforceOwnerOnlyVaultPermissions();
  return _db;
}

export function storeSecret(project: string, environment: string, name: string, value: string): void {
  validateScopeName(project, "project");
  validateScopeName(environment, "environment");
  const key = getKey();
  const db = getDb();
  assertKeyUnlocksVault(key);
  const vaultId = ensureVaultFormatMatchesKey(db, key);
  const write = db.transaction(() => {
    const existing = db.prepare(
      "SELECT record_id FROM secrets WHERE project = ? AND environment = ? AND name = ?",
    ).get(project, environment, name) as { record_id: Buffer } | undefined;
    const recordId = existing?.record_id ?? crypto.randomBytes(16);
    const { encrypted, iv, authTag } = encryptRecord(value, key, {
      vaultId,
      recordId,
      project,
      environment,
      name,
    });
    db.prepare(`
      INSERT INTO secrets (project, environment, name, record_id, record_kind, encrypted_value, iv, auth_tag, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
      ON CONFLICT(project, environment, name) DO UPDATE SET
        encrypted_value = excluded.encrypted_value,
        iv = excluded.iv,
        auth_tag = excluded.auth_tag,
        updated_at = datetime('now')
    `).run(project, environment, name, recordId, RECORD_KIND_SECRET, encrypted, iv, authTag);
  });
  write.immediate();
  rememberKeyValidation();
}

export function resolveSecret(project: string, environment: string, name: string): string | null {
  if (REMOVED_INTERNAL_SECRET_NAMES.has(name)) return null;

  const key = getKey();
  const db = getDb();
  const vaultId = ensureVaultFormatMatchesKey(db, key);
  const row = db.prepare(
    "SELECT project, environment, name, record_id, record_kind, encrypted_value, iv, auth_tag FROM secrets WHERE project = ? AND environment = ? AND name = ?"
  ).get(project, environment, name) as
    | NamedEncryptedVaultRow
    | undefined;

  if (!row) return null;
  return decryptRecord(row, key, vaultId);
}

export function resolveSecretsForRun(
  project: string,
  environment: string,
  names: readonly string[],
): Map<string, string> {
  if (names.length === 0) return new Map();
  const uniqueNames = [...new Set(names)];
  const key = getKey();
  const db = getDb();
  assertKeyUnlocksVault(key);
  const vaultId = ensureVaultFormatMatchesKey(db, key);
  const placeholders = uniqueNames.map(() => "?").join(", ");
  const read = db.transaction(() => {
    const rows = db.prepare(`
      SELECT project, environment, name, record_id, record_kind, encrypted_value, iv, auth_tag
      FROM secrets
      WHERE project = ? AND environment = ? AND name IN (${placeholders})
    `).all(project, environment, ...uniqueNames) as NamedEncryptedVaultRow[];
    const rowsByName = new Map(rows.map((row) => [row.name, row]));
    for (const name of uniqueNames) {
      if (!rowsByName.has(name)) {
        throw new Error(`Secret "${name}" disappeared before it could be injected.`);
      }
    }
    return new Map(uniqueNames.map((name) => [name, decryptRecord(rowsByName.get(name)!, key, vaultId)]));
  });
  return read();
}

export function isNewProjectEnvironment(project: string, environment: string): boolean {
  const db = getDb();
  if (!tableExists(db, "secrets")) return true;
  if (!secretsTableColumns(db).includes("project")) {
    if (project !== "default" || environment !== "default") return true;
    return db.prepare("SELECT 1 FROM secrets LIMIT 1").get() === undefined;
  }
  const row = db.prepare("SELECT 1 FROM secrets WHERE project = ? AND environment = ? LIMIT 1").get(project, environment);
  return row === undefined;
}

export function projects(): string[] {
  const db = getDb();
  if (!tableExists(db, "secrets")) return [];
  if (!secretsTableColumns(db).includes("project")) {
    return db.prepare("SELECT 1 FROM secrets LIMIT 1").get() === undefined ? [] : ["default"];
  }
  const rows = db.prepare("SELECT DISTINCT project FROM secrets ORDER BY project").all() as { project: string }[];
  return rows.map((r) => r.project);
}

export function environments(): string[] {
  const db = getDb();
  if (!tableExists(db, "secrets")) return [];
  if (!secretsTableColumns(db).includes("project")) {
    return db.prepare("SELECT 1 FROM secrets LIMIT 1").get() === undefined ? [] : ["default"];
  }
  const rows = db.prepare("SELECT DISTINCT environment FROM secrets ORDER BY environment").all() as { environment: string }[];
  return rows.map((r) => r.environment);
}

export function listSecrets(project?: string, environment?: string): string[] | ScopedSecret[] {
  const db = getDb();
  if (!tableExists(db, "secrets")) return [];
  const scopedSchema = secretsTableColumns(db).includes("project");
  if (!scopedSchema && ((project !== undefined && project !== "default") ||
      (environment !== undefined && environment !== "default"))) return [];
  const conditions: string[] = ["name NOT LIKE '@_@_%' ESCAPE '@'"];
  const params: string[] = [];
  if (scopedSchema && project !== undefined) {
    conditions.push("project = ?");
    params.push(project);
  }
  if (scopedSchema && environment !== undefined) {
    conditions.push("environment = ?");
    params.push(environment);
  }

  const rows = db.prepare(
    `SELECT ${scopedSchema ? "project, environment" : "'default' AS project, 'default' AS environment"}, name FROM secrets WHERE ${conditions.join(" AND ")} ORDER BY project, environment, name`
  ).all(...params) as ScopedSecret[];
  const filtered = rows.filter((r) => !REMOVED_INTERNAL_SECRET_NAMES.has(r.name));

  if (project !== undefined && environment !== undefined) {
    return filtered.map((r) => r.name);
  }
  return filtered;
}

export function checkVaultDecryptability(): DecryptabilityCheck {
  const db = getDb();
  let vaultId: Buffer | null = null;
  let rows = [...iterateNamedEncryptedVaultRows(db)];
  const failures: DecryptabilityCheck["failures"] = [];
  let checked = 0;
  let key: Buffer;

  try {
    key = getKey();
    vaultId = ensureVaultFormatMatchesKey(db, key);
    rows = [...iterateNamedEncryptedVaultRows(db)];
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
      if (!vaultId) throw new Error("Vault format is unavailable.");
      decryptRecord(row, key, vaultId);
    } catch (err: any) {
      failures.push({ name: row.name, error: err?.message ?? "Unable to decrypt" });
    }
  }

  return { checked, failures };
}

function currentVaultForMutation(): { db: Database.Database; key: Buffer; vaultId: Buffer } {
  const key = getKey();
  const db = getDb();
  assertKeyUnlocksVault(key);
  return { db, key, vaultId: ensureVaultFormatMatchesKey(db, key) };
}

export function deleteSecret(project: string, environment: string, name: string): boolean {
  const { db } = currentVaultForMutation();
  const result = db.prepare("DELETE FROM secrets WHERE project = ? AND environment = ? AND name = ?").run(project, environment, name);
  return result.changes > 0;
}

export function deleteProject(project: string): { deleted: number } {
  validateScopeName(project, "project");
  const { db } = currentVaultForMutation();
  const result = db.prepare("DELETE FROM secrets WHERE project = ?").run(project);
  return { deleted: result.changes };
}

export function deleteEnvironmentInProject(project: string, environment: string): { deleted: number } {
  validateScopeName(project, "project");
  validateScopeName(environment, "environment");
  const { db } = currentVaultForMutation();
  const result = db.prepare("DELETE FROM secrets WHERE project = ? AND environment = ?").run(project, environment);
  return { deleted: result.changes };
}

export function deleteEnvironmentAcrossAllProjects(environment: string): { deleted: number } {
  validateScopeName(environment, "environment");
  const { db } = currentVaultForMutation();
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
  const { db } = currentVaultForMutation();
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
  const { db } = currentVaultForMutation();
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

type CurrentSecretRow = NamedEncryptedVaultRow;

function reencryptMovedRows(
  db: Database.Database,
  key: Buffer,
  vaultId: Buffer,
  rows: CurrentSecretRow[],
  target: (row: CurrentSecretRow) => { project: string; environment: string },
): number {
  const update = db.prepare(`
    UPDATE secrets SET
      project = ?, environment = ?, encrypted_value = ?, iv = ?, auth_tag = ?, updated_at = datetime('now')
    WHERE project = ? AND environment = ? AND name = ?
  `);
  for (const row of rows) {
    const value = decryptRecord(row, key, vaultId);
    const destination = target(row);
    const encrypted = encryptRecord(value, key, {
      vaultId,
      recordId: row.record_id!,
      project: destination.project,
      environment: destination.environment,
      name: row.name,
      recordKind: row.record_kind,
    });
    update.run(
      destination.project,
      destination.environment,
      encrypted.encrypted,
      encrypted.iv,
      encrypted.authTag,
      row.project,
      row.environment,
      row.name,
    );
  }
  return rows.length;
}

const CURRENT_SECRET_COLUMNS = "project, environment, name, record_id, record_kind, encrypted_value, iv, auth_tag";

export function renameProject(fromProject: string, toProject: string): { moved: number } {
  validateScopeName(fromProject, "project");
  validateScopeName(toProject, "project");
  const key = getKey();
  const db = getDb();
  const vaultId = ensureVaultFormatMatchesKey(db, key);
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
    const rows = db.prepare(`SELECT ${CURRENT_SECRET_COLUMNS} FROM secrets WHERE project = ? ORDER BY environment, name`)
      .all(fromProject) as CurrentSecretRow[];
    return reencryptMovedRows(db, key, vaultId, rows, (row) => ({ project: toProject, environment: row.environment }));
  });
  return { moved: tx.immediate() };
}

export function renameEnvironmentInProject(project: string, fromEnvironment: string, toEnvironment: string): { moved: number } {
  validateScopeName(project, "project");
  validateScopeName(fromEnvironment, "environment");
  validateScopeName(toEnvironment, "environment");
  const key = getKey();
  const db = getDb();
  const vaultId = ensureVaultFormatMatchesKey(db, key);
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
    const rows = db.prepare(`SELECT ${CURRENT_SECRET_COLUMNS} FROM secrets WHERE project = ? AND environment = ? ORDER BY name`)
      .all(project, fromEnvironment) as CurrentSecretRow[];
    return reencryptMovedRows(db, key, vaultId, rows, () => ({ project, environment: toEnvironment }));
  });
  return { moved: tx.immediate() };
}

export function renameEnvironmentAcrossAllProjects(fromEnvironment: string, toEnvironment: string): { moved: number; projectsAffected: number } {
  validateScopeName(fromEnvironment, "environment");
  validateScopeName(toEnvironment, "environment");
  const key = getKey();
  const db = getDb();
  const vaultId = ensureVaultFormatMatchesKey(db, key);
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
    const rows = db.prepare(`SELECT ${CURRENT_SECRET_COLUMNS} FROM secrets WHERE environment = ? ORDER BY project, name`)
      .all(fromEnvironment) as CurrentSecretRow[];
    const moved = reencryptMovedRows(db, key, vaultId, rows, (row) => ({ project: row.project, environment: toEnvironment }));
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
  const key = getKey();
  const db = getDb();
  const vaultId = ensureVaultFormatMatchesKey(db, key);
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
    const rows = db.prepare(`SELECT ${CURRENT_SECRET_COLUMNS} FROM secrets WHERE project = ? AND environment = ? ORDER BY name`)
      .all(fromProject, fromEnvironment) as CurrentSecretRow[];
    return reencryptMovedRows(db, key, vaultId, rows, () => ({ project: toProject, environment: toEnvironment }));
  });
  return { moved: tx.immediate() };
}

export function closeDb(): void {
  if (_db) {
    _db.close();
    _db = null;
    _dbPath = null;
    _dbFileIdentity = null;
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

export function setVaultMigrationFaultForTests(
  fault: "after-backup" | "before-commit" | "after-commit" | null,
): void {
  _migrationFaultForTests = fault;
}

export function setVaultMigrationBackupHookForTests(hook: ((backupPath: string) => void) | null): void {
  _migrationBackupHookForTests = hook;
}
