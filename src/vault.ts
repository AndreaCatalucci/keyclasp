import Database from "better-sqlite3";
import crypto from "node:crypto";
import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import { enforceOwnerOnlyPath } from "./owner-only-path.js";
import {
  create as createKeyBundle,
  createFromKeys,
  enrollInteractive,
  parse as parseKeyBundle,
  rewrapInteractive,
  serialize as serializeKeyBundle,
  unwrapInteractive,
  unwrapMachine,
  type KeyBundleDescriptor,
} from "./software/key-bundle.js";

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
const VAULT_FORMAT_VERSION = 3;
const LEGACY_VAULT_FORMAT_VERSION = 2;
const RECORD_KIND_SECRET = "secret";
const RECORD_AAD_MAGIC = Buffer.from("keyclasp:record-aad:v2\0", "utf8");
const LEGACY_RECORD_AAD_MAGIC = Buffer.from("keyclasp:record-aad:v1\0", "utf8");
const VAULT_KEY_CHECK_AAD = Buffer.from("keyclasp:vault-key-check:v1\0", "utf8");
const VAULT_CLASS_KEY_CHECK_AAD = Buffer.from("keyclasp:vault-class-key-check:v1\0", "utf8");
const KEY_BUNDLE_MAGIC = Buffer.from("keyclasp:v5\n", "utf8");

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

export type KeyClass = "machine" | "interactive";

type EncryptedVaultRow = { encrypted_value: Buffer; iv: Buffer; auth_tag: Buffer };
type NamedEncryptedVaultRow = EncryptedVaultRow & {
  project: string;
  environment: string;
  name: string;
  record_id?: Buffer;
  record_kind?: string;
  key_class?: KeyClass;
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
let _custodyFaultForTests: "after-journal" | "after-bundle" | "after-database" | null = null;
let _dualMigrationFaultForTests: "after-backup" | "after-journal" | "after-bundle" | "after-database" | null = null;
let _keyAccessCountsForTests = { interactiveUnwraps: 0, interactiveDecrypts: 0 };
let _initializingVault = false;
let _vaultHomeCache: { signature: string; path: string } | null = null;
let _keyPathCache: { vaultDir: string; path: string } | null = null;

function getVaultDir(): string {
  return resolveVaultHome();
}

function enforceOwnerOnlyVaultPermissions(): void {
  const vaultDir = getVaultDir();
  if (!fs.existsSync(vaultDir)) return;
  enforceOwnerOnlyPath(vaultDir, { kind: "directory", label: "vault directory" });
  for (const entry of fs.readdirSync(vaultDir)) {
    if (entry === ".initialize.db" || entry.startsWith(".initialize.db-") ||
        entry === ".keyclasp.key" || entry.startsWith(".keyclasp.key.") ||
        entry === "vault.db" || entry.startsWith("vault.db-" ) || entry.startsWith("vault.db.")) {
      const entryPath = path.join(vaultDir, entry);
      try {
        enforceOwnerOnlyPath(entryPath, { kind: "file", label: `vault file "${entry}"` });
      } catch (err: any) {
        if (err?.code === "ENOENT" || !fs.existsSync(entryPath)) continue;
        throw err;
      }
    }
  }
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

export function ensureOwnerOnlyVaultDirectory(): void {
  const vaultDir = getVaultDir();
  if (!fs.existsSync(vaultDir)) fs.mkdirSync(vaultDir, { recursive: true, mode: 0o700 });
  enforceOwnerOnlyPath(vaultDir, { kind: "directory", label: "vault directory" });
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

export interface VaultDescriptor {
  mode: KeyFileMode;
  vaultId: Buffer;
  custody: "machine-only" | "dual-key";
  generation: number;
}

export class VaultSemanticDamageError extends Error {}

function assertRestoreValidationColumns(
  database: Database.Database,
  table: "vault_metadata" | "secrets",
  required: readonly string[],
): void {
  const columns = new Set(
    (database.pragma(`table_info(${table})`) as { name: string }[]).map((column) => column.name),
  );
  const missing = required.filter((column) => !columns.has(column));
  if (missing.length > 0) {
    throw new VaultSemanticDamageError(
      `Keyclasp live vault schema is missing ${table} column${missing.length === 1 ? "" : "s"}: ${missing.join(", ")}.`,
    );
  }
}

function isOperationalVaultValidationError(error: unknown): boolean {
  if (typeof error === "object" && error !== null && "code" in error) {
    const code = String((error as { code?: unknown }).code ?? "");
    if (/SQLITE_(?:CORRUPT|NOTADB|FORMAT)/.test(code)) return false;
    if (code) return true;
  }
  return error instanceof Error && /Unsafe |owner-only|permission|ACL|changed during/.test(error.message);
}

export function getVaultDescriptor(): VaultDescriptor {
  enforceOwnerOnlyVaultPermissions();
  const encoded = fs.readFileSync(getKeyPath());
  if (encoded.subarray(0, KEY_BUNDLE_MAGIC.length).equals(KEY_BUNDLE_MAGIC)) {
    const bundle = parseKeyBundle(encoded);
    return {
      mode: bundle.interactive ? "passphrase" : "machine",
      vaultId: Buffer.from(bundle.vaultId),
      custody: bundle.interactive ? "dual-key" : "machine-only",
      generation: bundle.generation,
    };
  }
  const parsed = readParsedKeyFile();
  if (parsed.format !== 4 || !parsed.vaultId || parsed.state !== "active") {
    throw new Error("Keyclasp vault must complete its storage upgrade before policy operations are available.");
  }
  return {
    mode: parsed.mode,
    vaultId: Buffer.from(parsed.vaultId),
    custody: parsed.mode === "passphrase" ? "dual-key" : "machine-only",
    generation: 0,
  };
}

/** Validate live key/database semantics for emergency-restore classification.
 * Filesystem, SQLite, permission, and identity failures remain operational
 * failures; format, schema, identity, and cryptographic mismatches are damage. */
export function validateLiveVaultSemanticsForRestore(
  databasePath = getVaultPath(),
  keyPath = getKeyPath(),
): void {
  try {
    const encoded = fs.readFileSync(keyPath);
    const database = new Database(databasePath, { readonly: true, fileMustExist: true });
    try {
      if (encoded.subarray(0, KEY_BUNDLE_MAGIC.length).equals(KEY_BUNDLE_MAGIC)) {
        const bundle = parseKeyBundle(encoded);
        assertRestoreValidationColumns(database, "vault_metadata", [
          "singleton", "format_version", "vault_id", "bundle_generation", "bundle_hash",
          "machine_key_check_iv", "machine_key_check_tag", "interactive_key_check_iv",
          "interactive_key_check_tag", "interactive_key_present",
        ]);
        assertRestoreValidationColumns(database, "secrets", [
          "project", "environment", "name", "record_id", "record_kind", "key_class",
          "encrypted_value", "iv", "auth_tag", "created_at", "updated_at",
        ]);
        validateBundleAgainstDatabase(database, bundle);
      } else {
        const parsed = parseKeyFile(encoded);
        if (tableExists(database, "vault_metadata")) {
          assertRestoreValidationColumns(database, "vault_metadata", [
            "singleton", "format_version", "vault_id", "key_check_iv", "key_check_tag",
          ]);
        }
        validateDatabaseStateForKeyFile(database, parsed);
      }
    } finally {
      database.close();
    }
  } catch (error) {
    if (isOperationalVaultValidationError(error)) throw error;
    throw new VaultSemanticDamageError(error instanceof Error ? error.message : "Live vault semantic validation failed.");
  }
}

function readActiveKeyBundle(filePath = getKeyPath()): KeyBundleDescriptor {
  const bundle = parseKeyBundle(fs.readFileSync(filePath));
  if (bundle.state !== "active") throw new Error("Keyclasp key bundle is not active.");
  return bundle;
}

function writeActiveKeyBundle(bundle: KeyBundleDescriptor, filePath = getKeyPath(), backup = true): void {
  const temporaryPath = `${filePath}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  fs.writeFileSync(temporaryPath, serializeKeyBundle(bundle), { mode: 0o600 });
  const descriptor = fs.openSync(temporaryPath, "r");
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
  if (backup) backupExistingKeyFile(filePath);
  fs.renameSync(temporaryPath, filePath);
  enforceOwnerOnlyPath(filePath, { kind: "file", label: "vault key bundle" });
  const directory = fs.openSync(path.dirname(filePath), "r");
  try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
}

function keyBundleHash(bundle: KeyBundleDescriptor): Buffer {
  return crypto.createHash("sha256").update(serializeKeyBundle(bundle)).digest();
}

export interface ManagedBackupKeys {
  bundle: KeyBundleDescriptor;
  machineKey?: Buffer;
  interactiveKey?: Buffer;
}

export function unlockManagedBackupKeys(keyPath: string, databasePath: string, passphrase?: string): ManagedBackupKeys {
  const bundle = parseKeyBundle(fs.readFileSync(keyPath));
  const database = new Database(databasePath, { readonly: true, fileMustExist: true });
  try {
    validateBundleAgainstDatabase(database, bundle);
    let machineKey: Buffer | undefined;
    for (const identity of deriveStableMachineIdentities()) {
      try {
        const candidate = unwrapMachine(bundle, identity);
        verifyClassKeyCheck(database, candidate, bundle.vaultId, "machine");
        machineKey = candidate;
        break;
      } catch {
        // Copied-machine restores may still be eligible when every record is interactive.
      }
    }
    let interactiveKey: Buffer | undefined;
    if (passphrase !== undefined && bundle.interactive) {
      try {
        const candidate = unwrapInteractive(bundle, passphrase);
        verifyClassKeyCheck(database, candidate, bundle.vaultId, "interactive");
        interactiveKey = candidate;
      } catch {
        throw new Error("Managed backup passphrase is incorrect or its interactive key does not match the database.");
      }
    }
    return { bundle, ...(machineKey ? { machineKey } : {}), ...(interactiveKey ? { interactiveKey } : {}) };
  } finally {
    database.close();
  }
}

export function getManagedBackupKeys(required: readonly KeyClass[] = ["machine", "interactive"]): ManagedBackupKeys & { bundle: KeyBundleDescriptor } {
  const bundle = readActiveKeyBundle();
  const db = getDb();
  validateBundleAgainstDatabase(db, bundle);
  const machineKey = required.includes("machine") ? getKey() : undefined;
  const interactiveKey = required.includes("interactive") && bundle.interactive
    ? keyForClass("interactive", db, bundle)
    : undefined;
  return { bundle, ...(machineKey ? { machineKey } : {}), ...(interactiveKey ? { interactiveKey } : {}) };
}

/** Validate every stored record against its authenticated identity and key class. */
export function validateManagedVaultContents(
  databasePath: string,
  keyPath: string,
  keys: Pick<ManagedBackupKeys, "machineKey" | "interactiveKey">,
): void {
  const bundle = readActiveKeyBundle(keyPath);
  const database = new Database(databasePath, { readonly: true, fileMustExist: true });
  try {
    validateBundleAgainstDatabase(database, bundle);
    if (keys.machineKey) verifyClassKeyCheck(database, keys.machineKey, bundle.vaultId, "machine");
    if (keys.interactiveKey) verifyClassKeyCheck(database, keys.interactiveKey, bundle.vaultId, "interactive");
    const rows = database.prepare(`SELECT ${currentSecretColumns(database)} FROM secrets ORDER BY project, environment, name`)
      .all() as CurrentSecretRow[];
    for (const row of rows) {
      if (row.key_class !== "machine" && row.key_class !== "interactive") {
        throw new Error("Managed backup contains a record with an invalid key class.");
      }
      const key = row.key_class === "machine" ? keys.machineKey : keys.interactiveKey;
      if (!key) throw new Error(`Managed backup requires the ${row.key_class} data key to authenticate its records.`);
      authenticateRecord(row, key, bundle.vaultId);
    }
  } finally {
    database.close();
  }
}

export function preparePortableInteractiveRestore(
  keyPath: string,
  databasePath: string,
  passphrase: string,
  afterDatabaseWriteForTests?: () => void,
): void {
  const keys = unlockManagedBackupKeys(keyPath, databasePath, passphrase);
  if (!keys.interactiveKey) throw new Error("All-interactive portable restore requires the backup passphrase.");
  const inventory = summarizeKeyClasses(databasePath);
  if (inventory.machine !== 0) throw new Error("A backup containing machine-key records cannot be restored on another machine.");
  if (keys.machineKey) return;
  const machineKey = crypto.randomBytes(KEY_LENGTH);
  const next = createFromKeys({
    vaultId: keys.bundle.vaultId,
    generation: keys.bundle.generation + 1,
    machineIdentity: deriveStableMachineIdentity(),
    machineKey,
    interactiveKey: keys.interactiveKey,
    interactivePassphrase: passphrase,
  });
  const database = new Database(databasePath, { fileMustExist: true });
  try {
    const update = database.transaction(() => {
      const machineCheck = createClassKeyCheck(machineKey, next.vaultId, "machine");
      database.prepare(`UPDATE vault_metadata SET bundle_generation = ?, bundle_hash = ?,
        machine_key_check_iv = ?, machine_key_check_tag = ? WHERE singleton = 1`)
        .run(next.generation, keyBundleHash(next), machineCheck.iv, machineCheck.authTag);
      afterDatabaseWriteForTests?.();
    });
    update.immediate();
  } finally {
    database.close();
  }
  writeActiveKeyBundle(next, keyPath, false);
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
  enforceOwnerOnlyPath(keyPath, { kind: "file", label: "vault key file" });
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
  enforceOwnerOnlyPath(backupPath, { kind: "file", label: "vault key backup" });
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
  const encoded = fs.readFileSync(keyPath);
  if (encoded.subarray(0, KEY_BUNDLE_MAGIC.length).equals(KEY_BUNDLE_MAGIC)) parseKeyBundle(encoded);
  else parseKeyFile(encoded);
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
  keyClass?: KeyClass;
  formatVersion?: number;
}): Buffer {
  const formatVersion = identity.formatVersion ?? VAULT_FORMAT_VERSION;
  const version = Buffer.alloc(4);
  version.writeUInt32BE(formatVersion);
  return Buffer.concat([
    formatVersion === LEGACY_VAULT_FORMAT_VERSION ? LEGACY_RECORD_AAD_MAGIC : RECORD_AAD_MAGIC,
    version,
    canonicalField(identity.vaultId),
    canonicalField(identity.recordId),
    canonicalField(identity.project),
    canonicalField(identity.environment),
    canonicalField(identity.name),
    canonicalField(identity.recordKind ?? RECORD_KIND_SECRET),
    ...(formatVersion === LEGACY_VAULT_FORMAT_VERSION ? [] : [canonicalField(identity.keyClass ?? "machine")]),
  ]);
}

function encryptRecord(value: string, key: Buffer, identity: Parameters<typeof buildRecordAssociatedData>[0]): ReturnType<typeof encrypt> {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  cipher.setAAD(buildRecordAssociatedData(identity));
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return { encrypted, iv, authTag: cipher.getAuthTag() };
}

function decryptRecord(
  row: NamedEncryptedVaultRow,
  key: Buffer,
  vaultId: Buffer,
  formatVersion = VAULT_FORMAT_VERSION,
): string {
  if (!row.record_id || row.record_id.length !== 16 || row.record_kind !== RECORD_KIND_SECRET) {
    throw new Error("Keyclasp vault record identity is missing or invalid.");
  }
  if (row.key_class === "interactive") _keyAccessCountsForTests.interactiveDecrypts += 1;
  const decipher = crypto.createDecipheriv(ALGORITHM, key, row.iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAAD(buildRecordAssociatedData({
    vaultId,
    recordId: row.record_id,
    project: row.project,
    environment: row.environment,
    name: row.name,
    recordKind: row.record_kind,
    keyClass: row.key_class ?? "machine",
    formatVersion,
  }));
  decipher.setAuthTag(row.auth_tag);
  return Buffer.concat([decipher.update(row.encrypted_value), decipher.final()]).toString("utf8");
}

function authenticateRecord(row: NamedEncryptedVaultRow, key: Buffer, vaultId: Buffer): void {
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
    keyClass: row.key_class ?? "machine",
  }));
  decipher.setAuthTag(row.auth_tag);
  const plaintext = Buffer.concat([decipher.update(row.encrypted_value), decipher.final()]);
  plaintext.fill(0);
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

function createClassKeyCheck(key: Buffer, vaultId: Buffer, keyClass: KeyClass): { iv: Buffer; authTag: Buffer } {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  cipher.setAAD(Buffer.concat([VAULT_CLASS_KEY_CHECK_AAD, vaultId, Buffer.from(keyClass, "utf8")]));
  cipher.final();
  return { iv, authTag: cipher.getAuthTag() };
}

function verifyClassKeyCheck(db: Database.Database, key: Buffer, vaultId: Buffer, keyClass: KeyClass): void {
  const prefix = keyClass === "machine" ? "machine" : "interactive";
  const row = db.prepare(`SELECT ${prefix}_key_check_iv AS iv, ${prefix}_key_check_tag AS tag FROM vault_metadata WHERE singleton = 1`).get() as
    | { iv: Buffer | null; tag: Buffer | null }
    | undefined;
  if (!row || !Buffer.isBuffer(row.iv) || row.iv.length !== IV_LENGTH ||
      !Buffer.isBuffer(row.tag) || row.tag.length !== AUTH_TAG_LENGTH) {
    throw new Error(`Keyclasp ${keyClass} key-check metadata is missing or corrupt.`);
  }
  const decipher = crypto.createDecipheriv(ALGORITHM, key, row.iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAAD(Buffer.concat([VAULT_CLASS_KEY_CHECK_AAD, vaultId, Buffer.from(keyClass, "utf8")]));
  decipher.setAuthTag(row.tag);
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
let _interactiveKey: Buffer | null = null;
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

  const encoded = fs.readFileSync(keyPath);
  if (encoded.subarray(0, KEY_BUNDLE_MAGIC.length).equals(KEY_BUNDLE_MAGIC)) {
    const bundle = parseKeyBundle(encoded);
    let loaded: Buffer | null = null;
    for (const identity of deriveStableMachineIdentities()) {
      try {
        loaded = unwrapMachine(bundle, identity);
        break;
      } catch {
        // Try the next stable identity candidate.
      }
    }
    if (!loaded) throw new Error(KEY_VAULT_MISMATCH_ERROR);
    const db = getDb();
    validateBundleAgainstDatabase(db, bundle);
    verifyClassKeyCheck(db, loaded, bundle.vaultId, "machine");
    cacheLoadedKey(loaded, keyPath);
    rememberKeyValidation();
    return loaded;
  }
  const parsed = parseKeyFile(encoded);
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
  const encoded = fs.readFileSync(getKeyPath());
  if (encoded.subarray(0, KEY_BUNDLE_MAGIC.length).equals(KEY_BUNDLE_MAGIC)) {
    const bundle = parseKeyBundle(encoded);
    if (!bundle.interactive) throw new Error("This vault has no interactive passphrase. Run: keyclasp passphrase set");
    let key: Buffer;
    try {
      key = unwrapInteractive(bundle, passphrase);
    } catch {
      throw new Error("Vault passphrase is incorrect.");
    }
    _keyAccessCountsForTests.interactiveUnwraps += 1;
    const db = getDb();
    validateBundleAgainstDatabase(db, bundle);
    verifyClassKeyCheck(db, key, bundle.vaultId, "interactive");
    _interactiveKey = key;
    return;
  }
  const parsed = parseKeyFile(encoded);
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
  enforceOwnerOnlyPath(lockPath, { kind: "file", label: "vault initialization lock" });
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

    const vaultId = crypto.randomBytes(16);
    const created = createKeyBundle({
      vaultId,
      generation: 1,
      machineIdentity: deriveStableMachineIdentity(),
      ...(passphrase ? { interactivePassphrase: passphrase } : {}),
    });
    writeActiveKeyBundle(created.bundle, getKeyPath(), false);

    closeDb();
    let db: Database.Database;
    _initializingVault = true;
    try {
      db = getDb();
      createDualKeyVault(db, created.bundle, created.machineKey, created.interactiveKey);
    } finally {
      _initializingVault = false;
    }
    cacheLoadedKey(created.machineKey, getKeyPath());
    _interactiveKey = created.interactiveKey ?? null;
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

export function authorizeAndUnlockVaultPassphrase(passphrase: string): boolean {
  const encoded = fs.readFileSync(getKeyPath());
  if (encoded.subarray(0, KEY_BUNDLE_MAGIC.length).equals(KEY_BUNDLE_MAGIC)) {
    if (!parseKeyBundle(encoded).interactive) return passphrase === "";
    if (!passphrase) return false;
    try {
      unlockVault(passphrase);
      return true;
    } catch {
      return false;
    }
  }
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
  const encoded = fs.readFileSync(getKeyPath());
  if (encoded.subarray(0, KEY_BUNDLE_MAGIC.length).equals(KEY_BUNDLE_MAGIC)) return Boolean(parseKeyBundle(encoded).interactive);
  return parseKeyFile(encoded).mode === "passphrase";
}

export function isInteractiveKeyUnlocked(): boolean {
  if (!vaultHasPassphrase()) return false;
  return _interactiveKey !== null;
}

const CUSTODY_JOURNAL_FILE = ".custody-transaction.v1.json";
interface CustodyJournal {
  version: 1;
  previousBundle: string;
  nextBundle: string;
  previousGeneration: number;
  nextGeneration: number;
  mac: string;
}

function custodyJournalPath(): string {
  return path.join(getVaultDir(), CUSTODY_JOURNAL_FILE);
}

function custodyJournalPayload(journal: Omit<CustodyJournal, "mac">): string {
  return JSON.stringify(journal);
}

function custodyJournalMac(payload: Omit<CustodyJournal, "mac">, machineKey: Buffer): string {
  return crypto.createHmac("sha256", machineKey)
    .update("keyclasp:custody-transaction:v1\0")
    .update(custodyJournalPayload(payload))
    .digest("base64");
}

function writeCustodyJournal(payload: Omit<CustodyJournal, "mac">, machineKey: Buffer): void {
  const filePath = custodyJournalPath();
  const temporaryPath = `${filePath}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  fs.writeFileSync(temporaryPath, `${JSON.stringify({ ...payload, mac: custodyJournalMac(payload, machineKey) })}\n`, { mode: 0o600 });
  const file = fs.openSync(temporaryPath, "r");
  try { fs.fsyncSync(file); } finally { fs.closeSync(file); }
  fs.renameSync(temporaryPath, filePath);
  enforceOwnerOnlyPath(filePath, { kind: "file", label: "custody transaction journal" });
  const directory = fs.openSync(getVaultDir(), "r");
  try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
}

function readDatabaseBundleGeneration(databasePath = getVaultPath()): number {
  const database = new Database(databasePath, { readonly: true, fileMustExist: true });
  try {
    const row = database.prepare("SELECT bundle_generation FROM vault_metadata WHERE singleton = 1").get() as { bundle_generation: number } | undefined;
    if (!row || !Number.isSafeInteger(row.bundle_generation)) throw new Error("Keyclasp vault bundle generation is missing.");
    return row.bundle_generation;
  } finally {
    database.close();
  }
}

export function recoverInterruptedCustodyTransition(): boolean {
  const journalPath = custodyJournalPath();
  if (!fs.existsSync(journalPath)) return false;
  enforceOwnerOnlyPath(journalPath, { kind: "file", label: "custody transaction journal" });
  let journal: CustodyJournal;
  try { journal = JSON.parse(fs.readFileSync(journalPath, "utf8")) as CustodyJournal; }
  catch { throw new Error("Keyclasp custody transaction journal is corrupt. Restore a managed backup."); }
  if (journal.version !== 1 || !Number.isSafeInteger(journal.previousGeneration) || !Number.isSafeInteger(journal.nextGeneration) ||
      journal.nextGeneration !== journal.previousGeneration + 1) {
    throw new Error("Keyclasp custody transaction journal is invalid. Restore a managed backup.");
  }
  const previousEncoded = Buffer.from(journal.previousBundle, "base64");
  const nextEncoded = Buffer.from(journal.nextBundle, "base64");
  const previous = parseKeyBundle(previousEncoded);
  const next = parseKeyBundle(nextEncoded);
  if (previous.generation !== journal.previousGeneration || next.generation !== journal.nextGeneration ||
      !previous.vaultId.equals(next.vaultId)) {
    throw new Error("Keyclasp custody transaction journal does not bind one vault generation.");
  }
  let machineKey: Buffer | null = null;
  for (const identity of deriveStableMachineIdentities()) {
    try { machineKey = unwrapMachine(previous, identity); break; } catch { /* try next */ }
  }
  if (!machineKey) throw new Error("Keyclasp custody transaction cannot authenticate on this machine.");
  const { mac, ...payload } = journal;
  const expected = Buffer.from(custodyJournalMac(payload, machineKey), "base64");
  const actual = Buffer.from(mac ?? "", "base64");
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
    throw new Error("Keyclasp custody transaction failed authentication.");
  }
  const databaseGeneration = readDatabaseBundleGeneration();
  if (databaseGeneration === previous.generation) writeActiveKeyBundle(previous, getKeyPath(), false);
  else if (databaseGeneration === next.generation) writeActiveKeyBundle(next, getKeyPath(), false);
  else throw new Error("Keyclasp custody transaction does not match the database commit point.");
  fs.unlinkSync(journalPath);
  const directory = fs.openSync(getVaultDir(), "r");
  try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
  clearKey();
  return true;
}

export function hasInterruptedCustodyTransition(): boolean {
  return fs.existsSync(custodyJournalPath());
}

function commitKeyBundleTransition(
  previous: KeyBundleDescriptor,
  next: KeyBundleDescriptor,
  machineKey: Buffer,
  interactiveKey: Buffer,
): void {
  const previousEncoded = serializeKeyBundle(previous);
  const nextEncoded = serializeKeyBundle(next);
  const payload: Omit<CustodyJournal, "mac"> = {
    version: 1,
    previousBundle: previousEncoded.toString("base64"),
    nextBundle: nextEncoded.toString("base64"),
    previousGeneration: previous.generation,
    nextGeneration: next.generation,
  };
  writeCustodyJournal(payload, machineKey);
  if (_custodyFaultForTests === "after-journal") throw new Error("Injected custody crash after journal publication.");
  writeActiveKeyBundle(next, getKeyPath(), false);
  if (_custodyFaultForTests === "after-bundle") throw new Error("Injected custody crash after bundle publication.");
  closeDb();
  const database = new Database(getVaultPath(), { fileMustExist: true });
  try {
    database.pragma("synchronous = FULL");
    const update = database.transaction(() => {
      const interactiveCheck = createClassKeyCheck(interactiveKey, next.vaultId, "interactive");
      database.prepare(`
        UPDATE vault_metadata SET bundle_generation = ?, bundle_hash = ?, interactive_key_check_iv = ?,
          interactive_key_check_tag = ?, interactive_key_present = 1 WHERE singleton = 1
      `).run(next.generation, keyBundleHash(next), interactiveCheck.iv, interactiveCheck.authTag);
    });
    update.immediate();
  } catch (error) {
    if (_custodyFaultForTests !== null) throw error;
    recoverInterruptedCustodyTransition();
    throw error;
  } finally {
    database.close();
  }
  if (_custodyFaultForTests === "after-database") throw new Error("Injected custody crash after database commit.");
  fs.unlinkSync(custodyJournalPath());
  const directory = fs.openSync(getVaultDir(), "r");
  try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
  clearKey();
  cacheLoadedKey(machineKey, getKeyPath());
  _interactiveKey = interactiveKey;
  rememberKeyValidation();
}

export function enrollInteractivePassphrase(newPassphrase: string): void {
  if (!newPassphrase) throw new Error("Interactive passphrase must be non-empty.");
  const previous = readActiveKeyBundle();
  if (previous.interactive) throw new Error("Interactive passphrase is already set. Use passphrase rotate.");
  const machineKey = getKey();
  const enrolled = enrollInteractive(previous, {
    newPassphrase,
    machineIdentity: deriveStableMachineIdentity(),
    machineKey,
  });
  commitKeyBundleTransition(previous, enrolled.bundle, machineKey, enrolled.interactiveKey);
}

export function rotateInteractivePassphrase(currentPassphrase: string, newPassphrase: string): void {
  if (!currentPassphrase || !newPassphrase) throw new Error("Current and new interactive passphrases must be non-empty.");
  const previous = readActiveKeyBundle();
  if (!previous.interactive) throw new Error("Interactive passphrase is not set. Use passphrase set.");
  const machineKey = getKey();
  const rotated = rewrapInteractive(previous, {
    currentPassphrase,
    newPassphrase,
    machineIdentity: deriveStableMachineIdentity(),
    machineKey,
  });
  verifyClassKeyCheck(getDb(), rotated.interactiveKey, previous.vaultId, "interactive");
  commitKeyBundleTransition(previous, rotated.bundle, machineKey, rotated.interactiveKey);
}

export function setCustodyFaultForTests(fault: "after-journal" | "after-bundle" | "after-database" | null): void {
  _custodyFaultForTests = fault;
}

export function resetKeyAccessCountsForTests(): void {
  _keyAccessCountsForTests = { interactiveUnwraps: 0, interactiveDecrypts: 0 };
}

export function readKeyAccessCountsForTests(): Readonly<typeof _keyAccessCountsForTests> {
  return { ..._keyAccessCountsForTests };
}

export function needsDualKeyMigration(): boolean {
  if (!fs.existsSync(getKeyPath())) return false;
  const encoded = fs.readFileSync(getKeyPath());
  return !encoded.subarray(0, KEY_BUNDLE_MAGIC.length).equals(KEY_BUNDLE_MAGIC);
}

const DUAL_MIGRATION_JOURNAL = ".dual-key-migration.v1.json";
const DUAL_MIGRATION_JOURNAL_KEY = ".dual-key-migration.key";
interface DualMigrationJournal {
  version: 1;
  previousKeyFile: string;
  nextBundle: string;
  databaseBackup: string;
  databaseBackupHash: string;
  vaultId: string;
  mac: string;
}

function dualMigrationJournalKey(): Buffer {
  const filePath = path.join(getVaultDir(), DUAL_MIGRATION_JOURNAL_KEY);
  if (!fs.existsSync(filePath)) fs.writeFileSync(filePath, crypto.randomBytes(32), { mode: 0o600, flag: "wx" });
  enforceOwnerOnlyPath(filePath, { kind: "file", label: "dual-key migration journal key" });
  const key = fs.readFileSync(filePath);
  if (key.length !== 32) throw new Error("Dual-key migration journal key is corrupt.");
  return key;
}

function dualMigrationPayload(journal: Omit<DualMigrationJournal, "mac">): string {
  return JSON.stringify(journal);
}

function dualMigrationMac(payload: Omit<DualMigrationJournal, "mac">): string {
  return crypto.createHmac("sha256", dualMigrationJournalKey())
    .update("keyclasp:dual-key-migration:v1\0")
    .update(dualMigrationPayload(payload))
    .digest("base64");
}

function writeDualMigrationJournal(payload: Omit<DualMigrationJournal, "mac">): void {
  const filePath = path.join(getVaultDir(), DUAL_MIGRATION_JOURNAL);
  const temporaryPath = `${filePath}.${process.pid}.tmp`;
  fs.writeFileSync(temporaryPath, `${JSON.stringify({ ...payload, mac: dualMigrationMac(payload) })}\n`, { mode: 0o600 });
  const file = fs.openSync(temporaryPath, "r");
  try { fs.fsyncSync(file); } finally { fs.closeSync(file); }
  fs.renameSync(temporaryPath, filePath);
  const directory = fs.openSync(getVaultDir(), "r");
  try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
}

function publishRawKeyFile(encoded: Buffer): void {
  const temporaryPath = `${getKeyPath()}.${process.pid}.${crypto.randomBytes(4).toString("hex")}.tmp`;
  fs.writeFileSync(temporaryPath, encoded, { mode: 0o600 });
  const file = fs.openSync(temporaryPath, "r");
  try { fs.fsyncSync(file); } finally { fs.closeSync(file); }
  fs.renameSync(temporaryPath, getKeyPath());
  enforceOwnerOnlyPath(getKeyPath(), { kind: "file", label: "vault key file" });
}

export function hasInterruptedDualKeyMigration(): boolean {
  return fs.existsSync(path.join(getVaultDir(), DUAL_MIGRATION_JOURNAL));
}

export function recoverInterruptedDualKeyMigration(): boolean {
  const journalPath = path.join(getVaultDir(), DUAL_MIGRATION_JOURNAL);
  if (!fs.existsSync(journalPath)) return false;
  enforceOwnerOnlyPath(journalPath, { kind: "file", label: "dual-key migration journal" });
  const journal = JSON.parse(fs.readFileSync(journalPath, "utf8")) as DualMigrationJournal;
  const { mac, ...payload } = journal;
  const expected = Buffer.from(dualMigrationMac(payload), "base64");
  const actual = Buffer.from(mac ?? "", "base64");
  if (journal.version !== 1 || actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
    throw new Error("Dual-key migration journal failed authentication.");
  }
  const backupPath = path.join(getVaultDir(), journal.databaseBackup);
  if (path.basename(backupPath) !== journal.databaseBackup ||
      crypto.createHash("sha256").update(fs.readFileSync(backupPath)).digest("hex") !== journal.databaseBackupHash) {
    throw new Error("Dual-key migration backup failed authentication.");
  }
  const database = new Database(getVaultPath(), { readonly: true, fileMustExist: true });
  let formatVersion: number;
  try {
    const row = database.prepare("SELECT format_version FROM vault_metadata WHERE singleton = 1").get() as { format_version: number } | undefined;
    formatVersion = row?.format_version ?? 0;
  } finally { database.close(); }
  if (formatVersion === LEGACY_VAULT_FORMAT_VERSION) publishRawKeyFile(Buffer.from(journal.previousKeyFile, "base64"));
  else if (formatVersion === VAULT_FORMAT_VERSION) publishRawKeyFile(Buffer.from(journal.nextBundle, "base64"));
  else throw new Error("Dual-key migration journal does not match the vault database format.");
  fs.unlinkSync(journalPath);
  const directory = fs.openSync(getVaultDir(), "r");
  try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
  clearKey();
  return true;
}

export function inspectLegacyVaultMode(): KeyFileMode | null {
  if (!needsDualKeyMigration()) return null;
  return parseKeyFile(fs.readFileSync(getKeyPath())).mode;
}

export function migrateLegacyVaultToDualKey(
  evaluate: (project: string, environment: string, secret?: string) => "locked" | "unlocked",
  options: { currentPassphrase?: string; newInteractivePassphrase?: string } = {},
): void {
  if (!needsDualKeyMigration()) return;
  enforceOwnerOnlyVaultPermissions();
  const previousEncoded = fs.readFileSync(getKeyPath());
  const parsed = parseKeyFile(previousEncoded);
  if (parsed.format === 3) {
    if (parsed.mode === "passphrase") {
      if (!options.currentPassphrase) throw new Error(KEY_LOCKED_ERROR);
      unlockVault(options.currentPassphrase);
    } else {
      getKey();
    }
    return migrateLegacyVaultToDualKey(evaluate, options);
  }
  if (parsed.format !== 4 || parsed.state !== "active" || !parsed.vaultId) {
    throw new Error("Complete the existing storage migration before upgrading to dual-key custody.");
  }
  let previousKey: Buffer;
  if (parsed.mode === "passphrase") {
    if (!options.currentPassphrase) throw new Error(KEY_LOCKED_ERROR);
    try { previousKey = unwrapDek(parsed, deriveKey(parsed.salt, options.currentPassphrase)); }
    catch { throw new Error("Vault passphrase is incorrect."); }
  } else {
    previousKey = unwrapWithAnyStableIdentity(parsed);
  }
  assertKeyUnlocksVault(previousKey, parsed.vaultId);
  closeDb();
  const database = new Database(getVaultPath(), { fileMustExist: true });
  database.pragma("busy_timeout = 5000");
  const rows = database.prepare(`SELECT project, environment, name, record_id, record_kind, encrypted_value, iv, auth_tag FROM secrets ORDER BY project, environment, name`)
    .all() as CurrentSecretRow[];
  const lockedRows = rows.filter((row) => evaluate(row.project, row.environment, row.name) === "locked");
  const interactivePassphrase = parsed.mode === "passphrase"
    ? options.currentPassphrase
    : lockedRows.length > 0 ? options.newInteractivePassphrase : undefined;
  if (lockedRows.length > 0 && !interactivePassphrase) {
    database.close();
    throw new Error("Locked records require interactive passphrase enrollment before migration.");
  }
  const machineKey = parsed.mode === "machine" ? previousKey : crypto.randomBytes(KEY_LENGTH);
  const interactiveKey = parsed.mode === "passphrase"
    ? previousKey
    : interactivePassphrase ? crypto.randomBytes(KEY_LENGTH) : undefined;
  const bundle = createFromKeys({
    vaultId: parsed.vaultId,
    generation: 1,
    machineIdentity: deriveStableMachineIdentity(),
    machineKey,
    ...(interactiveKey && interactivePassphrase ? { interactiveKey, interactivePassphrase } : {}),
  });
  const backupPath = nextVaultBackupPath(getVaultPath()).replace(".v1.", ".v2.");
  try {
    database.prepare("VACUUM INTO ?").run(backupPath);
    enforceOwnerOnlyPath(backupPath, { kind: "file", label: "dual-key migration database backup" });
    backupExistingKeyFile(getKeyPath());
    if (_dualMigrationFaultForTests === "after-backup") throw new Error("Injected dual-key migration crash after backup.");
    writeDualMigrationJournal({
      version: 1,
      previousKeyFile: previousEncoded.toString("base64"),
      nextBundle: serializeKeyBundle(bundle).toString("base64"),
      databaseBackup: path.basename(backupPath),
      databaseBackupHash: crypto.createHash("sha256").update(fs.readFileSync(backupPath)).digest("hex"),
      vaultId: parsed.vaultId.toString("base64"),
    });
    if (_dualMigrationFaultForTests === "after-journal") throw new Error("Injected dual-key migration crash after journal.");
    writeActiveKeyBundle(bundle, getKeyPath(), false);
    if (_dualMigrationFaultForTests === "after-bundle") throw new Error("Injected dual-key migration crash after bundle.");
    const migrate = database.transaction(() => {
      database.exec("ALTER TABLE secrets ADD COLUMN key_class TEXT NOT NULL DEFAULT 'machine' CHECK(key_class IN ('machine', 'interactive'))");
      const update = database.prepare(`UPDATE secrets SET key_class = ?, encrypted_value = ?, iv = ?, auth_tag = ? WHERE project = ? AND environment = ? AND name = ?`);
      for (const row of rows) {
        const target: KeyClass = evaluate(row.project, row.environment, row.name) === "locked" ? "interactive" : "machine";
        const value = decryptRecord(row, previousKey, parsed.vaultId!, LEGACY_VAULT_FORMAT_VERSION);
        const encrypted = encryptRecord(value, target === "interactive" ? interactiveKey! : machineKey, {
          vaultId: parsed.vaultId!, recordId: row.record_id!, project: row.project, environment: row.environment,
          name: row.name, recordKind: row.record_kind, keyClass: target,
        });
        update.run(target, encrypted.encrypted, encrypted.iv, encrypted.authTag, row.project, row.environment, row.name);
      }
      const columns = (database.pragma("table_info(vault_metadata)") as { name: string }[]).map((column) => column.name);
      if (!columns.includes("bundle_generation")) database.exec("ALTER TABLE vault_metadata ADD COLUMN bundle_generation INTEGER");
      if (!columns.includes("bundle_hash")) database.exec("ALTER TABLE vault_metadata ADD COLUMN bundle_hash BLOB");
      if (!columns.includes("machine_key_check_iv")) database.exec("ALTER TABLE vault_metadata ADD COLUMN machine_key_check_iv BLOB");
      if (!columns.includes("machine_key_check_tag")) database.exec("ALTER TABLE vault_metadata ADD COLUMN machine_key_check_tag BLOB");
      if (!columns.includes("interactive_key_check_iv")) database.exec("ALTER TABLE vault_metadata ADD COLUMN interactive_key_check_iv BLOB");
      if (!columns.includes("interactive_key_check_tag")) database.exec("ALTER TABLE vault_metadata ADD COLUMN interactive_key_check_tag BLOB");
      if (!columns.includes("interactive_key_present")) database.exec("ALTER TABLE vault_metadata ADD COLUMN interactive_key_present INTEGER");
      const machineCheck = createClassKeyCheck(machineKey, parsed.vaultId!, "machine");
      const interactiveCheck = interactiveKey ? createClassKeyCheck(interactiveKey, parsed.vaultId!, "interactive") : { iv: null, authTag: null };
      database.prepare(`UPDATE vault_metadata SET format_version = ?, bundle_generation = ?, bundle_hash = ?,
        machine_key_check_iv = ?, machine_key_check_tag = ?, interactive_key_check_iv = ?, interactive_key_check_tag = ?, interactive_key_present = ?
        WHERE singleton = 1`).run(
        VAULT_FORMAT_VERSION, bundle.generation, keyBundleHash(bundle), machineCheck.iv, machineCheck.authTag,
        interactiveCheck.iv, interactiveCheck.authTag, interactiveKey ? 1 : 0,
      );
      database.pragma(`user_version = ${VAULT_FORMAT_VERSION}`);
    });
    migrate.immediate();
    if (_dualMigrationFaultForTests === "after-database") throw new Error("Injected dual-key migration crash after database commit.");
    fs.unlinkSync(path.join(getVaultDir(), DUAL_MIGRATION_JOURNAL));
  } catch (error) {
    if (_dualMigrationFaultForTests === null) {
      if (hasInterruptedDualKeyMigration()) recoverInterruptedDualKeyMigration();
      else publishRawKeyFile(previousEncoded);
    }
    throw error;
  } finally {
    database.close();
  }
  clearKey();
  cacheLoadedKey(machineKey, getKeyPath());
  _interactiveKey = interactiveKey ?? null;
  rememberKeyValidation();
}

export function setDualKeyMigrationFaultForTests(
  fault: "after-backup" | "after-journal" | "after-bundle" | "after-database" | null,
): void {
  _dualMigrationFaultForTests = fault;
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

function createCurrentSecretsTableSql(
  tableName: "secrets" | "secrets_current_migrate",
  dualKey = false,
): string {
  return `
  CREATE TABLE ${tableName} (
    project TEXT NOT NULL,
    environment TEXT NOT NULL,
    name TEXT NOT NULL,
    record_id BLOB NOT NULL UNIQUE CHECK(length(record_id) = 16),
    record_kind TEXT NOT NULL CHECK(record_kind = 'secret'),
    ${dualKey ? "key_class TEXT NOT NULL CHECK(key_class IN ('machine', 'interactive'))," : ""}
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
  if (!row || (row.format_version !== LEGACY_VAULT_FORMAT_VERSION && row.format_version !== VAULT_FORMAT_VERSION) ||
      !Buffer.isBuffer(row.vault_id) || row.vault_id.length !== 16) {
    throw new Error("Keyclasp vault format metadata is corrupt or unsupported.");
  }
  const columns = secretsTableColumns(db);
  if (!columns.includes("record_id") || !columns.includes("record_kind")) {
    throw new Error("Keyclasp vault is partially migrated: format metadata and record schema disagree. Restore a pre-migration backup.");
  }
  if (row.format_version === VAULT_FORMAT_VERSION && !columns.includes("key_class")) {
    throw new Error("Keyclasp vault is partially migrated: dual-key metadata and record schema disagree. Restore a pre-migration backup.");
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
    enforceOwnerOnlyPath(backupPath, { kind: "file", label: "vault migration backup" });
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
        formatVersion: LEGACY_VAULT_FORMAT_VERSION,
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
  `).run(LEGACY_VAULT_FORMAT_VERSION, vaultId, keyCheck.iv, keyCheck.authTag);
  db.pragma(`user_version = ${LEGACY_VAULT_FORMAT_VERSION}`);
}

function createDualKeyVault(
  db: Database.Database,
  bundle: KeyBundleDescriptor,
  machineKey: Buffer,
  interactiveKey?: Buffer,
): void {
  const create = db.transaction(() => {
    db.exec(createCurrentSecretsTableSql("secrets", true));
    const machineCheck = createClassKeyCheck(machineKey, bundle.vaultId, "machine");
    const interactiveCheck = interactiveKey
      ? createClassKeyCheck(interactiveKey, bundle.vaultId, "interactive")
      : { iv: null, authTag: null };
    db.exec(`
      CREATE TABLE vault_metadata (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
        format_version INTEGER NOT NULL,
        vault_id BLOB NOT NULL CHECK(length(vault_id) = 16),
        bundle_generation INTEGER NOT NULL,
        bundle_hash BLOB NOT NULL CHECK(length(bundle_hash) = 32),
        machine_key_check_iv BLOB NOT NULL CHECK(length(machine_key_check_iv) = 12),
        machine_key_check_tag BLOB NOT NULL CHECK(length(machine_key_check_tag) = 16),
        interactive_key_check_iv BLOB CHECK(interactive_key_check_iv IS NULL OR length(interactive_key_check_iv) = 12),
        interactive_key_check_tag BLOB CHECK(interactive_key_check_tag IS NULL OR length(interactive_key_check_tag) = 16),
        interactive_key_present INTEGER NOT NULL CHECK(interactive_key_present IN (0, 1))
      )
    `);
    db.prepare(`
      INSERT INTO vault_metadata (
        singleton, format_version, vault_id, bundle_generation, bundle_hash,
        machine_key_check_iv, machine_key_check_tag,
        interactive_key_check_iv, interactive_key_check_tag, interactive_key_present
      ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      VAULT_FORMAT_VERSION,
      bundle.vaultId,
      bundle.generation,
      keyBundleHash(bundle),
      machineCheck.iv,
      machineCheck.authTag,
      interactiveCheck.iv,
      interactiveCheck.authTag,
      interactiveKey ? 1 : 0,
    );
    db.pragma(`user_version = ${VAULT_FORMAT_VERSION}`);
  });
  create.immediate();
}

function validateBundleAgainstDatabase(db: Database.Database, bundle: KeyBundleDescriptor): void {
  if (!tableExists(db, "vault_metadata")) {
    if (tableExists(db, "secrets") && secretsTableColumns(db).includes("record_id")) {
      throw new Error("Keyclasp vault is partially migrated: record identity exists without format metadata. Restore a pre-migration backup.");
    }
    throw new Error("Keyclasp vault database is empty or replaced. Restore vault.db and its matching key bundle from the same backup.");
  }
  const row = db.prepare(`
    SELECT format_version, vault_id, bundle_generation, bundle_hash, interactive_key_present
    FROM vault_metadata WHERE singleton = 1
  `).get() as {
    format_version: number;
    vault_id: Buffer;
    bundle_generation: number;
    bundle_hash: Buffer;
    interactive_key_present: number;
  } | undefined;
  if (!row || row.format_version !== VAULT_FORMAT_VERSION || !Buffer.isBuffer(row.vault_id) ||
      !row.vault_id.equals(bundle.vaultId) || row.bundle_generation !== bundle.generation ||
      !Buffer.isBuffer(row.bundle_hash) || !row.bundle_hash.equals(keyBundleHash(bundle)) ||
      row.interactive_key_present !== (bundle.interactive ? 1 : 0)) {
    throw new Error(KEY_VAULT_MISMATCH_ERROR);
  }
  const columns = secretsTableColumns(db);
  if (!columns.includes("key_class")) {
    throw new Error("Keyclasp vault appears partially migrated: the dual-key record schema is incomplete.");
  }
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
      const encoded = fs.readFileSync(getKeyPath());
      if (encoded.subarray(0, KEY_BUNDLE_MAGIC.length).equals(KEY_BUNDLE_MAGIC)) {
        validateBundleAgainstDatabase(_db, parseKeyBundle(encoded));
      } else {
        validateDatabaseStateForKeyFile(_db, parseKeyFile(encoded));
      }
    } catch (err) {
      closeDb();
      throw err;
    }
  }
  enforceOwnerOnlyVaultPermissions();
  return _db;
}

function currentDualKeyVault(): { db: Database.Database; bundle: KeyBundleDescriptor; vaultId: Buffer } {
  const bundle = readActiveKeyBundle();
  const db = getDb();
  validateBundleAgainstDatabase(db, bundle);
  return { db, bundle, vaultId: bundle.vaultId };
}

function keyForClass(keyClass: KeyClass, db: Database.Database, bundle: KeyBundleDescriptor): Buffer {
  if (keyClass === "machine") return getKey();
  if (!_interactiveKey) throw new Error(KEY_LOCKED_ERROR);
  verifyClassKeyCheck(db, _interactiveKey, bundle.vaultId, "interactive");
  return _interactiveKey;
}

export function storeSecret(
  project: string,
  environment: string,
  name: string,
  value: string,
  requestedKeyClass: KeyClass = "machine",
): void {
  validateScopeName(project, "project");
  validateScopeName(environment, "environment");
  const encoded = fs.readFileSync(getKeyPath());
  if (!encoded.subarray(0, KEY_BUNDLE_MAGIC.length).equals(KEY_BUNDLE_MAGIC)) {
    const key = getKey();
    const db = getDb();
    assertKeyUnlocksVault(key);
    const vaultId = ensureVaultFormatMatchesKey(db, key);
    storeSecretWithKey(db, vaultId, key, project, environment, name, value);
    return;
  }
  const { db, bundle, vaultId } = currentDualKeyVault();
  const key = keyForClass(requestedKeyClass, db, bundle);
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
      keyClass: requestedKeyClass,
    });
    db.prepare(`
      INSERT INTO secrets (project, environment, name, record_id, record_kind, key_class, encrypted_value, iv, auth_tag, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
      ON CONFLICT(project, environment, name) DO UPDATE SET
        key_class = excluded.key_class,
        encrypted_value = excluded.encrypted_value,
        iv = excluded.iv,
        auth_tag = excluded.auth_tag,
        updated_at = datetime('now')
    `).run(project, environment, name, recordId, RECORD_KIND_SECRET, requestedKeyClass, encrypted, iv, authTag);
  });
  write.immediate();
  rememberKeyValidation();
}

function storeSecretWithKey(
  db: Database.Database,
  vaultId: Buffer,
  key: Buffer,
  project: string,
  environment: string,
  name: string,
  value: string,
): void {
  const write = db.transaction(() => {
    const existing = db.prepare("SELECT record_id FROM secrets WHERE project = ? AND environment = ? AND name = ?")
      .get(project, environment, name) as { record_id: Buffer } | undefined;
    const recordId = existing?.record_id ?? crypto.randomBytes(16);
    const encrypted = encryptRecord(value, key, { vaultId, recordId, project, environment, name, formatVersion: LEGACY_VAULT_FORMAT_VERSION });
    db.prepare(`
      INSERT INTO secrets (project, environment, name, record_id, record_kind, encrypted_value, iv, auth_tag, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
      ON CONFLICT(project, environment, name) DO UPDATE SET encrypted_value = excluded.encrypted_value, iv = excluded.iv, auth_tag = excluded.auth_tag, updated_at = datetime('now')
    `).run(project, environment, name, recordId, RECORD_KIND_SECRET, encrypted.encrypted, encrypted.iv, encrypted.authTag);
  });
  write.immediate();
  rememberKeyValidation();
}

export function resolveSecret(project: string, environment: string, name: string): string | null {
  if (REMOVED_INTERNAL_SECRET_NAMES.has(name)) return null;

  const encoded = fs.readFileSync(getKeyPath());
  const dualKey = encoded.subarray(0, KEY_BUNDLE_MAGIC.length).equals(KEY_BUNDLE_MAGIC);
  const db = getDb();
  const bundle = dualKey ? parseKeyBundle(encoded) : null;
  const key = dualKey ? null : getKey();
  const vaultId = dualKey ? bundle!.vaultId : ensureVaultFormatMatchesKey(db, key!);
  const row = db.prepare(
    `SELECT project, environment, name, record_id, record_kind, ${dualKey ? "key_class," : ""} encrypted_value, iv, auth_tag FROM secrets WHERE project = ? AND environment = ? AND name = ?`
  ).get(project, environment, name) as
    | NamedEncryptedVaultRow
    | undefined;

  if (!row) return null;
  const rowKey = dualKey ? keyForClass(row.key_class!, db, bundle!) : key!;
  return decryptRecord(row, rowKey, vaultId, dualKey ? VAULT_FORMAT_VERSION : LEGACY_VAULT_FORMAT_VERSION);
}

export function resolveSecretsForRun(
  project: string,
  environment: string,
  names: readonly string[],
): Map<string, string> {
  if (names.length === 0) return new Map();
  const uniqueNames = [...new Set(names)];
  const encoded = fs.readFileSync(getKeyPath());
  const dualKey = encoded.subarray(0, KEY_BUNDLE_MAGIC.length).equals(KEY_BUNDLE_MAGIC);
  const db = getDb();
  const bundle = dualKey ? parseKeyBundle(encoded) : null;
  const key = dualKey ? null : getKey();
  if (key) assertKeyUnlocksVault(key);
  const vaultId = dualKey ? bundle!.vaultId : ensureVaultFormatMatchesKey(db, key!);
  const placeholders = uniqueNames.map(() => "?").join(", ");
  const read = db.transaction(() => {
    const rows = db.prepare(`
      SELECT project, environment, name, record_id, record_kind, ${dualKey ? "key_class," : ""} encrypted_value, iv, auth_tag
      FROM secrets
      WHERE project = ? AND environment = ? AND name IN (${placeholders})
    `).all(project, environment, ...uniqueNames) as NamedEncryptedVaultRow[];
    const rowsByName = new Map(rows.map((row) => [row.name, row]));
    for (const name of uniqueNames) {
      if (!rowsByName.has(name)) {
        throw new Error(`Secret "${name}" disappeared before it could be injected.`);
      }
    }
    return new Map(uniqueNames.map((name) => {
      const row = rowsByName.get(name)!;
      const rowKey = dualKey ? keyForClass(row.key_class!, db, bundle!) : key!;
      return [name, decryptRecord(row, rowKey, vaultId, dualKey ? VAULT_FORMAT_VERSION : LEGACY_VAULT_FORMAT_VERSION)];
    }));
  });
  return read();
}

export function transitionRecordCustody(
  database: Database.Database,
  nextRules: readonly { project?: string; environment?: string; secret?: string; locked: boolean }[],
  evaluate: (
    rules: readonly { project?: string; environment?: string; secret?: string; locked: boolean }[],
    project: string,
    environment: string,
    secret?: string,
  ) => "locked" | "unlocked",
): number {
  const bundle = readActiveKeyBundle();
  validateBundleAgainstDatabase(database, bundle);
  const machineKey = getKey();
  const rows = database.prepare(`SELECT ${currentSecretColumns(database)} FROM secrets ORDER BY project, environment, name`)
    .all() as CurrentSecretRow[];
  const transitions = rows.map((row) => ({
    row,
    target: evaluate(nextRules, row.project, row.environment, row.name) === "locked" ? "interactive" as const : "machine" as const,
  })).filter(({ row, target }) => row.key_class !== target);
  if (transitions.some(({ target }) => target === "interactive") && !bundle.interactive) {
    throw new Error("Interactive custody is not enrolled. Run: keyclasp passphrase set");
  }
  const interactiveKey = transitions.some(({ row, target }) => row.key_class === "interactive" || target === "interactive")
    ? keyForClass("interactive", database, bundle)
    : null;
  const update = database.prepare(`
    UPDATE secrets SET key_class = ?, encrypted_value = ?, iv = ?, auth_tag = ?, updated_at = datetime('now')
    WHERE project = ? AND environment = ? AND name = ?
  `);
  for (const { row, target } of transitions) {
    const sourceKey = row.key_class === "interactive" ? interactiveKey! : machineKey;
    const targetKey = target === "interactive" ? interactiveKey! : machineKey;
    const value = decryptRecord(row, sourceKey, bundle.vaultId);
    const encrypted = encryptRecord(value, targetKey, {
      vaultId: bundle.vaultId,
      recordId: row.record_id!,
      project: row.project,
      environment: row.environment,
      name: row.name,
      recordKind: row.record_kind,
      keyClass: target,
    });
    update.run(target, encrypted.encrypted, encrypted.iv, encrypted.authTag, row.project, row.environment, row.name);
  }
  return transitions.length;
}

export function readSecretKeyClass(project: string, environment: string, name: string): KeyClass | null {
  const db = getDb();
  if (!secretsTableColumns(db).includes("key_class")) return null;
  const row = db.prepare("SELECT key_class FROM secrets WHERE project = ? AND environment = ? AND name = ?")
    .get(project, environment, name) as { key_class: KeyClass } | undefined;
  return row?.key_class ?? null;
}

export function summarizeKeyClasses(databasePath = getVaultPath()): { machine: number; interactive: number } {
  const database = databasePath === getVaultPath() ? getDb() : new Database(databasePath, { readonly: true, fileMustExist: true });
  const closeAfter = databasePath !== getVaultPath();
  try {
    if (!secretsTableColumns(database).includes("key_class")) return { machine: 0, interactive: 0 };
    const rows = database.prepare("SELECT key_class, count(*) AS count FROM secrets GROUP BY key_class").all() as
      { key_class: KeyClass; count: number }[];
    return {
      machine: rows.find((row) => row.key_class === "machine")?.count ?? 0,
      interactive: rows.find((row) => row.key_class === "interactive")?.count ?? 0,
    };
  } finally {
    if (closeAfter) database.close();
  }
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

function currentVaultForMutation(): { db: Database.Database; key: Buffer; vaultId: Buffer } {
  const key = getKey();
  const db = getDb();
  const encoded = fs.readFileSync(getKeyPath());
  if (encoded.subarray(0, KEY_BUNDLE_MAGIC.length).equals(KEY_BUNDLE_MAGIC)) {
    const bundle = parseKeyBundle(encoded);
    validateBundleAgainstDatabase(db, bundle);
    return { db, key, vaultId: bundle.vaultId };
  }
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
  bundle?: KeyBundleDescriptor,
): number {
  const update = db.prepare(`
    UPDATE secrets SET
      project = ?, environment = ?, encrypted_value = ?, iv = ?, auth_tag = ?, updated_at = datetime('now')
    WHERE project = ? AND environment = ? AND name = ?
  `);
  for (const row of rows) {
    const rowKey = bundle ? keyForClass(row.key_class!, db, bundle) : key;
    const value = decryptRecord(row, rowKey, vaultId, bundle ? VAULT_FORMAT_VERSION : LEGACY_VAULT_FORMAT_VERSION);
    const destination = target(row);
    const encrypted = encryptRecord(value, rowKey, {
      vaultId,
      recordId: row.record_id!,
      project: destination.project,
      environment: destination.environment,
      name: row.name,
      recordKind: row.record_kind,
      ...(bundle ? { keyClass: row.key_class } : { formatVersion: LEGACY_VAULT_FORMAT_VERSION }),
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

function currentSecretColumns(db: Database.Database): string {
  return `project, environment, name, record_id, record_kind, ${secretsTableColumns(db).includes("key_class") ? "key_class," : ""} encrypted_value, iv, auth_tag`;
}

function currentBundleForDatabase(db: Database.Database): KeyBundleDescriptor | undefined {
  const encoded = fs.readFileSync(getKeyPath());
  if (!encoded.subarray(0, KEY_BUNDLE_MAGIC.length).equals(KEY_BUNDLE_MAGIC)) return undefined;
  const bundle = parseKeyBundle(encoded);
  validateBundleAgainstDatabase(db, bundle);
  return bundle;
}

export function renameProject(fromProject: string, toProject: string): { moved: number } {
  validateScopeName(fromProject, "project");
  validateScopeName(toProject, "project");
  const key = getKey();
  const db = getDb();
  const bundle = currentBundleForDatabase(db);
  const vaultId = bundle?.vaultId ?? ensureVaultFormatMatchesKey(db, key);
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
    const rows = db.prepare(`SELECT ${currentSecretColumns(db)} FROM secrets WHERE project = ? ORDER BY environment, name`)
      .all(fromProject) as CurrentSecretRow[];
    return reencryptMovedRows(db, key, vaultId, rows, (row) => ({ project: toProject, environment: row.environment }), bundle);
  });
  return { moved: tx.immediate() };
}

export function renameEnvironmentInProject(project: string, fromEnvironment: string, toEnvironment: string): { moved: number } {
  validateScopeName(project, "project");
  validateScopeName(fromEnvironment, "environment");
  validateScopeName(toEnvironment, "environment");
  const key = getKey();
  const db = getDb();
  const bundle = currentBundleForDatabase(db);
  const vaultId = bundle?.vaultId ?? ensureVaultFormatMatchesKey(db, key);
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
    const rows = db.prepare(`SELECT ${currentSecretColumns(db)} FROM secrets WHERE project = ? AND environment = ? ORDER BY name`)
      .all(project, fromEnvironment) as CurrentSecretRow[];
    return reencryptMovedRows(db, key, vaultId, rows, () => ({ project, environment: toEnvironment }), bundle);
  });
  return { moved: tx.immediate() };
}

export function renameEnvironmentAcrossAllProjects(fromEnvironment: string, toEnvironment: string): { moved: number; projectsAffected: number } {
  validateScopeName(fromEnvironment, "environment");
  validateScopeName(toEnvironment, "environment");
  const key = getKey();
  const db = getDb();
  const bundle = currentBundleForDatabase(db);
  const vaultId = bundle?.vaultId ?? ensureVaultFormatMatchesKey(db, key);
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
    const rows = db.prepare(`SELECT ${currentSecretColumns(db)} FROM secrets WHERE environment = ? ORDER BY project, name`)
      .all(fromEnvironment) as CurrentSecretRow[];
    const moved = reencryptMovedRows(db, key, vaultId, rows, (row) => ({ project: row.project, environment: toEnvironment }), bundle);
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
  const bundle = currentBundleForDatabase(db);
  const vaultId = bundle?.vaultId ?? ensureVaultFormatMatchesKey(db, key);
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
    const rows = db.prepare(`SELECT ${currentSecretColumns(db)} FROM secrets WHERE project = ? AND environment = ? ORDER BY name`)
      .all(fromProject, fromEnvironment) as CurrentSecretRow[];
    return reencryptMovedRows(db, key, vaultId, rows, () => ({ project: toProject, environment: toEnvironment }), bundle);
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
  _interactiveKey = null;
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
