import crypto from "node:crypto";
import Database from "better-sqlite3";
import fs from "node:fs";
import path from "node:path";
import { closeDb, clearKey, ensureOwnerOnlyVaultDirectory, getKey, getVaultDescriptor, getVaultLocation, unlockManagedBackupKey, validateKeyFileDescriptor } from "./vault.js";
import { AUTHORIZATION_POLICY_BACKUP_FILES, authorizationPolicyFiles, validateAuthorizationPolicyBackup, validateLiveAuthorizationPolicy } from "./policy.js";
import { enforceOwnerOnlyPath } from "./owner-only-path.js";
import type { OperatorAuthorization, OperatorAuthorizer } from "./runtime.js";

const BACKUP_VERSION = 1;
const MANAGED_FILES = ["vault.db", ".keyclasp.key", ...AUTHORIZATION_POLICY_BACKUP_FILES] as const;
const RESTORE_JOURNAL = ".restore-transaction.v1.json";
const RESTORE_JOURNAL_KEY = ".restore-journal.key";
type RestoreFault =
  | "crash-after-first-stage-copy"
  | "crash-after-journal"
  | "crash-after-first-previous"
  | "crash-after-previous-fsync"
  | "crash-after-first-publish"
  | "crash-after-all-published"
  | "crash-after-commit-journal";
let _restoreFaultForTests: RestoreFault | null = null;
type BackupFault = "crash-before-backup-publish" | "crash-after-backup-publish";
let _backupFaultForTests: BackupFault | null = null;

interface RestoreJournal {
  version: 1;
  phase: "staging" | "replacing" | "committed";
  transactionId: string;
  staged: string[];
  previous: string[];
  previousHashes: Record<string, string>;
  stagedHashes: Record<string, string>;
  mac: string;
}

interface BackupManifest {
  version: 1;
  createdAt: string;
  vaultId: string;
  mode: "passphrase" | "machine";
  files: Record<string, string>;
  mac: string;
}

interface ManagedRestoreResult {
  manifest: BackupManifest;
  cleanupWarnings: string[];
}

function manifestPayload(manifest: Omit<BackupManifest, "mac">): string {
  return JSON.stringify({
    version: manifest.version,
    createdAt: manifest.createdAt,
    vaultId: manifest.vaultId,
    mode: manifest.mode,
    files: Object.fromEntries(Object.entries(manifest.files).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)),
  });
}

function manifestMac(manifest: Omit<BackupManifest, "mac">, key: Buffer): string {
  return crypto.createHmac("sha256", key)
    .update("keyclasp:managed-backup:v1\0")
    .update(manifestPayload(manifest))
    .digest("base64");
}

function sha256(filePath: string): string {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function fsyncFile(filePath: string): void {
  const descriptor = fs.openSync(filePath, "r");
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}

function fsyncDirectory(directory: string): void {
  const descriptor = fs.openSync(directory, "r");
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}

function restoreJournalPath(): string {
  return path.join(getVaultLocation(), RESTORE_JOURNAL);
}

function restoreJournalKey(): Buffer {
  const keyPath = path.join(getVaultLocation(), RESTORE_JOURNAL_KEY);
  if (!fs.existsSync(keyPath)) {
    fs.writeFileSync(keyPath, crypto.randomBytes(32), { mode: 0o600, flag: "wx" });
    fsyncFile(keyPath);
    fsyncDirectory(getVaultLocation());
  }
  enforceOwnerOnlyPath(keyPath, { kind: "file", label: "managed-restore journal key" });
  const key = fs.readFileSync(keyPath);
  if (key.length !== 32) throw new Error("Managed-restore journal key is corrupt.");
  return key;
}

function restoreJournalPayload(journal: Omit<RestoreJournal, "mac">): string {
  return JSON.stringify(journal);
}

function restoreJournalMac(journal: Omit<RestoreJournal, "mac">): string {
  return crypto.createHmac("sha256", restoreJournalKey())
    .update("keyclasp:restore-journal:v1\0")
    .update(restoreJournalPayload(journal))
    .digest("base64");
}

function writeRestoreJournal(payload: Omit<RestoreJournal, "mac">): void {
  const journalPath = restoreJournalPath();
  const journal: RestoreJournal = { ...payload, mac: restoreJournalMac(payload) };
  const temporaryPath = `${journalPath}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  fs.writeFileSync(temporaryPath, `${JSON.stringify(journal)}\n`, { mode: 0o600 });
  enforceOwnerOnlyPath(temporaryPath, { kind: "file", label: "managed-restore journal staging file" });
  fsyncFile(temporaryPath);
  fs.renameSync(temporaryPath, journalPath);
  enforceOwnerOnlyPath(journalPath, { kind: "file", label: "managed-restore journal" });
  fsyncDirectory(getVaultLocation());
}

export function recoverInterruptedManagedRestore(): boolean {
  const journalPath = restoreJournalPath();
  if (!fs.existsSync(journalPath)) return false;
  enforceOwnerOnlyPath(journalPath, { kind: "file", label: "managed-restore journal" });
  let journal: RestoreJournal;
  try {
    journal = JSON.parse(fs.readFileSync(journalPath, "utf8")) as RestoreJournal;
  } catch {
    throw new Error("Managed-restore journal is corrupt. Recover the vault directory from a trusted backup.");
  }
  const validNames = new Set<string>(MANAGED_FILES);
  if (journal.version !== 1 || !["staging", "replacing", "committed"].includes(journal.phase) || !journal.transactionId ||
      !journal.staged.every((name) => validNames.has(name)) ||
      !journal.previous.every((name) => validNames.has(name)) || typeof journal.mac !== "string") {
    throw new Error("Managed-restore journal is invalid. Recover the vault directory from a trusted backup.");
  }
  const { mac, ...payload } = journal;
  const expectedMac = Buffer.from(restoreJournalMac(payload), "base64");
  const actualMac = Buffer.from(mac, "base64");
  if (actualMac.length !== expectedMac.length || !crypto.timingSafeEqual(actualMac, expectedMac)) {
    throw new Error("Managed-restore journal failed authentication. Recover the vault directory from a trusted backup.");
  }
  const vaultDir = getVaultLocation();
  if (journal.phase === "staging") {
    for (const name of journal.staged) {
      const stagedPath = path.join(vaultDir, `${name}.${journal.transactionId}.restore`);
      if (fs.existsSync(stagedPath)) fs.unlinkSync(stagedPath);
    }
    fsyncDirectory(vaultDir);
    fs.unlinkSync(journalPath);
    fsyncDirectory(vaultDir);
    return true;
  }
  if (journal.phase === "committed") {
    for (const name of journal.staged) {
      const livePath = path.join(vaultDir, name);
      if (fs.existsSync(livePath)) enforceOwnerOnlyPath(livePath, { kind: "file", label: `committed restored file "${name}"` });
      if (!fs.existsSync(livePath) || sha256(livePath) !== journal.stagedHashes[name]) {
        throw new Error(`Managed-restore committed file "${name}" failed journal authentication.`);
      }
    }
    for (const name of journal.previous) {
      const previousPath = path.join(vaultDir, `${name}.${journal.transactionId}.previous`);
      if (fs.existsSync(previousPath)) enforceOwnerOnlyPath(previousPath, { kind: "file", label: `managed restore prior file "${name}"` });
      if (fs.existsSync(previousPath) && sha256(previousPath) !== journal.previousHashes[name]) {
        throw new Error(`Managed-restore prior file "${name}" failed journal authentication.`);
      }
    }
    for (const name of MANAGED_FILES) {
      const stagedPath = path.join(vaultDir, `${name}.${journal.transactionId}.restore`);
      const previousPath = path.join(vaultDir, `${name}.${journal.transactionId}.previous`);
      if (fs.existsSync(stagedPath)) fs.unlinkSync(stagedPath);
      if (fs.existsSync(previousPath)) fs.unlinkSync(previousPath);
    }
    fsyncDirectory(vaultDir);
    fs.unlinkSync(journalPath);
    fsyncDirectory(vaultDir);
    return true;
  }
  for (const name of journal.previous) {
    const livePath = path.join(vaultDir, name);
    const previousPath = path.join(vaultDir, `${name}.${journal.transactionId}.previous`);
    const candidate = fs.existsSync(previousPath) ? previousPath : livePath;
    if (fs.existsSync(candidate)) enforceOwnerOnlyPath(candidate, { kind: "file", label: `managed restore prior candidate "${name}"` });
    if (!fs.existsSync(candidate) || sha256(candidate) !== journal.previousHashes[name]) {
      throw new Error(`Managed-restore prior file "${name}" failed journal authentication.`);
    }
  }
  for (const name of journal.staged) {
    const livePath = path.join(vaultDir, name);
    const stagedPath = path.join(vaultDir, `${name}.${journal.transactionId}.restore`);
    const candidate = fs.existsSync(stagedPath) ? stagedPath : livePath;
    if (fs.existsSync(candidate)) enforceOwnerOnlyPath(candidate, { kind: "file", label: `managed restore staged candidate "${name}"` });
    if (!fs.existsSync(candidate) || sha256(candidate) !== journal.stagedHashes[name]) {
      throw new Error(`Managed-restore staged file "${name}" failed journal authentication.`);
    }
  }
  for (const name of MANAGED_FILES) {
    const livePath = path.join(vaultDir, name);
    const stagedPath = path.join(vaultDir, `${name}.${journal.transactionId}.restore`);
    const previousPath = path.join(vaultDir, `${name}.${journal.transactionId}.previous`);
    if (fs.existsSync(previousPath)) {
      if (fs.existsSync(livePath)) fs.unlinkSync(livePath);
      fs.renameSync(previousPath, livePath);
      enforceOwnerOnlyPath(livePath, { kind: "file", label: `recovered vault file "${name}"` });
    } else if (!journal.previous.includes(name) && journal.staged.includes(name) && fs.existsSync(livePath)) {
      fs.unlinkSync(livePath);
    }
    if (fs.existsSync(stagedPath)) fs.unlinkSync(stagedPath);
  }
  fsyncDirectory(vaultDir);
  fs.unlinkSync(journalPath);
  fsyncDirectory(vaultDir);
  return true;
}

export function hasInterruptedManagedRestore(): boolean {
  return fs.existsSync(restoreJournalPath());
}

function assertSafeBackupDirectory(directory: string): void {
  assertSafeBackupParent(path.dirname(directory));
  enforceOwnerOnlyPath(directory, { kind: "directory", label: "managed backup directory" });
}

function assertSafeBackupParent(directory: string): void {
  enforceOwnerOnlyPath(directory, {
    kind: "directory",
    label: "managed backup parent",
    access: "safe-parent",
  });
}

function readManifest(directory: string): BackupManifest {
  let manifest: BackupManifest;
  try {
    enforceOwnerOnlyPath(path.join(directory, "backup.json"), { kind: "file", label: "managed backup manifest" });
    manifest = JSON.parse(fs.readFileSync(path.join(directory, "backup.json"), "utf8")) as BackupManifest;
  } catch {
    throw new Error("Managed backup manifest is missing or corrupt.");
  }
  if (manifest.version !== BACKUP_VERSION || !manifest.vaultId || typeof manifest.mac !== "string" ||
      (manifest.mode !== "passphrase" && manifest.mode !== "machine") || !manifest.files) {
    throw new Error("Managed backup manifest is unsupported or incomplete.");
  }
  const allowedKeys = new Set(["version", "createdAt", "vaultId", "mode", "files", "mac"]);
  if (Object.keys(manifest).some((key) => !allowedKeys.has(key))) {
    throw new Error("Managed backup manifest contains an unknown field.");
  }
  for (const [name, expectedHash] of Object.entries(manifest.files)) {
    if (!MANAGED_FILES.includes(name as typeof MANAGED_FILES[number]) || !/^[a-f0-9]{64}$/.test(expectedHash)) {
      throw new Error("Managed backup manifest contains an invalid file entry.");
    }
    const filePath = path.join(directory, name);
    if (fs.existsSync(filePath)) {
      enforceOwnerOnlyPath(filePath, { kind: "file", label: `managed backup file "${name}"` });
    }
    if (!fs.existsSync(filePath) || sha256(filePath) !== expectedHash) {
      throw new Error(`Managed backup file "${name}" failed its integrity check.`);
    }
  }
  if (!manifest.files["vault.db"] || !manifest.files[".keyclasp.key"]) {
    throw new Error("Managed backup must contain vault.db and .keyclasp.key.");
  }
  return manifest;
}

function assertReadOnlyBackupIdentity(filePath: string, kind: "file" | "directory"): fs.Stats {
  const stat = fs.lstatSync(filePath);
  if (stat.isSymbolicLink() || (kind === "file" ? !stat.isFile() : !stat.isDirectory())) {
    throw new Error(`Managed backup ${kind} is unsafe.`);
  }
  const currentUid = process.getuid?.();
  if (currentUid !== undefined && stat.uid !== currentUid) {
    throw new Error(`Managed backup ${kind} is not owned by the current user.`);
  }
  return stat;
}

function assertReadOnlyBackupIdentityUnchanged(filePath: string, before: fs.Stats, kind: "file" | "directory"): void {
  const after = assertReadOnlyBackupIdentity(filePath, kind);
  if (before.dev !== after.dev || before.ino !== after.ino) {
    throw new Error(`Managed backup ${kind} changed during authorization.`);
  }
}

function readManifestForAuthorization(directory: string): BackupManifest {
  const directoryBefore = assertReadOnlyBackupIdentity(directory, "directory");
  const manifestPath = path.join(directory, "backup.json");
  const manifestBefore = assertReadOnlyBackupIdentity(manifestPath, "file");
  let manifest: BackupManifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as BackupManifest;
  } catch {
    throw new Error("Managed backup manifest is missing or corrupt.");
  }
  assertReadOnlyBackupIdentityUnchanged(manifestPath, manifestBefore, "file");
  assertReadOnlyBackupIdentityUnchanged(directory, directoryBefore, "directory");
  if (manifest.version !== BACKUP_VERSION || (manifest.mode !== "passphrase" && manifest.mode !== "machine")) {
    throw new Error("Managed backup manifest is unsupported or incomplete.");
  }
  return manifest;
}

function readDatabaseMetadata(databasePath: string): { vaultId: string; policyGeneration: number | null; policyDocumentHash: string | null } {
  const db = new Database(databasePath, { readonly: true, fileMustExist: true });
  try {
    const row = db.prepare("SELECT format_version, vault_id FROM vault_metadata WHERE singleton = 1").get() as
      | { format_version: number; vault_id: Buffer }
      | undefined;
    if (!row || row.format_version !== 2 || !Buffer.isBuffer(row.vault_id) || row.vault_id.length !== 16) {
      throw new Error("Managed backup database has unsupported vault metadata.");
    }
    const columns = (db.pragma("table_info(vault_metadata)") as { name: string }[]).map((column) => column.name);
    let policyGeneration: number | null = null;
    let policyDocumentHash: string | null = null;
    if (columns.includes("strict_policy_required") && columns.includes("strict_policy_generation") && columns.includes("strict_policy_document_hash")) {
      const policy = db.prepare("SELECT strict_policy_required, strict_policy_generation, strict_policy_document_hash FROM vault_metadata WHERE singleton = 1").get() as
        { strict_policy_required: number; strict_policy_generation: number | null; strict_policy_document_hash: string | null };
      if (policy.strict_policy_required === 1) {
        policyGeneration = policy.strict_policy_generation;
        policyDocumentHash = policy.strict_policy_document_hash;
      }
    }
    return { vaultId: row.vault_id.toString("base64"), policyGeneration, policyDocumentHash };
  } finally {
    db.close();
  }
}

export function createManagedBackup(destination: string): BackupManifest {
  const descriptor = getVaultDescriptor();
  validateLiveAuthorizationPolicy();
  if (fs.existsSync(destination)) throw new Error("Managed backup destination already exists.");
  const parent = path.dirname(destination);
  assertSafeBackupParent(parent);
  const staging = path.join(parent, `.${path.basename(destination)}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`);
  fs.mkdirSync(staging, { recursive: false, mode: 0o700 });
  assertSafeBackupDirectory(staging);
  const vaultDir = getVaultLocation();
  let published = false;
  try {
    const snapshotPath = path.join(staging, "vault.db");
    const sourceDb = new Database(path.join(vaultDir, "vault.db"), { readonly: true, fileMustExist: true });
    try {
      sourceDb.prepare("VACUUM INTO ?").run(snapshotPath);
    } finally {
      sourceDb.close();
    }
    enforceOwnerOnlyPath(snapshotPath, { kind: "file", label: "managed backup database" });
    fs.copyFileSync(path.join(vaultDir, ".keyclasp.key"), path.join(staging, ".keyclasp.key"));
    enforceOwnerOnlyPath(path.join(staging, ".keyclasp.key"), { kind: "file", label: "managed backup key" });
    for (const source of authorizationPolicyFiles()) {
      const target = path.join(staging, path.basename(source));
      fs.copyFileSync(source, target);
      enforceOwnerOnlyPath(target, { kind: "file", label: `managed backup policy file "${path.basename(target)}"` });
    }
    const files: Record<string, string> = {};
    for (const name of MANAGED_FILES) {
      const filePath = path.join(staging, name);
      if (fs.existsSync(filePath)) files[name] = sha256(filePath);
    }
    const payload: Omit<BackupManifest, "mac"> = {
      version: BACKUP_VERSION,
      createdAt: new Date().toISOString(),
      vaultId: descriptor.vaultId.toString("base64"),
      mode: descriptor.mode,
      files,
    };
    const manifest: BackupManifest = { ...payload, mac: manifestMac(payload, getKey()) };
    const manifestPath = path.join(staging, "backup.json");
    fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
    enforceOwnerOnlyPath(manifestPath, { kind: "file", label: "managed backup manifest" });
    for (const name of [...Object.keys(files), "backup.json"]) fsyncFile(path.join(staging, name));
    fsyncDirectory(staging);
    if (_backupFaultForTests === "crash-before-backup-publish") throw new Error("Injected managed-backup crash before publication.");
    fs.renameSync(staging, destination);
    published = true;
    enforceOwnerOnlyPath(destination, { kind: "directory", label: "managed backup directory" });
    if (_backupFaultForTests === "crash-after-backup-publish") throw new Error("Injected managed-backup crash after publication.");
    fsyncDirectory(parent);
    return manifest;
  } catch (error) {
    if (!published) fs.rmSync(staging, { recursive: true, force: true });
    if (published && _backupFaultForTests === null) {
      throw new Error(`Managed backup was published at "${destination}", but its directory durability is indeterminate: ${error instanceof Error ? error.message : "unknown error"}`);
    }
    throw error;
  }
}

export function inspectManagedBackupMode(source: string): "passphrase" | "machine" {
  return readManifestForAuthorization(source).mode;
}

export async function createManagedBackupAuthorized(
  destination: string,
  dependencies: {
    authorize: OperatorAuthorizer;
    ensureUnlocked: () => Promise<void>;
    validatePolicy?: typeof validateLiveAuthorizationPolicy;
    create?: typeof createManagedBackup;
  },
): Promise<BackupManifest> {
  (dependencies.validatePolicy ?? validateLiveAuthorizationPolicy)();
  await dependencies.authorize("Create a managed Keyclasp backup");
  await dependencies.ensureUnlocked();
  return (dependencies.create ?? createManagedBackup)(destination);
}

export async function restoreManagedBackupAuthorized(
  source: string,
  dependencies: {
    authorize: (reason: string, mode: "passphrase" | "machine") =>
      OperatorAuthorization | Promise<OperatorAuthorization>;
    promptPassphrase: () => Promise<string>;
    inspectMode?: typeof inspectManagedBackupMode;
    restore?: typeof restoreManagedBackup;
  },
): Promise<ManagedRestoreResult> {
  const mode = (dependencies.inspectMode ?? inspectManagedBackupMode)(source);
  const authorization = await dependencies.authorize("Restore a managed Keyclasp backup", mode);
  const authorizedPassphrase = authorization.method === "passphrase" ? authorization.passphrase : undefined;
  const passphrase = mode === "passphrase"
    ? authorizedPassphrase ?? await dependencies.promptPassphrase()
    : undefined;
  return (dependencies.restore ?? restoreManagedBackup)(source, passphrase);
}

export function verifyManagedBackupPassphrase(source: string, passphrase: string): boolean {
  try {
    const manifest = readManifestForAuthorization(source);
    if (manifest.mode !== "passphrase") return false;
    const databasePath = path.join(source, "vault.db");
    const keyPath = path.join(source, ".keyclasp.key");
    const databaseBefore = assertReadOnlyBackupIdentity(databasePath, "file");
    const keyBefore = assertReadOnlyBackupIdentity(keyPath, "file");
    const databaseMetadata = readDatabaseMetadata(databasePath);
    if (databaseMetadata.vaultId !== manifest.vaultId) return false;
    validateKeyFileDescriptor(
      keyPath,
      Buffer.from(manifest.vaultId, "base64"),
      "passphrase",
    );
    unlockManagedBackupKey(keyPath, databasePath, passphrase);
    assertReadOnlyBackupIdentityUnchanged(keyPath, keyBefore, "file");
    assertReadOnlyBackupIdentityUnchanged(databasePath, databaseBefore, "file");
    return true;
  } catch {
    return false;
  }
}

export function restoreManagedBackup(source: string, passphrase?: string): ManagedRestoreResult {
  assertSafeBackupDirectory(source);
  const manifest = readManifest(source);
  const databaseMetadata = readDatabaseMetadata(path.join(source, "vault.db"));
  if (databaseMetadata.vaultId !== manifest.vaultId) {
    throw new Error("Managed backup database identity does not match its manifest.");
  }
  validateKeyFileDescriptor(
    path.join(source, ".keyclasp.key"),
    Buffer.from(manifest.vaultId, "base64"),
    manifest.mode,
  );
  const backupKey = unlockManagedBackupKey(path.join(source, ".keyclasp.key"), path.join(source, "vault.db"), passphrase);
  const { mac, ...payload } = manifest;
  const expectedMac = manifestMac(payload, backupKey);
  const actualMac = Buffer.from(mac, "base64");
  const expectedMacBytes = Buffer.from(expectedMac, "base64");
  if (actualMac.length !== expectedMacBytes.length || !crypto.timingSafeEqual(actualMac, expectedMacBytes)) {
    throw new Error("Managed backup manifest failed authentication. Live vault state was not changed.");
  }
  const hasPolicy = Boolean(manifest.files["strict-policy.v1.json"]);
  const hasPolicyAnchor = Boolean(manifest.files[".strict-policy.key"]);
  if (hasPolicy !== hasPolicyAnchor) throw new Error("Managed backup authorization policy is incomplete.");
  if (hasPolicy !== (databaseMetadata.policyGeneration !== null)) {
    throw new Error("Managed backup authorization-policy presence does not match its database anchor.");
  }
  if (hasPolicy) {
    if (!databaseMetadata.policyDocumentHash) throw new Error("Managed backup authorization-policy commitment is missing.");
    validateAuthorizationPolicyBackup(
      source,
      Buffer.from(manifest.vaultId, "base64"),
      databaseMetadata.policyGeneration!,
      databaseMetadata.policyDocumentHash,
    );
  }
  const vaultDir = getVaultLocation();
  ensureOwnerOnlyVaultDirectory();
  closeDb();
  clearKey();
  const transactionId = `${process.pid}.${crypto.randomBytes(6).toString("hex")}`;
  const staged = MANAGED_FILES.filter((name) => Boolean(manifest.files[name]));
  const previous: string[] = [];
  try {
    writeRestoreJournal({
      version: 1,
      phase: "staging",
      transactionId,
      staged,
      previous: [],
      stagedHashes: {},
      previousHashes: {},
    });
    for (const [index, name] of staged.entries()) {
      const stagePath = path.join(vaultDir, `${name}.${transactionId}.restore`);
      fs.copyFileSync(path.join(source, name), stagePath);
      if (index === 0 && _restoreFaultForTests === "crash-after-first-stage-copy") {
        throw new Error("Injected managed-restore crash after first staged copy.");
      }
      enforceOwnerOnlyPath(stagePath, { kind: "file", label: `managed restore staging file "${name}"` });
      if (sha256(stagePath) !== manifest.files[name]) throw new Error(`Staged restore file "${name}" failed verification.`);
      fsyncFile(stagePath);
    }
    fsyncDirectory(vaultDir);
    for (const name of MANAGED_FILES) {
      if (fs.existsSync(path.join(vaultDir, name))) previous.push(name);
    }
    writeRestoreJournal({
      version: 1,
      phase: "replacing",
      transactionId,
      staged,
      previous,
      stagedHashes: Object.fromEntries(staged.map((name) => [name, sha256(path.join(vaultDir, `${name}.${transactionId}.restore`))])),
      previousHashes: Object.fromEntries(previous.map((name) => [name, sha256(path.join(vaultDir, name))])),
    });
    if (_restoreFaultForTests === "crash-after-journal") throw new Error("Injected managed-restore crash after journal publication.");
    for (const [index, name] of previous.entries()) {
      const livePath = path.join(vaultDir, name);
      const previousPath = `${livePath}.${transactionId}.previous`;
      fs.renameSync(livePath, previousPath);
      enforceOwnerOnlyPath(previousPath, { kind: "file", label: `managed restore prior file "${name}"` });
      if (index === 0 && _restoreFaultForTests === "crash-after-first-previous") throw new Error("Injected managed-restore crash after first live rename.");
    }
    fsyncDirectory(vaultDir);
    if (_restoreFaultForTests === "crash-after-previous-fsync") throw new Error("Injected managed-restore crash after prior-file publication.");
    for (const [index, name] of staged.entries()) {
      fs.renameSync(path.join(vaultDir, `${name}.${transactionId}.restore`), path.join(vaultDir, name));
      enforceOwnerOnlyPath(path.join(vaultDir, name), { kind: "file", label: `restored vault file "${name}"` });
      if (index === 0 && _restoreFaultForTests === "crash-after-first-publish") throw new Error("Injected managed-restore crash after first staged publication.");
    }
    fsyncDirectory(vaultDir);
    if (_restoreFaultForTests === "crash-after-all-published") throw new Error("Injected managed-restore crash after complete staged publication.");
    writeRestoreJournal({
      version: 1,
      phase: "committed",
      transactionId,
      staged,
      previous,
      stagedHashes: Object.fromEntries(staged.map((name) => [name, sha256(path.join(vaultDir, name))])),
      previousHashes: Object.fromEntries(previous.map((name) => [name, sha256(path.join(vaultDir, `${name}.${transactionId}.previous`))])),
    });
    if (_restoreFaultForTests === "crash-after-commit-journal") throw new Error("Injected managed-restore crash after commit journal publication.");
  } catch (error) {
    if (_restoreFaultForTests?.startsWith("crash-")) throw error;
    if (fs.existsSync(restoreJournalPath())) recoverInterruptedManagedRestore();
    else for (const name of staged) {
      const stagePath = path.join(vaultDir, `${name}.${transactionId}.restore`);
      if (fs.existsSync(stagePath)) fs.unlinkSync(stagePath);
    }
    if (!fs.existsSync(restoreJournalPath())) fsyncDirectory(vaultDir);
    throw error;
  }
  const cleanupWarnings: string[] = [];
  for (const name of previous) {
    const previousPath = path.join(vaultDir, `${name}.${transactionId}.previous`);
    try {
      fs.unlinkSync(previousPath);
    } catch (error) {
      cleanupWarnings.push(`Old file cleanup failed at "${previousPath}": ${error instanceof Error ? error.message : "unknown error"}`);
    }
  }
  try {
    fsyncDirectory(vaultDir);
    if (cleanupWarnings.length === 0) {
      fs.unlinkSync(restoreJournalPath());
      fsyncDirectory(vaultDir);
    }
  } catch (error) {
    cleanupWarnings.push(`Managed restore cleanup could not be made durable: ${error instanceof Error ? error.message : "unknown error"}`);
  }
  return { manifest, cleanupWarnings };
}

export function setRestoreFaultForTests(fault: RestoreFault | null): void {
  _restoreFaultForTests = fault;
}

export function setBackupFaultForTests(fault: BackupFault | null): void {
  _backupFaultForTests = fault;
}
