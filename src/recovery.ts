import crypto from "node:crypto";
import Database from "better-sqlite3";
import fs from "node:fs";
import path from "node:path";
import {
  closeDb,
  clearKey,
  ensureOwnerOnlyVaultDirectory,
  getManagedBackupKeys,
  getVaultDescriptor,
  getVaultLocation,
  preparePortableInteractiveRestore,
  summarizeKeyClasses,
  unlockManagedBackupKeys,
  validateManagedVaultContents,
  validateLiveVaultSemanticsForRestore,
  VaultSemanticDamageError,
} from "./vault.js";
import { AUTHORIZATION_POLICY_BACKUP_FILES, authorizationPolicyFiles, validateAuthorizationPolicyBackup, validateLiveAuthorizationPolicy } from "./policy.js";
import { assertOwnerOnlyPath, enforceOwnerOnlyPath } from "./owner-only-path.js";
import type { OperatorAuthorization, OperatorAuthorizer } from "./runtime.js";
import {
  DamagedLiveDatabaseError,
  SQLITE_LIVE_FILES,
  VaultWriterExclusionError,
  assertNoExternalVaultClients,
  assertExactVaultFilesUnchanged,
  assertRollbackOperationsReconciliable,
  assertVaultFilesUnchanged,
  fsyncDirectory,
  fsyncFile,
  hasSQLiteHeader,
  quiesceSqliteCopy,
  reconcileFileOperation,
  sha256File,
  snapshotExactVaultFiles,
  snapshotVaultFiles,
  validatePublishedSqlite,
  type VaultFileFaultPoint,
  type VaultFileOperation,
  type VaultFileSnapshot,
} from "./vault-files.js";

const BACKUP_VERSION = 2;
const MANAGED_FILES = ["vault.db", ".keyclasp.key", ...AUTHORIZATION_POLICY_BACKUP_FILES] as const;
const CLASSIFICATION_SQLITE_FILES = [".classification-vault.db", ".classification-vault.db-wal", ".classification-vault.db-shm"] as const;
const PORTABLE_SQLITE_SIDECARS = ["vault.db.portable-journal", "vault.db.portable-wal", "vault.db.portable-shm"] as const;
const LEGACY_RESTORE_JOURNAL = ".restore-transaction.v1.json";
const RECOVERY_METADATA_FILES = [
  ".strict-policy.pending",
  ".custody-transaction.v1.json",
  ".dual-key-migration.v1.json",
  ".dual-key-migration.key",
  ".restore-journal.key",
  LEGACY_RESTORE_JOURNAL,
] as const;
const PENDING_RECOVERY_TRIGGER_FILES = RECOVERY_METADATA_FILES.filter((name) => name !== ".dual-key-migration.key");
type RestoreFault =
  | "crash-after-first-stage-copy"
  | "crash-during-portable-conversion"
  | "crash-during-open-portable-conversion"
  | "crash-after-journal"
  | "crash-after-first-previous"
  | "crash-after-previous-fsync"
  | "crash-after-first-publish"
  | "crash-after-all-published"
  | "crash-after-commit-journal";
let _restoreFaultForTests: RestoreFault | null = null;
let _restoreOperationFaultForTests: { occurrence: number; point: VaultFileFaultPoint } | null = null;
let _restoreOperationCount = 0;
export type RestorePrimitive = "copy" | "journal" | "rename" | "unlink" | "sync" | "validation" | "directory-cleanup";
let _restorePrimitiveFaultForTests: { primitive: RestorePrimitive; occurrence: number; point: VaultFileFaultPoint } | null = null;
let _restorePrimitiveCounts: Partial<Record<RestorePrimitive, number>> = {};
let _restorePrimitiveFaultTriggered = false;
type BackupFault = "crash-before-backup-publish" | "crash-after-backup-publish";
let _backupFaultForTests: BackupFault | null = null;

function beginRestorePrimitive(primitive: RestorePrimitive): number {
  const occurrence = (_restorePrimitiveCounts[primitive] ?? 0) + 1;
  _restorePrimitiveCounts[primitive] = occurrence;
  return occurrence;
}

function injectRestorePrimitiveFault(primitive: RestorePrimitive, occurrence: number, point: VaultFileFaultPoint): void {
  const fault = _restorePrimitiveFaultForTests;
  if (!fault || fault.primitive !== primitive || fault.occurrence !== occurrence || fault.point !== point) return;
  _restorePrimitiveFaultTriggered = true;
  throw new Error(`Injected managed-restore ${primitive} ${point} interruption at occurrence ${occurrence}.`);
}

function runRestorePrimitive<T>(
  primitive: RestorePrimitive,
  mutation: () => T,
  persistCompletion: () => void = () => {},
): T {
  const occurrence = beginRestorePrimitive(primitive);
  injectRestorePrimitiveFault(primitive, occurrence, "before-mutation");
  const result = mutation();
  injectRestorePrimitiveFault(primitive, occurrence, "after-mutation");
  persistCompletion();
  injectRestorePrimitiveFault(primitive, occurrence, "after-completion");
  return result;
}

function restoreFsyncFile(filePath: string): void {
  runRestorePrimitive("sync", () => fsyncFile(filePath));
}

function restoreFsyncDirectory(directory: string): void {
  runRestorePrimitive("sync", () => fsyncDirectory(directory));
}

interface RestoreJournal {
  version: 2;
  phase: "staging" | "publishing" | "rollback" | "committed" | "staging-cleanup" | "rollback-cleanup" | "committed-cleanup";
  branch: "healthy" | "damaged";
  transactionId: string;
  stagingDirectory: string;
  previousDirectory: string;
  transactionDirectories: string[];
  stagedHashes: Record<string, string>;
  previousHashes: Record<string, string>;
  operations: VaultFileOperation[];
  mac: string;
}

type BackupKeyClass = "machine" | "interactive";

interface BackupManifest {
  version: 2;
  createdAt: string;
  vaultId: string;
  custody: "machine-only" | "dual-key";
  bundleGeneration: number;
  recordClasses: Record<BackupKeyClass, number>;
  files: Record<string, string>;
  authenticators: Partial<Record<BackupKeyClass, string>>;
}

interface ManagedRestoreResult {
  manifest: BackupManifest;
  cleanupWarnings: string[];
  rollbackEvidencePath?: string;
}

function manifestPayload(manifest: Omit<BackupManifest, "authenticators">): string {
  return JSON.stringify({
    version: manifest.version,
    createdAt: manifest.createdAt,
    vaultId: manifest.vaultId,
    custody: manifest.custody,
    bundleGeneration: manifest.bundleGeneration,
    recordClasses: {
      machine: manifest.recordClasses.machine,
      interactive: manifest.recordClasses.interactive,
    },
    files: Object.fromEntries(Object.entries(manifest.files).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)),
  });
}

function manifestAuthenticator(
  manifest: Omit<BackupManifest, "authenticators">,
  keyClass: BackupKeyClass,
  key: Buffer,
): string {
  return crypto.createHmac("sha256", key)
    .update(`keyclasp:managed-backup:v2:${keyClass}\0`)
    .update(manifestPayload(manifest))
    .digest("base64");
}

function requiredAuthenticatorClasses(manifest: Pick<BackupManifest, "custody" | "recordClasses">): BackupKeyClass[] {
  const total = manifest.recordClasses.machine + manifest.recordClasses.interactive;
  const required: BackupKeyClass[] = [];
  if (manifest.recordClasses.machine > 0 || total === 0) required.push("machine");
  if (manifest.recordClasses.interactive > 0 || (total === 0 && manifest.custody === "dual-key")) required.push("interactive");
  return required;
}

function exactAuthenticatorClasses(manifest: BackupManifest): boolean {
  const actual = Object.keys(manifest.authenticators).sort();
  const expected = requiredAuthenticatorClasses(manifest).sort();
  return actual.length === expected.length && actual.every((value, index) => value === expected[index]);
}

function strictBase64Bytes(value: unknown, length: number): boolean {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return false;
  const decoded = Buffer.from(value, "base64");
  return decoded.length === length && decoded.toString("base64") === value;
}

function timingSafeBase64Equal(actual: string, expected: string): boolean {
  const actualBytes = Buffer.from(actual, "base64");
  const expectedBytes = Buffer.from(expected, "base64");
  return actualBytes.length === expectedBytes.length && crypto.timingSafeEqual(actualBytes, expectedBytes);
}

function restoreJournalKeyName(transactionId: string): string {
  return `.restore-journal.v2.${transactionId}.key`;
}

function restoreJournalKeyNames(): string[] {
  const vaultDir = getVaultLocation();
  if (!fs.existsSync(vaultDir)) return [];
  return fs.readdirSync(vaultDir).filter((name) => /^\.restore-journal\.v2\.[A-Za-z0-9.]+\.key$/.test(name)).sort();
}

function restoreJournalKey(transactionId: string, create: boolean): Buffer {
  const keyPath = path.join(getVaultLocation(), restoreJournalKeyName(transactionId));
  if (!fs.existsSync(keyPath) && create) {
    fs.writeFileSync(keyPath, crypto.randomBytes(32), { mode: 0o600, flag: "wx" });
    restoreFsyncFile(keyPath);
    restoreFsyncDirectory(getVaultLocation());
  }
  if (!fs.existsSync(keyPath)) throw new Error("Managed-restore transaction key is missing.");
  assertOwnerOnlyPath(keyPath, { kind: "file", label: "managed-restore journal key" });
  const key = fs.readFileSync(keyPath);
  if (key.length !== 32) throw new Error("Managed-restore transaction key is corrupt.");
  return key;
}

function restoreJournalPayload(journal: Omit<RestoreJournal, "mac">): string {
  return JSON.stringify(journal);
}

function restoreJournalMac(journal: Omit<RestoreJournal, "mac">, createKey: boolean): string {
  return crypto.createHmac("sha256", restoreJournalKey(journal.transactionId, createKey))
    .update("keyclasp:restore-journal:v2\0")
    .update(restoreJournalPayload(journal))
    .digest("base64");
}

function restoreJournalName(transactionId: string): string {
  return `.restore-transaction.v2.${transactionId}.json`;
}

function restoreJournalTemporaryName(transactionId: string): string {
  return `.restore-transaction.v2.${transactionId}.tmp`;
}

function restoreJournalPath(transactionId: string): string {
  return path.join(getVaultLocation(), restoreJournalName(transactionId));
}

function restoreJournalNames(): string[] {
  const vaultDir = getVaultLocation();
  if (!fs.existsSync(vaultDir)) return [];
  return fs.readdirSync(vaultDir).filter((name) => /^\.restore-transaction\.v2\.[A-Za-z0-9.]+\.json$/.test(name)).sort();
}

function restoreJournalTemporaryNames(): string[] {
  const vaultDir = getVaultLocation();
  if (!fs.existsSync(vaultDir)) return [];
  return fs.readdirSync(vaultDir).filter((name) => /^\.restore-transaction\.v2\.[A-Za-z0-9.]+\.tmp$/.test(name)).sort();
}

function journalSqlitePaths(journal: RestoreJournal): string[] {
  const sqliteNames = new Set<string>(SQLITE_LIVE_FILES);
  const paths: string[] = [...SQLITE_LIVE_FILES];
  for (const operation of journal.operations) {
    if (operation.kind !== "rename") continue;
    if (sqliteNames.has(path.basename(operation.from))) paths.push(operation.from);
    if (sqliteNames.has(path.basename(operation.to))) paths.push(operation.to);
  }
  return [...new Set(paths)];
}

function transactionIdFromJournalName(name: string): string {
  const match = name.match(/^\.restore-transaction\.v2\.([A-Za-z0-9.]+)\.json$/);
  if (!match) throw new Error("Managed restore contains an invalid journal name.");
  return match[1]!;
}

function isTransactionDirectoryName(name: string): boolean {
  return /^\.restore-(?:staging|previous|damaged-evidence)\.[A-Za-z0-9.]+$/.test(name);
}

function isAllowedTransactionLeaf(name: string): boolean {
  return (MANAGED_FILES as readonly string[]).includes(name) ||
    (RECOVERY_METADATA_FILES as readonly string[]).includes(name) ||
    /^\.restore-transaction\.v2\.[A-Za-z0-9.]+\.json$/.test(name) ||
    /^\.restore-transaction\.v2\.[A-Za-z0-9.]+\.tmp$/.test(name) ||
    /^\.restore-journal\.v2\.[A-Za-z0-9.]+\.key$/.test(name) ||
    (CLASSIFICATION_SQLITE_FILES as readonly string[]).includes(name) ||
    (PORTABLE_SQLITE_SIDECARS as readonly string[]).includes(name) ||
    /^(?:vault\.db|\.keyclasp\.key|strict-policy\.v1\.json|\.strict-policy\.key)\.(?:partial|portable)$/.test(name);
}

function pendingTransactionMaterial(journalNames: readonly string[]): { files: string[]; directories: string[] } {
  const vaultDir = getVaultLocation();
  const files: string[] = [];
  const directories: string[] = [];
  const walk = (relativeDirectory: string, depth: number): void => {
    if (depth > 16) throw new Error("Managed restore transaction nesting exceeds the recovery limit.");
    const directoryPath = path.join(vaultDir, relativeDirectory);
    enforceOwnerOnlyPath(directoryPath, { kind: "directory", label: `managed restore transaction directory \"${relativeDirectory}\"` });
    directories.push(relativeDirectory);
    for (const entry of fs.readdirSync(directoryPath, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name))) {
      const relative = `${relativeDirectory}/${entry.name}`;
      if (entry.isDirectory() && isTransactionDirectoryName(entry.name)) {
        walk(relative, depth + 1);
      } else if (entry.isFile() && isAllowedTransactionLeaf(entry.name)) {
        assertOwnerOnlyPath(path.join(vaultDir, relative), { kind: "file", label: `managed restore transaction file \"${entry.name}\"` });
        files.push(relative);
      } else {
        throw new Error(`Managed restore transaction directory \"${relativeDirectory}\" contains an unknown entry.`);
      }
    }
  };
  for (const journalName of journalNames) {
    const transactionId = transactionIdFromJournalName(journalName);
    for (const prefix of [".restore-staging", ".restore-previous", ".restore-damaged-evidence"] as const) {
      const directory = `${prefix}.${transactionId}`;
      const directoryPath = path.join(vaultDir, directory);
      if (!fs.existsSync(directoryPath)) continue;
      walk(directory, 1);
    }
  }
  return { files: [...new Set(files)].sort(), directories: [...new Set(directories)].sort() };
}

function prepareEvidenceParents(vaultDir: string, previousDirectory: string, directories: readonly string[]): void {
  for (const directory of [...directories].sort((left, right) => left.split("/").length - right.split("/").length || left.localeCompare(right))) {
    const target = path.join(vaultDir, previousDirectory, directory);
    fs.mkdirSync(target, { mode: 0o700 });
    enforceOwnerOnlyPath(target, { kind: "directory", label: `managed restore evidence directory \"${directory}\"` });
  }
  if (directories.length > 0) restoreFsyncDirectory(path.join(vaultDir, previousDirectory));
}

function isRecognizedRollbackName(name: string): boolean {
  if ((MANAGED_FILES as readonly string[]).includes(name) ||
    (SQLITE_LIVE_FILES.slice(1) as readonly string[]).includes(name) ||
    (RECOVERY_METADATA_FILES as readonly string[]).includes(name) ||
    /^\.restore-transaction\.v2\.[A-Za-z0-9.]+\.json$/.test(name) ||
    /^\.restore-transaction\.v2\.[A-Za-z0-9.]+\.tmp$/.test(name) ||
    /^\.restore-journal\.v2\.[A-Za-z0-9.]+\.key$/.test(name)) return true;
  const segments = name.split("/");
  return segments.length > 1 && segments.slice(0, -1).every(isTransactionDirectoryName) && isAllowedTransactionLeaf(segments.at(-1)!);
}

function hasExactTransactionDirectories(journal: RestoreJournal): boolean {
  if (!Array.isArray(journal.transactionDirectories)) return false;
  const sorted = [...journal.transactionDirectories].sort();
  return sorted.length === new Set(sorted).size &&
    sorted.every((name, index) => name === journal.transactionDirectories[index] && name.split("/").every(isTransactionDirectoryName));
}

function hasExactJournalOperations(journal: RestoreJournal): boolean {
  const previousEntries = Object.entries(journal.previousHashes);
  const stagedEntries = Object.entries(journal.stagedHashes);
  if (previousEntries.some(([name, hash]) => !isRecognizedRollbackName(name) || !/^[a-f0-9]{64}$/.test(hash)) ||
      stagedEntries.some(([name, hash]) => !(MANAGED_FILES as readonly string[]).includes(name) || !/^[a-f0-9]{64}$/.test(hash))) return false;
  if (journal.phase === "staging") return journal.operations.length === 0;
  if (journal.phase === "staging-cleanup") {
    const expected = [
      ...CLASSIFICATION_SQLITE_FILES.map((name): VaultFileOperation => ({
        kind: "unlink",
        path: `${journal.stagingDirectory}/${name}`,
        hash: "",
        unverifiedTransactionFile: true,
        completed: false,
      })),
      ...PORTABLE_SQLITE_SIDECARS.map((name): VaultFileOperation => ({
        kind: "unlink",
        path: `${journal.stagingDirectory}/${name}`,
        hash: "",
        unverifiedTransactionFile: true,
        completed: false,
      })),
      ...stagedEntries.flatMap(([name]): VaultFileOperation[] => [".partial", ".portable", ""].map((suffix) => ({
      kind: "unlink",
      path: `${journal.stagingDirectory}/${name}${suffix}`,
      hash: "",
      unverifiedTransactionFile: true,
      completed: false,
      }))),
    ];
    if (journal.operations.length !== expected.length) return false;
    return expected.every((item, index) => {
      const actual = journal.operations[index];
      if (!actual || actual.kind !== "unlink" || typeof actual.completed !== "boolean") return false;
      const { completed: _expectedCompleted, ...expectedIdentity } = item;
      const { completed: _actualCompleted, ...actualIdentity } = actual;
      return JSON.stringify(actualIdentity) === JSON.stringify(expectedIdentity);
    });
  }
  if (journal.phase === "rollback-cleanup" || journal.phase === "committed-cleanup") {
    const expected: VaultFileOperation[] = [
      ...stagedEntries.map(([name]): VaultFileOperation => ({
        kind: "unlink",
        path: `${journal.stagingDirectory}/${name}.partial`,
        hash: "",
        unverifiedTransactionFile: true,
        completed: false,
      })),
      ...stagedEntries.map(([name, hash]) => ({
        kind: "unlink" as const,
        path: `${journal.stagingDirectory}/${name}`,
        hash,
        completed: false,
      })),
      ...(journal.phase === "committed-cleanup" && journal.branch === "healthy" ? previousEntries.map(([name, hash]) => ({
        kind: "unlink" as const,
        path: `${journal.previousDirectory}/${name}`,
        hash,
        completed: false,
      })) : []),
    ];
    if (journal.operations.length !== expected.length) return false;
    return expected.every((item, index) => {
      const actual = journal.operations[index];
      if (!actual || actual.kind !== "unlink" || typeof actual.completed !== "boolean") return false;
      const { completed: _expectedCompleted, ...expectedIdentity } = item;
      const { completed: _actualCompleted, ...actualIdentity } = actual;
      return JSON.stringify(actualIdentity) === JSON.stringify(expectedIdentity);
    });
  }
  if (journal.operations.length !== previousEntries.length + stagedEntries.length) return false;
  const expected: VaultFileOperation[] = [
    ...previousEntries.map(([name, hash]) => ({
      kind: "rename" as const,
      from: name,
      to: `${journal.previousDirectory}/${name}`,
      hash,
      completed: false,
    })),
    ...stagedEntries.map(([name, hash]) => ({
      kind: "rename" as const,
      from: `${journal.stagingDirectory}/${name}`,
      to: name,
      hash,
      ...(journal.previousHashes[name] ? { rollbackDestinationHash: journal.previousHashes[name] } : {}),
      completed: false,
    })),
  ];
  return expected.every((item, index) => {
    const actual = journal.operations[index];
    if (!actual || actual.kind !== "rename" || typeof actual.completed !== "boolean") return false;
    const { completed: _expectedCompleted, ...expectedIdentity } = item;
    const { completed: _actualCompleted, ...actualIdentity } = actual;
    return JSON.stringify(actualIdentity) === JSON.stringify(expectedIdentity);
  });
}

function writeRestoreJournal(payload: Omit<RestoreJournal, "mac">): void {
  const journalPath = restoreJournalPath(payload.transactionId);
  const journal: RestoreJournal = { ...payload, mac: restoreJournalMac(payload, true) };
  const temporaryPath = path.join(getVaultLocation(), restoreJournalTemporaryName(payload.transactionId));
  try {
    fs.writeFileSync(temporaryPath, `${JSON.stringify(journal)}\n`, { mode: 0o600 });
    enforceOwnerOnlyPath(temporaryPath, { kind: "file", label: "managed-restore journal staging file" });
    restoreFsyncFile(temporaryPath);
    runRestorePrimitive("rename", () => fs.renameSync(temporaryPath, journalPath));
  } catch (error) {
    if (fs.existsSync(temporaryPath)) removeExactFile(temporaryPath);
    throw error;
  }
  enforceOwnerOnlyPath(journalPath, { kind: "file", label: "managed-restore journal" });
  restoreFsyncDirectory(getVaultLocation());
}

function readRestoreJournal(journalPath: string): RestoreJournal {
  assertOwnerOnlyPath(journalPath, { kind: "file", label: "managed-restore journal" });
  let journal: RestoreJournal;
  try {
    journal = JSON.parse(fs.readFileSync(journalPath, "utf8")) as RestoreJournal;
  } catch {
    throw new Error("Managed-restore journal is corrupt. Recover the vault directory from a trusted backup.");
  }
  if (journal.version !== 2 || !["staging", "publishing", "rollback", "committed", "staging-cleanup", "rollback-cleanup", "committed-cleanup"].includes(journal.phase) ||
      !/^[A-Za-z0-9.]+$/.test(journal.transactionId) || path.basename(journalPath) !== restoreJournalName(journal.transactionId) ||
      journal.stagingDirectory !== `.restore-staging.${journal.transactionId}` ||
      ![`.restore-previous.${journal.transactionId}`, `.restore-damaged-evidence.${journal.transactionId}`].includes(journal.previousDirectory) ||
      !Array.isArray(journal.operations) || !journal.stagedHashes || !journal.previousHashes ||
      !hasExactTransactionDirectories(journal) ||
      !hasExactJournalOperations(journal) || typeof journal.mac !== "string") {
    throw new Error("Managed-restore journal is invalid. Recover the vault directory from a trusted backup.");
  }
  const { mac, ...payload } = journal;
  const expectedMac = Buffer.from(restoreJournalMac(payload, false), "base64");
  const actualMac = Buffer.from(mac, "base64");
  if (actualMac.length !== expectedMac.length || !crypto.timingSafeEqual(actualMac, expectedMac)) {
    throw new Error("Managed-restore journal failed authentication. Recover the vault directory from a trusted backup.");
  }
  return journal;
}

function persistJournal(journal: RestoreJournal): void {
  const { mac: _mac, ...payload } = journal;
  let nextMac = "";
  runRestorePrimitive(
    "journal",
    () => {
      writeRestoreJournal(payload);
      nextMac = restoreJournalMac(payload, false);
    },
    () => { journal.mac = nextMac; },
  );
}

const restorePrimitiveOperationOccurrences = new WeakMap<VaultFileOperation, number>();

function maybeInjectOperationFault(point: VaultFileFaultPoint, operation: VaultFileOperation): void {
  let primitiveOccurrence = restorePrimitiveOperationOccurrences.get(operation);
  if (point === "before-mutation") {
    primitiveOccurrence = beginRestorePrimitive(operation.kind);
    restorePrimitiveOperationOccurrences.set(operation, primitiveOccurrence);
  }
  if (primitiveOccurrence !== undefined) injectRestorePrimitiveFault(operation.kind, primitiveOccurrence, point);
  if (_restoreOperationFaultForTests && _restoreOperationFaultForTests.point === point) {
    _restoreOperationCount += 1;
    if (_restoreOperationCount === _restoreOperationFaultForTests.occurrence) {
      throw new Error(`Injected managed-restore ${point} interruption.`);
    }
  }
}

function removeExactFile(filePath: string, expectedHash?: string): void {
  if (!fs.existsSync(filePath)) return;
  assertOwnerOnlyPath(filePath, { kind: "file", label: `managed restore cleanup file \"${path.basename(filePath)}\"` });
  if (expectedHash && sha256File(filePath) !== expectedHash) {
    throw new Error(`Managed restore cleanup file \"${path.basename(filePath)}\" failed authentication.`);
  }
  runRestorePrimitive("unlink", () => fs.unlinkSync(filePath));
}

function removeDirectoryIfEmpty(directory: string): void {
  if (!fs.existsSync(directory)) return;
  enforceOwnerOnlyPath(directory, { kind: "directory", label: `managed restore directory \"${path.basename(directory)}\"` });
  if (fs.readdirSync(directory).length !== 0) throw new Error(`Managed restore directory \"${path.basename(directory)}\" contains unknown files.`);
  runRestorePrimitive("directory-cleanup", () => fs.rmdirSync(directory));
}

function cleanupOperations(journal: RestoreJournal, disposition: "staging" | "rollback" | "committed"): VaultFileOperation[] {
  if (disposition === "staging") {
    return [
      ...CLASSIFICATION_SQLITE_FILES.map((name): VaultFileOperation => ({
        kind: "unlink",
        path: `${journal.stagingDirectory}/${name}`,
        hash: "",
        unverifiedTransactionFile: true,
        completed: false,
      })),
      ...PORTABLE_SQLITE_SIDECARS.map((name): VaultFileOperation => ({
        kind: "unlink",
        path: `${journal.stagingDirectory}/${name}`,
        hash: "",
        unverifiedTransactionFile: true,
        completed: false,
      })),
      ...Object.keys(journal.stagedHashes).flatMap((name): VaultFileOperation[] => [".partial", ".portable", ""].map((suffix) => ({
        kind: "unlink",
        path: `${journal.stagingDirectory}/${name}${suffix}`,
        hash: "",
        unverifiedTransactionFile: true,
        completed: false,
      }))),
    ];
  }
  return [
    ...Object.keys(journal.stagedHashes).map((name): VaultFileOperation => ({
      kind: "unlink",
      path: `${journal.stagingDirectory}/${name}.partial`,
      hash: "",
      unverifiedTransactionFile: true,
      completed: false,
    })),
    ...Object.entries(journal.stagedHashes).map(([name, hash]): VaultFileOperation => ({
      kind: "unlink",
      path: `${journal.stagingDirectory}/${name}`,
      hash,
      completed: false,
    })),
    ...(disposition === "committed" && journal.branch === "healthy" ? Object.entries(journal.previousHashes).map(([name, hash]): VaultFileOperation => ({
      kind: "unlink",
      path: `${journal.previousDirectory}/${name}`,
      hash,
      completed: false,
    })) : []),
  ];
}

function finishCleanupJournal(journal: RestoreJournal): void {
  const vaultDir = getVaultLocation();
  for (const operation of journal.operations) {
    reconcileFileOperation(vaultDir, operation, "forward", () => persistJournal(journal), maybeInjectOperationFault, restoreFsyncDirectory);
  }
  for (const directory of [...journal.transactionDirectories].sort().reverse()) {
    if (journal.phase === "staging-cleanup" || journal.phase === "rollback-cleanup") {
      removeDirectoryIfEmpty(path.join(vaultDir, journal.previousDirectory, directory));
    } else {
      removeDirectoryIfEmpty(path.join(vaultDir, directory));
    }
  }
  removeDirectoryIfEmpty(path.join(vaultDir, journal.stagingDirectory));
  if (journal.phase === "staging-cleanup" || journal.phase === "rollback-cleanup" || journal.branch === "healthy") {
    removeDirectoryIfEmpty(path.join(vaultDir, journal.previousDirectory));
  }
  restoreFsyncDirectory(vaultDir);
  const journalPath = restoreJournalPath(journal.transactionId);
  assertOwnerOnlyPath(journalPath, { kind: "file", label: "managed-restore journal" });
  runRestorePrimitive("unlink", () => fs.unlinkSync(journalPath));
  restoreFsyncDirectory(vaultDir);
  const keyPath = path.join(vaultDir, restoreJournalKeyName(journal.transactionId));
  assertOwnerOnlyPath(keyPath, { kind: "file", label: "managed-restore transaction key" });
  runRestorePrimitive("unlink", () => fs.unlinkSync(keyPath));
  restoreFsyncDirectory(vaultDir);
}

function beginCleanupJournal(journal: RestoreJournal, disposition: "staging" | "rollback" | "committed"): void {
  journal.operations = cleanupOperations(journal, disposition);
  journal.phase = disposition === "staging" ? "staging-cleanup" : disposition === "rollback" ? "rollback-cleanup" : "committed-cleanup";
  persistJournal(journal);
  finishCleanupJournal(journal);
}

function rollbackJournal(journal: RestoreJournal): void {
  const vaultDir = getVaultLocation();
  if (journal.phase === "staging") {
    beginCleanupJournal(journal, "staging");
    return;
  }
  assertRollbackOperationsReconciliable(vaultDir, journal.operations, journal.stagedHashes);
  journal.phase = "rollback";
  persistJournal(journal);
  for (const operation of [...journal.operations].reverse()) {
    reconcileFileOperation(vaultDir, operation, "rollback", () => persistJournal(journal), maybeInjectOperationFault, restoreFsyncDirectory);
  }
  beginCleanupJournal(journal, "rollback");
}

function finishCommittedJournal(journal: RestoreJournal): void {
  const vaultDir = getVaultLocation();
  for (const [name, hash] of Object.entries(journal.stagedHashes)) {
    const livePath = path.join(vaultDir, name);
    if (!fs.existsSync(livePath) || sha256File(livePath) !== hash) {
      throw new Error(`Managed-restore committed file \"${name}\" failed journal authentication.`);
    }
  }
  beginCleanupJournal(journal, "committed");
}

export function recoverInterruptedManagedRestore(): boolean {
  const journals = restoreJournalNames();
  const temporaryJournals = restoreJournalTemporaryNames();
  if (journals.length === 0) {
    if (fs.existsSync(path.join(getVaultLocation(), LEGACY_RESTORE_JOURNAL))) {
      throw new Error("A legacy managed-restore journal requires authenticated emergency restore.");
    }
    let cleaned = false;
    for (const temporaryName of temporaryJournals) {
      removeExactFile(path.join(getVaultLocation(), temporaryName));
      cleaned = true;
    }
    for (const keyName of restoreJournalKeyNames()) {
      const keyPath = path.join(getVaultLocation(), keyName);
      assertOwnerOnlyPath(keyPath, { kind: "file", label: "orphan managed-restore transaction key" });
      if (fs.statSync(keyPath).size !== 32) throw new Error("Orphan managed-restore transaction key is corrupt.");
      runRestorePrimitive("unlink", () => fs.unlinkSync(keyPath));
      cleaned = true;
    }
    if (cleaned) restoreFsyncDirectory(getVaultLocation());
    return cleaned;
  }
  if (journals.length !== 1) throw new Error("Multiple managed-restore journals require authenticated emergency restore.");
  for (const temporaryName of temporaryJournals) removeExactFile(path.join(getVaultLocation(), temporaryName));
  if (temporaryJournals.length > 0) restoreFsyncDirectory(getVaultLocation());
  const journal = readRestoreJournal(path.join(getVaultLocation(), journals[0]!));
  if (journal.phase === "publishing" || journal.phase === "rollback") {
    assertNoExternalVaultClients(getVaultLocation(), journalSqlitePaths(journal));
  }
  if (journal.phase === "committed") finishCommittedJournal(journal);
  else if (journal.phase === "staging-cleanup" || journal.phase === "rollback-cleanup" || journal.phase === "committed-cleanup") finishCleanupJournal(journal);
  else rollbackJournal(journal);
  return true;
}

export function hasInterruptedManagedRestore(): boolean {
  return restoreJournalNames().length > 0 || restoreJournalTemporaryNames().length > 0 || restoreJournalKeyNames().length > 0 || fs.existsSync(path.join(getVaultLocation(), LEGACY_RESTORE_JOURNAL));
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

function validateManifestShape(manifest: BackupManifest): void {
  if (manifest.version !== BACKUP_VERSION || !strictBase64Bytes(manifest.vaultId, 16) ||
      (manifest.custody !== "machine-only" && manifest.custody !== "dual-key") ||
      !Number.isSafeInteger(manifest.bundleGeneration) || manifest.bundleGeneration < 1 ||
      !manifest.recordClasses || !Number.isSafeInteger(manifest.recordClasses.machine) || manifest.recordClasses.machine < 0 ||
      !Number.isSafeInteger(manifest.recordClasses.interactive) || manifest.recordClasses.interactive < 0 ||
      !manifest.files || !manifest.authenticators || typeof manifest.createdAt !== "string") {
    throw new Error("Managed backup manifest is unsupported or incomplete.");
  }
  const allowedKeys = new Set([
    "version", "createdAt", "vaultId", "custody", "bundleGeneration", "recordClasses", "files", "authenticators",
  ]);
  if (Object.keys(manifest).some((key) => !allowedKeys.has(key))) {
    throw new Error("Managed backup manifest contains an unknown field.");
  }
  if (Object.keys(manifest.recordClasses).sort().join(",") !== "interactive,machine" ||
      Object.keys(manifest.authenticators).some((key) => key !== "machine" && key !== "interactive") ||
      !exactAuthenticatorClasses(manifest) ||
      requiredAuthenticatorClasses(manifest).some((keyClass) => !strictBase64Bytes(manifest.authenticators[keyClass], 32))) {
    throw new Error("Managed backup manifest has invalid key-class authenticators.");
  }
  if (manifest.custody === "machine-only" && manifest.recordClasses.interactive !== 0) {
    throw new Error("Managed backup machine-only custody cannot contain interactive records.");
  }
  for (const [name, expectedHash] of Object.entries(manifest.files)) {
    if (!MANAGED_FILES.includes(name as typeof MANAGED_FILES[number]) || !/^[a-f0-9]{64}$/.test(expectedHash)) {
      throw new Error("Managed backup manifest contains an invalid file entry.");
    }
  }
  if (!manifest.files["vault.db"] || !manifest.files[".keyclasp.key"]) {
    throw new Error("Managed backup must contain vault.db and .keyclasp.key.");
  }
}

function readManifest(directory: string): BackupManifest {
  let manifest: BackupManifest;
  try {
    enforceOwnerOnlyPath(path.join(directory, "backup.json"), { kind: "file", label: "managed backup manifest" });
    manifest = JSON.parse(fs.readFileSync(path.join(directory, "backup.json"), "utf8")) as BackupManifest;
  } catch {
    throw new Error("Managed backup manifest is missing or corrupt.");
  }
  validateManifestShape(manifest);
  for (const [name, expectedHash] of Object.entries(manifest.files)) {
    const filePath = path.join(directory, name);
    if (fs.existsSync(filePath)) {
      enforceOwnerOnlyPath(filePath, { kind: "file", label: `managed backup file "${name}"` });
    }
    if (!fs.existsSync(filePath) || sha256File(filePath) !== expectedHash) {
      throw new Error(`Managed backup file "${name}" failed its integrity check.`);
    }
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

function copyLiveSqliteForClassification(
  vaultDir: string,
  stagingDirectory: string,
  inventory: readonly ReturnType<typeof snapshotExactVaultFiles>[number][],
): string {
  for (const [index, sourceName] of SQLITE_LIVE_FILES.entries()) {
    const source = inventory.find((item) => item.name === sourceName)?.file;
    if (!source) continue;
    const targetName = CLASSIFICATION_SQLITE_FILES[index]!;
    const targetPath = path.join(vaultDir, stagingDirectory, targetName);
    runRestorePrimitive("copy", () => fs.copyFileSync(path.join(vaultDir, sourceName), targetPath));
    enforceOwnerOnlyPath(targetPath, { kind: "file", label: `managed restore classification file \"${sourceName}\"` });
    restoreFsyncFile(targetPath);
  }
  restoreFsyncDirectory(path.join(vaultDir, stagingDirectory));
  assertExactVaultFilesUnchanged(vaultDir, inventory);
  return path.join(vaultDir, stagingDirectory, CLASSIFICATION_SQLITE_FILES[0]);
}

function validateCopiedLiveState(vaultDir: string, databasePath: string): void {
  try {
    validateLiveVaultSemanticsForRestore(databasePath, path.join(vaultDir, ".keyclasp.key"));
    const metadata = readDatabaseMetadata(databasePath);
    const hasDocument = fs.existsSync(path.join(vaultDir, "strict-policy.v1.json"));
    const hasAnchor = fs.existsSync(path.join(vaultDir, ".strict-policy.key"));
    const expectsPolicy = metadata.policyGeneration !== null;
    if (hasDocument !== hasAnchor || hasDocument !== expectsPolicy) {
      throw new Error("Keyclasp authorization policy does not match its database anchor.");
    }
    if (expectsPolicy) {
      if (!metadata.policyDocumentHash) throw new Error("Keyclasp authorization-policy commitment is missing.");
      validateAuthorizationPolicyBackup(
        vaultDir,
        Buffer.from(metadata.vaultId, "base64"),
        metadata.policyGeneration!,
        metadata.policyDocumentHash,
      );
    }
  } catch (error) {
    if (error instanceof VaultSemanticDamageError) throw error;
    if (typeof error === "object" && error !== null && "code" in error) {
      const code = String((error as { code?: unknown }).code ?? "");
      if (/SQLITE_(?:CORRUPT|NOTADB|FORMAT)/.test(code)) {
        throw new VaultSemanticDamageError(error instanceof Error ? error.message : "Live SQLite state is corrupt.");
      }
      if (code) throw error;
    }
    if (error instanceof Error && /Unsafe |owner-only|permission|ACL|changed during/.test(error.message)) throw error;
    throw new VaultSemanticDamageError(error instanceof Error ? error.message : "Live vault semantic validation failed.");
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
  validateManifestShape(manifest);
  return manifest;
}

function readDatabaseMetadata(databasePath: string): {
  vaultId: string;
  bundleGeneration: number;
  policyGeneration: number | null;
  policyDocumentHash: string | null;
} {
  const db = new Database(databasePath, { readonly: true, fileMustExist: true });
  try {
    const row = db.prepare("SELECT format_version, vault_id, bundle_generation FROM vault_metadata WHERE singleton = 1").get() as
      | { format_version: number; vault_id: Buffer; bundle_generation: number }
      | undefined;
    if (!row || row.format_version !== 3 || !Buffer.isBuffer(row.vault_id) || row.vault_id.length !== 16 ||
        !Number.isSafeInteger(row.bundle_generation) || row.bundle_generation < 1) {
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
    return { vaultId: row.vault_id.toString("base64"), bundleGeneration: row.bundle_generation, policyGeneration, policyDocumentHash };
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
    runRestorePrimitive("copy", () => fs.copyFileSync(path.join(vaultDir, ".keyclasp.key"), path.join(staging, ".keyclasp.key")));
    enforceOwnerOnlyPath(path.join(staging, ".keyclasp.key"), { kind: "file", label: "managed backup key" });
    for (const source of authorizationPolicyFiles()) {
      const target = path.join(staging, path.basename(source));
      runRestorePrimitive("copy", () => fs.copyFileSync(source, target));
      enforceOwnerOnlyPath(target, { kind: "file", label: `managed backup policy file "${path.basename(target)}"` });
    }
    const files: Record<string, string> = {};
    for (const name of MANAGED_FILES) {
      const filePath = path.join(staging, name);
      if (fs.existsSync(filePath)) files[name] = sha256File(filePath);
    }
    const recordClasses = summarizeKeyClasses(snapshotPath);
    const payload: Omit<BackupManifest, "authenticators"> = {
      version: BACKUP_VERSION,
      createdAt: new Date().toISOString(),
      vaultId: descriptor.vaultId.toString("base64"),
      custody: descriptor.custody,
      bundleGeneration: descriptor.generation,
      recordClasses,
      files,
    };
    const requiredClasses = requiredAuthenticatorClasses(payload);
    const keys = getManagedBackupKeys(requiredClasses);
    const authenticators: BackupManifest["authenticators"] = {};
    for (const keyClass of requiredClasses) {
      const key = keyClass === "machine" ? keys.machineKey : keys.interactiveKey;
      if (!key) throw new Error(`Managed backup requires the unlocked ${keyClass} data key.`);
      authenticators[keyClass] = manifestAuthenticator(payload, keyClass, key);
    }
    const manifest: BackupManifest = { ...payload, authenticators };
    assertManifestMatchesBackup(manifest, snapshotPath, keys);
    verifyManifestAuthenticators(manifest, keys);
    runRestorePrimitive("validation", () => validatePublishedSqlite(staging, (databasePath) => {
      validateManagedVaultContents(databasePath, path.join(staging, ".keyclasp.key"), keys);
    }, true));
    const metadata = readDatabaseMetadata(snapshotPath);
    if (manifest.files["strict-policy.v1.json"] && metadata.policyGeneration !== null) {
      validateAuthorizationPolicyBackup(staging, descriptor.vaultId, metadata.policyGeneration!, metadata.policyDocumentHash!);
    }
    const manifestPath = path.join(staging, "backup.json");
    fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
    enforceOwnerOnlyPath(manifestPath, { kind: "file", label: "managed backup manifest" });
    for (const name of [...Object.keys(files), "backup.json"]) restoreFsyncFile(path.join(staging, name));
    restoreFsyncDirectory(staging);
    if (_backupFaultForTests === "crash-before-backup-publish") throw new Error("Injected managed-backup crash before publication.");
    runRestorePrimitive("rename", () => fs.renameSync(staging, destination));
    published = true;
    enforceOwnerOnlyPath(destination, { kind: "directory", label: "managed backup directory" });
    if (_backupFaultForTests === "crash-after-backup-publish") throw new Error("Injected managed-backup crash after publication.");
    restoreFsyncDirectory(parent);
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
  return readManifestForAuthorization(source).authenticators.interactive ? "passphrase" : "machine";
}

export async function createManagedBackupAuthorized(
  destination: string,
  dependencies: {
    authorize: OperatorAuthorizer;
    ensureUnlocked: (authorizedPassphrase?: string) => Promise<void>;
    validatePolicy?: typeof validateLiveAuthorizationPolicy;
    create?: typeof createManagedBackup;
  },
): Promise<BackupManifest> {
  const authorization = await dependencies.authorize("Create a managed Keyclasp backup");
  (dependencies.validatePolicy ?? validateLiveAuthorizationPolicy)();
  const descriptor = getVaultDescriptor();
  const inventory = summarizeKeyClasses();
  const required = requiredAuthenticatorClasses({ custody: descriptor.custody, recordClasses: inventory });
  if (required.includes("interactive")) {
    await dependencies.ensureUnlocked(authorization.method === "passphrase" ? authorization.passphrase : undefined);
  }
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

function assertManifestMatchesBackup(
  manifest: BackupManifest,
  databasePath: string,
  keys: ReturnType<typeof unlockManagedBackupKeys>,
): void {
  const metadata = readDatabaseMetadata(databasePath);
  const inventory = summarizeKeyClasses(databasePath);
  if (metadata.vaultId !== manifest.vaultId || !keys.bundle.vaultId.equals(Buffer.from(manifest.vaultId, "base64"))) {
    throw new Error("Managed backup database and key-bundle identity do not match its manifest.");
  }
  if (metadata.bundleGeneration !== manifest.bundleGeneration || keys.bundle.generation !== manifest.bundleGeneration) {
    throw new Error("Managed backup bundle generation does not match its manifest.");
  }
  const custody = keys.bundle.interactive ? "dual-key" : "machine-only";
  if (custody !== manifest.custody || inventory.machine !== manifest.recordClasses.machine ||
      inventory.interactive !== manifest.recordClasses.interactive) {
    throw new Error("Managed backup key-class inventory does not match its manifest.");
  }
}

function verifyManifestAuthenticators(
  manifest: BackupManifest,
  keys: ReturnType<typeof unlockManagedBackupKeys>,
): void {
  const { authenticators, ...payload } = manifest;
  for (const keyClass of requiredAuthenticatorClasses(manifest)) {
    const key = keyClass === "machine" ? keys.machineKey : keys.interactiveKey;
    if (!key) {
      if (keyClass === "machine") {
        throw new Error("This backup requires its source machine key and cannot be unlocked on the current machine. Live vault state was not changed.");
      }
      throw new Error("This managed backup requires its interactive passphrase. Live vault state was not changed.");
    }
    const actual = authenticators[keyClass]!;
    const expected = manifestAuthenticator(payload, keyClass, key);
    if (!timingSafeBase64Equal(actual, expected)) {
      throw new Error(`Managed backup manifest failed authentication for the ${keyClass} key class. Live vault state was not changed.`);
    }
  }
}

export function verifyManagedBackupPassphrase(source: string, passphrase: string): boolean {
  try {
    const manifest = readManifestForAuthorization(source);
    if (!manifest.authenticators.interactive) return false;
    const databasePath = path.join(source, "vault.db");
    const keyPath = path.join(source, ".keyclasp.key");
    const databaseBefore = assertReadOnlyBackupIdentity(databasePath, "file");
    const keyBefore = assertReadOnlyBackupIdentity(keyPath, "file");
    const keys = unlockManagedBackupKeys(keyPath, databasePath, passphrase);
    assertManifestMatchesBackup(manifest, databasePath, keys);
    if (!keys.interactiveKey) return false;
    const { authenticators, ...payload } = manifest;
    if (!timingSafeBase64Equal(
      authenticators.interactive!,
      manifestAuthenticator(payload, "interactive", keys.interactiveKey),
    )) return false;
    assertReadOnlyBackupIdentityUnchanged(keyPath, keyBefore, "file");
    assertReadOnlyBackupIdentityUnchanged(databasePath, databaseBefore, "file");
    return true;
  } catch {
    return false;
  }
}

export function restoreManagedBackup(source: string, passphrase?: string): ManagedRestoreResult {
  assertSafeBackupDirectory(source);
  const sourceDirectoryIdentity = assertReadOnlyBackupIdentity(source, "directory");
  const manifest = readManifest(source);
  const sourceSnapshot = snapshotVaultFiles(source, Object.keys(manifest.files));
  if (sourceSnapshot.length !== Object.keys(manifest.files).length ||
      sourceSnapshot.some((item) => manifest.files[item.name] !== item.hash)) {
    throw new Error("Managed backup files changed while their manifest was being verified.");
  }
  const sourceDatabasePath = path.join(source, "vault.db");
  const sourceKeyPath = path.join(source, ".keyclasp.key");
  const databaseMetadata = readDatabaseMetadata(sourceDatabasePath);
  const backupKeys = unlockManagedBackupKeys(sourceKeyPath, sourceDatabasePath, passphrase);
  assertManifestMatchesBackup(manifest, sourceDatabasePath, backupKeys);
  verifyManifestAuthenticators(manifest, backupKeys);
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
  runRestorePrimitive("validation", () => validatePublishedSqlite(source, (databasePath) => {
    validateManagedVaultContents(databasePath, sourceKeyPath, backupKeys);
  }, true));
  assertReadOnlyBackupIdentityUnchanged(source, sourceDirectoryIdentity, "directory");
  const vaultDir = getVaultLocation();
  ensureOwnerOnlyVaultDirectory();
  closeDb();
  clearKey();
  const transactionId = `${process.pid}.${crypto.randomBytes(6).toString("hex")}`;
  const staged = MANAGED_FILES.filter((name) => Boolean(manifest.files[name]));
  const portableInteractive = manifest.recordClasses.machine === 0 && manifest.recordClasses.interactive > 0 && !backupKeys.machineKey;
  if (portableInteractive && passphrase === undefined) {
    throw new Error("All-interactive portable restore requires the backup passphrase.");
  }
  const pendingJournalNames = restoreJournalNames();
  const pendingJournalTemporaryNames = restoreJournalTemporaryNames();
  const pendingMaterial = pendingTransactionMaterial(pendingJournalNames);
  const pendingRecoveryMaterial = [
    ...PENDING_RECOVERY_TRIGGER_FILES,
    ...pendingJournalNames,
    ...pendingJournalTemporaryNames,
  ].some((name) => fs.existsSync(path.join(vaultDir, name)));
  const recognizedLiveNames = [
    ...MANAGED_FILES,
    ...SQLITE_LIVE_FILES.slice(1),
    ...RECOVERY_METADATA_FILES,
    ...pendingJournalNames,
    ...pendingJournalTemporaryNames,
    ...restoreJournalKeyNames(),
    ...pendingMaterial.files,
  ];
  const uniqueLiveNames = [...new Set(recognizedLiveNames)];
  const classificationInventory = snapshotExactVaultFiles(vaultDir, uniqueLiveNames);
  assertExactVaultFilesUnchanged(vaultDir, classificationInventory);
  let branch: "healthy" | "damaged" = "damaged";
  let exactLiveInventory = classificationInventory;
  let previousSnapshot = exactLiveInventory.flatMap((item) => item.file ? [item.file] : []);
  const stagingDirectory = `.restore-staging.${transactionId}`;
  const previousDirectory = `.restore-previous.${transactionId}`;
  const initialStagedHashes = Object.fromEntries(staged.map((name) => [name, manifest.files[name]!]));
  let journal: RestoreJournal = {
    version: 2,
    phase: "staging",
    branch,
    transactionId,
    stagingDirectory,
    previousDirectory,
    transactionDirectories: pendingMaterial.directories,
    stagedHashes: initialStagedHashes,
    previousHashes: Object.fromEntries(previousSnapshot.map((item) => [item.name, item.hash])),
    operations: [],
    mac: "",
  };
  const persist = () => persistJournal(journal);
  try {
    persist();
    fs.mkdirSync(path.join(vaultDir, stagingDirectory), { mode: 0o700 });
    fs.mkdirSync(path.join(vaultDir, previousDirectory), { mode: 0o700 });
    enforceOwnerOnlyPath(path.join(vaultDir, stagingDirectory), { kind: "directory", label: "managed restore staging directory" });
    enforceOwnerOnlyPath(path.join(vaultDir, previousDirectory), { kind: "directory", label: "managed restore rollback directory" });
    prepareEvidenceParents(vaultDir, previousDirectory, pendingMaterial.directories);
    const liveDatabasePath = path.join(vaultDir, "vault.db");
    if (SQLITE_LIVE_FILES.some((name) => fs.existsSync(path.join(vaultDir, name)))) {
      assertNoExternalVaultClients(vaultDir);
      assertExactVaultFilesUnchanged(vaultDir, classificationInventory);
    }
    if (fs.existsSync(liveDatabasePath) && hasSQLiteHeader(liveDatabasePath)) {
      if (!pendingRecoveryMaterial && fs.existsSync(path.join(vaultDir, ".keyclasp.key"))) {
        const classificationDatabase = copyLiveSqliteForClassification(vaultDir, stagingDirectory, classificationInventory);
        let semanticState: "healthy" | "damaged" = "healthy";
        try {
          runRestorePrimitive("validation", () => validateCopiedLiveState(vaultDir, classificationDatabase));
          assertExactVaultFilesUnchanged(vaultDir, classificationInventory);
        } catch (error) {
          if (!(error instanceof VaultSemanticDamageError)) throw error;
          semanticState = "damaged";
        }
        if (semanticState === "healthy") {
          assertExactVaultFilesUnchanged(vaultDir, classificationInventory);
          try {
            runRestorePrimitive("validation", () => quiesceSqliteCopy(classificationDatabase));
            branch = "healthy";
          } catch (error) {
            if (!(error instanceof DamagedLiveDatabaseError)) throw error;
          }
        }
        for (const name of CLASSIFICATION_SQLITE_FILES) removeExactFile(path.join(vaultDir, stagingDirectory, name));
        restoreFsyncDirectory(path.join(vaultDir, stagingDirectory));
      }
    }
    journal.branch = branch;
    journal.previousHashes = Object.fromEntries(previousSnapshot.map((item) => [item.name, item.hash]));
    persist();
    assertExactVaultFilesUnchanged(vaultDir, exactLiveInventory);
    assertReadOnlyBackupIdentityUnchanged(source, sourceDirectoryIdentity, "directory");
    assertVaultFilesUnchanged(source, sourceSnapshot);
    for (const [index, name] of staged.entries()) {
      const stagePath = path.join(vaultDir, stagingDirectory, name);
      const partialPath = `${stagePath}.partial`;
      assertReadOnlyBackupIdentityUnchanged(source, sourceDirectoryIdentity, "directory");
      assertVaultFilesUnchanged(source, sourceSnapshot);
      runRestorePrimitive("copy", () => fs.copyFileSync(path.join(source, name), partialPath));
      enforceOwnerOnlyPath(partialPath, { kind: "file", label: `managed restore partial staging file "${name}"` });
      if (sha256File(partialPath) !== manifest.files[name]) throw new Error(`Staged restore file "${name}" failed verification.`);
      restoreFsyncFile(partialPath);
      runRestorePrimitive("rename", () => fs.renameSync(partialPath, stagePath));
      restoreFsyncDirectory(path.join(vaultDir, stagingDirectory));
      if (index === 0 && _restoreFaultForTests === "crash-after-first-stage-copy") {
        throw new Error("Injected managed-restore crash after first staged copy.");
      }
    }
    assertVaultFilesUnchanged(source, sourceSnapshot);
    if (portableInteractive) {
      const stagedKeyPath = path.join(vaultDir, stagingDirectory, ".keyclasp.key");
      const stagedDatabasePath = path.join(vaultDir, stagingDirectory, "vault.db");
      const portableKeyPath = `${stagedKeyPath}.portable`;
      const portableDatabasePath = `${stagedDatabasePath}.portable`;
      runRestorePrimitive("copy", () => fs.copyFileSync(stagedKeyPath, portableKeyPath));
      runRestorePrimitive("copy", () => fs.copyFileSync(stagedDatabasePath, portableDatabasePath));
      enforceOwnerOnlyPath(portableKeyPath, { kind: "file", label: "portable managed restore key bundle" });
      enforceOwnerOnlyPath(portableDatabasePath, { kind: "file", label: "portable managed restore database" });
      preparePortableInteractiveRestore(
        portableKeyPath,
        portableDatabasePath,
        passphrase!,
        _restoreFaultForTests === "crash-during-open-portable-conversion"
          ? () => process.exit(23)
          : undefined,
      );
      if (_restoreFaultForTests === "crash-during-portable-conversion") {
        throw new Error("Injected managed-restore crash during portable conversion.");
      }
      restoreFsyncFile(portableKeyPath);
      restoreFsyncFile(portableDatabasePath);
      runRestorePrimitive("rename", () => fs.renameSync(portableKeyPath, stagedKeyPath));
      runRestorePrimitive("rename", () => fs.renameSync(portableDatabasePath, stagedDatabasePath));
      restoreFsyncDirectory(path.join(vaultDir, stagingDirectory));
    }
    restoreFsyncDirectory(path.join(vaultDir, stagingDirectory));
    restoreFsyncDirectory(vaultDir);
    assertExactVaultFilesUnchanged(vaultDir, exactLiveInventory);
    journal.stagedHashes = Object.fromEntries(staged.map((name) => [name, sha256File(path.join(vaultDir, stagingDirectory, name))]));
    journal.operations = [
      ...previousSnapshot.map((item): VaultFileOperation => ({
        kind: "rename",
        from: item.name,
        to: `${previousDirectory}/${item.name}`,
        hash: item.hash,
        completed: false,
      })),
      ...staged.map((name): VaultFileOperation => ({
        kind: "rename",
        from: `${stagingDirectory}/${name}`,
        to: name,
        hash: journal.stagedHashes[name]!,
        ...(journal.previousHashes[name] ? { rollbackDestinationHash: journal.previousHashes[name] } : {}),
        completed: false,
      })),
    ];
    journal.phase = "publishing";
    persist();
    assertNoExternalVaultClients(vaultDir, journalSqlitePaths(journal));
    assertExactVaultFilesUnchanged(vaultDir, exactLiveInventory);
    if (_restoreFaultForTests === "crash-after-journal") throw new Error("Injected managed-restore crash after journal publication.");
    const previousCount = previousSnapshot.length;
    for (const [index, operation] of journal.operations.entries()) {
      reconcileFileOperation(vaultDir, operation, "forward", persist, maybeInjectOperationFault, restoreFsyncDirectory);
      if (index === 0 && _restoreFaultForTests === "crash-after-first-previous") {
        throw new Error("Injected managed-restore crash after first live rename.");
      }
      if (index === previousCount - 1 && _restoreFaultForTests === "crash-after-previous-fsync") {
        throw new Error("Injected managed-restore crash after prior-file publication.");
      }
      if (index === previousCount && _restoreFaultForTests === "crash-after-first-publish") {
        throw new Error("Injected managed-restore crash after first staged publication.");
      }
    }
    restoreFsyncDirectory(vaultDir);
    if (_restoreFaultForTests === "crash-after-all-published") throw new Error("Injected managed-restore crash after complete staged publication.");
    for (const [name, hash] of Object.entries(journal.stagedHashes)) {
      if (sha256File(path.join(vaultDir, name)) !== hash) throw new Error(`Published restore file "${name}" failed verification.`);
    }
    runRestorePrimitive("validation", () => validatePublishedSqlite(vaultDir, (databasePath) => {
      validateManagedVaultContents(databasePath, path.join(vaultDir, ".keyclasp.key"), backupKeys);
      if (hasPolicy) {
        validateAuthorizationPolicyBackup(
          vaultDir,
          Buffer.from(manifest.vaultId, "base64"),
          databaseMetadata.policyGeneration!,
          databaseMetadata.policyDocumentHash!,
        );
      }
    }));
    journal.phase = "committed";
    persist();
    if (_restoreFaultForTests === "crash-after-commit-journal") throw new Error("Injected managed-restore crash after commit journal publication.");
  } catch (error) {
    if (_restoreFaultForTests?.startsWith("crash-") || _restorePrimitiveFaultTriggered) throw error;
    if (fs.existsSync(restoreJournalPath(transactionId))) {
      journal = readRestoreJournal(restoreJournalPath(transactionId));
      rollbackJournal(journal);
    } else {
      for (const name of staged) {
        const stagedPath = path.join(vaultDir, stagingDirectory, name);
        if (fs.existsSync(stagedPath)) runRestorePrimitive("unlink", () => fs.unlinkSync(stagedPath));
      }
      removeDirectoryIfEmpty(path.join(vaultDir, stagingDirectory));
      removeDirectoryIfEmpty(path.join(vaultDir, previousDirectory));
      const transactionKeyPath = path.join(vaultDir, restoreJournalKeyName(transactionId));
      if (fs.existsSync(transactionKeyPath)) removeExactFile(transactionKeyPath);
      restoreFsyncDirectory(vaultDir);
    }
    throw error;
  }
  const cleanupWarnings: string[] = [];
  try {
    finishCommittedJournal(journal);
  } catch (error) {
    cleanupWarnings.push(`Managed restore cleanup could not be made durable: ${error instanceof Error ? error.message : "unknown error"}`);
  }
  return {
    manifest,
    cleanupWarnings,
    ...(branch === "damaged" ? { rollbackEvidencePath: path.join(vaultDir, previousDirectory) } : {}),
  };
}

export function setRestoreFaultForTests(fault: RestoreFault | null): void {
  _restoreFaultForTests = fault;
}

export function setRestoreOperationFaultForTests(fault: { occurrence: number; point: VaultFileFaultPoint } | null): void {
  _restoreOperationFaultForTests = fault;
  _restoreOperationCount = 0;
}

export function setRestorePrimitiveFaultForTests(
  fault: { primitive: RestorePrimitive; occurrence: number; point: VaultFileFaultPoint } | null,
): void {
  _restorePrimitiveFaultForTests = fault;
  _restorePrimitiveCounts = {};
  _restorePrimitiveFaultTriggered = false;
}

export function getRestorePrimitiveCountsForTests(): Partial<Record<RestorePrimitive, number>> {
  return { ..._restorePrimitiveCounts };
}

export function wasRestorePrimitiveFaultTriggeredForTests(): boolean {
  return _restorePrimitiveFaultTriggered;
}

export function setBackupFaultForTests(fault: BackupFault | null): void {
  _backupFaultForTests = fault;
}
