import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import Database from "better-sqlite3";
import fs from "node:fs";
import path from "node:path";
import { assertOwnerOnlyPath, enforceOwnerOnlyPath } from "./owner-only-path.js";

export const SQLITE_LIVE_FILES = ["vault.db", "vault.db-wal", "vault.db-shm"] as const;

export interface VaultFileSnapshot {
  name: string;
  hash: string;
  size: number;
  device: number;
  inode: number;
}

export interface ExactVaultFileSnapshot {
  name: string;
  file: VaultFileSnapshot | null;
}

export interface RenameOperation {
  kind: "rename";
  from: string;
  to: string;
  hash: string;
  rollbackDestinationHash?: string;
  completed: boolean;
}

export interface UnlinkOperation {
  kind: "unlink";
  path: string;
  hash: string;
  unverifiedTransactionFile?: true;
  completed: boolean;
}

export type VaultFileOperation = RenameOperation | UnlinkOperation;
export type VaultFileFaultPoint = "before-mutation" | "after-mutation" | "after-completion";

export class VaultWriterExclusionError extends Error {}

function isUnobservableProcEntry(error: unknown): boolean {
  return ["ENOENT", "EACCES", "EPERM"].includes((error as NodeJS.ErrnoException).code ?? "");
}
export class DamagedLiveDatabaseError extends Error {}

function hashFile(filePath: string): string {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

export function fsyncFile(filePath: string): void {
  const descriptor = fs.openSync(filePath, "r");
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}

export function fsyncDirectory(directory: string): void {
  const descriptor = fs.openSync(directory, "r");
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}

function assertRelativeName(name: string): void {
  if (!name || path.isAbsolute(name) || name.includes("\0") || name.split(path.sep).includes("..")) {
    throw new Error("Managed restore contains an unsafe file path.");
  }
}

export function snapshotVaultFiles(vaultDir: string, names: readonly string[]): VaultFileSnapshot[] {
  const snapshots: VaultFileSnapshot[] = [];
  for (const name of names) {
    assertRelativeName(name);
    const filePath = path.join(vaultDir, name);
    if (!fs.existsSync(filePath)) continue;
    const identity = assertOwnerOnlyPath(filePath, { kind: "file", label: `live vault file \"${name}\"` });
    snapshots.push({ name, hash: hashFile(filePath), size: identity.size, device: identity.device, inode: identity.inode });
  }
  return snapshots;
}

export function assertVaultFilesUnchanged(vaultDir: string, snapshots: readonly VaultFileSnapshot[]): void {
  for (const before of snapshots) {
    const filePath = path.join(vaultDir, before.name);
    if (!fs.existsSync(filePath)) throw new VaultWriterExclusionError(`Live vault file \"${before.name}\" changed during restore preparation.`);
    const after = assertOwnerOnlyPath(filePath, { kind: "file", label: `live vault file \"${before.name}\"` });
    if (after.device !== before.device || after.inode !== before.inode || after.size !== before.size || hashFile(filePath) !== before.hash) {
      throw new VaultWriterExclusionError(`Live vault file \"${before.name}\" changed during restore preparation.`);
    }
  }
}

export function snapshotExactVaultFiles(vaultDir: string, names: readonly string[]): ExactVaultFileSnapshot[] {
  const present = new Map(snapshotVaultFiles(vaultDir, names).map((item) => [item.name, item]));
  return names.map((name) => ({ name, file: present.get(name) ?? null }));
}

export function assertExactVaultFilesUnchanged(vaultDir: string, inventory: readonly ExactVaultFileSnapshot[]): void {
  for (const item of inventory) {
    const filePath = path.join(vaultDir, item.name);
    if (item.file === null) {
      if (fs.existsSync(filePath)) {
        throw new VaultWriterExclusionError(`Live vault file \"${item.name}\" appeared during restore preparation.`);
      }
      continue;
    }
    assertVaultFilesUnchanged(vaultDir, [item.file]);
  }
}

/** Canonicalize a transaction-owned SQLite copy. The live DB/WAL/SHM remain
 * byte-for-byte unchanged until the authenticated publication journal exists. */
export function quiesceSqliteCopy(databasePath: string): void {
  const database = new Database(databasePath, { fileMustExist: true });
  try {
    database.pragma("busy_timeout = 0");
    const quick = database.pragma("quick_check") as { quick_check?: string }[];
    if (quick.length !== 1 || quick[0]?.quick_check !== "ok") {
      throw new DamagedLiveDatabaseError("Live vault classification copy failed SQLite quick_check.");
    }
    database.exec("BEGIN EXCLUSIVE");
    database.exec("COMMIT");
    database.pragma("wal_checkpoint(TRUNCATE)");
    database.pragma("journal_mode = DELETE");
  } finally {
    database.close();
  }
  fsyncFile(databasePath);
  fsyncDirectory(path.dirname(databasePath));
}

/** Fail closed when another process already has a live SQLite file open.
 * This check does not open SQLite, so damaged DB/WAL/SHM bytes remain intact. */
export function assertNoExternalVaultClients(vaultDir: string, relativeNames: readonly string[] = SQLITE_LIVE_FILES): void {
  const targets = [...new Set(relativeNames.map((name) => path.join(vaultDir, name)))].filter(fs.existsSync);
  if (targets.length === 0) return;
  if (process.platform === "darwin") {
    const result = spawnSync("/usr/sbin/lsof", ["-t", "--", ...targets], { encoding: "utf8" });
    const pids = result.stdout.trim().split(/\s+/).filter(Boolean);
    if (pids.length > 0) throw new VaultWriterExclusionError("A process has a live vault SQLite file open; stop every external SQLite client before restoring.");
    if (result.error || result.status !== 1 || result.stderr.trim() !== "") {
      throw new VaultWriterExclusionError("Keyclasp could not verify that external SQLite clients are stopped.");
    }
    return;
  }
  if (process.platform === "linux") {
    const exactTargets = new Set(targets.map((target) => path.resolve(target)));
    for (const pid of fs.readdirSync("/proc").filter((name) => /^\d+$/.test(name))) {
      const fdDirectory = `/proc/${pid}/fd`;
      try {
        const processStat = fs.statSync(`/proc/${pid}`);
        if (process.getuid && processStat.uid !== process.getuid()) continue;
      } catch (error) {
        if (isUnobservableProcEntry(error)) continue;
        throw new VaultWriterExclusionError("Keyclasp could not inspect a same-user process for open vault files.");
      }
      let descriptors: string[];
      try { descriptors = fs.readdirSync(fdDirectory); } catch (error) {
        if (isUnobservableProcEntry(error)) continue;
        throw new VaultWriterExclusionError("Keyclasp could not inspect a same-user process for open vault files.");
      }
      for (const descriptor of descriptors) {
        try {
          // stat follows every descriptor target and can fail on an unrelated
          // protected path. The proc descriptor link identifies the opened
          // pathname without traversing that target.
          const openedPath = fs.readlinkSync(path.join(fdDirectory, descriptor));
          if (path.isAbsolute(openedPath) && exactTargets.has(path.normalize(openedPath))) {
            throw new VaultWriterExclusionError("A process has a live vault SQLite file open; stop every external SQLite client before restoring.");
          }
        } catch (error) {
          if (error instanceof VaultWriterExclusionError) throw error;
          // Linux may deny fd-link inspection across otherwise same-UID
          // processes (for example under ptrace restrictions). Such holders
          // are outside this documented observable-process guard.
          if (!isUnobservableProcEntry(error)) {
            throw new VaultWriterExclusionError("Keyclasp could not inspect a same-user process descriptor for open vault files.");
          }
        }
      }
    }
    return;
  }
  throw new VaultWriterExclusionError("Keyclasp cannot verify external SQLite clients on this platform.");
}

function observedFile(filePath: string, expectedHash: string): "expected" | "absent" | "other" {
  if (!fs.existsSync(filePath)) return "absent";
  assertOwnerOnlyPath(filePath, { kind: "file", label: `managed restore transaction file \"${path.basename(filePath)}\"` });
  return hashFile(filePath) === expectedHash ? "expected" : "other";
}

export function assertRollbackOperationsReconciliable(
  vaultDir: string,
  operations: readonly VaultFileOperation[],
  replacementHashes: Readonly<Record<string, string>> = {},
): void {
  for (const operation of [...operations].reverse()) {
    if (operation.kind !== "rename") throw new Error("Managed restore rollback contains an irreversible operation.");
    const live = path.join(vaultDir, operation.to);
    const stagedOrPrevious = path.join(vaultDir, operation.from);
    const liveState = observedFile(live, operation.hash);
    const otherState = observedFile(stagedOrPrevious, operation.hash);
    const authenticatedOldAtLive = liveState === "other" && otherState === "expected" &&
      operation.rollbackDestinationHash !== undefined && hashFile(live) === operation.rollbackDestinationHash;
    const identicalOldAtLive = liveState === "expected" && otherState === "expected" &&
      operation.rollbackDestinationHash === operation.hash;
    const authenticatedReplacementAtLive = liveState === "expected" && otherState === "other" &&
      replacementHashes[operation.from] !== undefined && hashFile(stagedOrPrevious) === replacementHashes[operation.from];
    const identicalReplacementAtLive = liveState === "expected" && otherState === "expected" &&
      replacementHashes[operation.from] === operation.hash;
    const ordinary = (liveState === "expected" && otherState === "absent") ||
      (liveState === "absent" && otherState === "expected");
    if (!ordinary && !authenticatedOldAtLive && !identicalOldAtLive && !authenticatedReplacementAtLive && !identicalReplacementAtLive) {
      throw new Error(`Managed restore rename \"${operation.from}\" -> \"${operation.to}\" has a mixed or unknown state.`);
    }
  }
}

export function reconcileFileOperation(
  vaultDir: string,
  operation: VaultFileOperation,
  direction: "forward" | "rollback",
  persistCompletion: () => void,
  fault?: (point: VaultFileFaultPoint, operation: VaultFileOperation) => void,
  syncDirectory: (directory: string) => void = fsyncDirectory,
): void {
  if (operation.kind === "unlink") {
    const target = path.join(vaultDir, operation.path);
    const state = operation.unverifiedTransactionFile
      ? (() => {
          if (!fs.existsSync(target)) return "absent" as const;
          assertOwnerOnlyPath(target, { kind: "file", label: `managed restore transaction file \"${path.basename(target)}\"` });
          return "expected" as const;
        })()
      : observedFile(target, operation.hash);
    const wantsAbsent = direction === "forward";
    if (state === "other") throw new Error(`Managed restore file \"${operation.path}\" has an unknown state.`);
    if ((state === "absent") === wantsAbsent) {
      if (!operation.completed) {
        operation.completed = true;
        persistCompletion();
      }
      return;
    }
    if (direction === "rollback") {
      // Unlink is used only for cleanup after the commit point and is not
      // reversible. Rollback never includes one.
      throw new Error("Managed restore attempted to reverse an irreversible cleanup operation.");
    }
    fault?.("before-mutation", operation);
    fs.unlinkSync(target);
    syncDirectory(path.dirname(target));
    fault?.("after-mutation", operation);
    operation.completed = true;
    persistCompletion();
    fault?.("after-completion", operation);
    return;
  }

  const forwardFrom = path.join(vaultDir, operation.from);
  const forwardTo = path.join(vaultDir, operation.to);
  const from = direction === "forward" ? forwardFrom : forwardTo;
  const to = direction === "forward" ? forwardTo : forwardFrom;
  const fromState = observedFile(from, operation.hash);
  const toState = observedFile(to, operation.hash);
  if (direction === "rollback" && fromState === "other" && toState === "expected" &&
      operation.rollbackDestinationHash && hashFile(forwardTo) === operation.rollbackDestinationHash) {
    // Publication had not started for this file and rollback of its earlier
    // live-to-previous operation has already restored the authenticated old
    // destination. The staged new file remains available for cleanup.
    return;
  }
  if (direction === "rollback" && fromState === "expected" && toState === "expected" &&
      operation.rollbackDestinationHash === operation.hash) {
    // Old and new representations are byte-identical. The earlier preservation
    // rename did not run, so leave the authenticated live copy in place and
    // let exact staging cleanup remove the duplicate.
    return;
  }
  if (fromState === "other" || toState === "other" || fromState === toState) {
    throw new Error(`Managed restore rename \"${operation.from}\" -> \"${operation.to}\" has a mixed or unknown state.`);
  }
  if (fromState === "absent" && toState === "expected") {
    if (!operation.completed) {
      operation.completed = true;
      persistCompletion();
    }
    return;
  }
  fault?.("before-mutation", operation);
  fs.renameSync(from, to);
  enforceOwnerOnlyPath(to, { kind: "file", label: `managed restore file \"${path.basename(to)}\"` });
  syncDirectory(path.dirname(from));
  if (path.dirname(to) !== path.dirname(from)) syncDirectory(path.dirname(to));
  fault?.("after-mutation", operation);
  operation.completed = true;
  persistCompletion();
  fault?.("after-completion", operation);
}

export function validatePublishedSqlite(
  vaultDir: string,
  validateContents: (databasePath: string) => void,
  fullIntegrityCheck = false,
): void {
  for (const sidecar of SQLITE_LIVE_FILES.slice(1)) {
    if (fs.existsSync(path.join(vaultDir, sidecar))) {
      throw new Error(`Restored vault retained attachable SQLite sidecar \"${sidecar}\".`);
    }
  }
  const databasePath = path.join(vaultDir, "vault.db");
  const database = new Database(databasePath, { readonly: true, fileMustExist: true });
  try {
    const pragma = fullIntegrityCheck ? "integrity_check" : "quick_check";
    const rows = database.pragma(pragma) as Record<string, string>[];
    if (rows.length !== 1 || Object.values(rows[0] ?? {})[0] !== "ok") {
      throw new Error(`Restored vault failed SQLite ${pragma}.`);
    }
  } finally {
    database.close();
  }
  validateContents(databasePath);
}

export function sha256File(filePath: string): string {
  return hashFile(filePath);
}

export function hasSQLiteHeader(databasePath: string): boolean {
  const descriptor = fs.openSync(databasePath, "r");
  try {
    const header = Buffer.alloc(16);
    return fs.readSync(descriptor, header, 0, header.length, 0) === header.length &&
      header.equals(Buffer.from("SQLite format 3\0", "binary"));
  } finally {
    fs.closeSync(descriptor);
  }
}
