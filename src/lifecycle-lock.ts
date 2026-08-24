import Database from "better-sqlite3";
import path from "node:path";
import { ensureOwnerOnlyVaultDirectory, getVaultLocation } from "./vault.js";
import { enforceOwnerOnlyPath } from "./owner-only-path.js";

export type VaultLifecycleLock = { release(): void };
let _freshSchemaBarrierForTests: (() => void) | null = null;

export function lifecycleModeForCommand(command: string): "shared" | "exclusive" {
  return ["init", "lock", "unlock", "inherit", "passphrase", "backup", "rename"].includes(command) ? "exclusive" : "shared";
}

export function setFreshLifecycleSchemaBarrierForTests(barrier: (() => void) | null): void {
  _freshSchemaBarrierForTests = barrier;
}

export function acquireVaultLifecycleLock(mode: "shared" | "exclusive"): VaultLifecycleLock {
  const vaultDir = getVaultLocation();
  ensureOwnerOnlyVaultDirectory();
  const lockPath = path.join(vaultDir, ".lifecycle.db");
  const db = new Database(lockPath);
  try {
    enforceOwnerOnlyPath(lockPath, { kind: "file", label: "vault lifecycle lock" });
    // Lifecycle mutations serialize behind ordinary commands, including long-lived
    // children. Process termination remains the cancellation mechanism for this
    // synchronous SQLite wait.
    db.pragma("busy_timeout = 2147483647");
    const tableExists = db.prepare("SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'lifecycle_lock'").get();
    if (!tableExists) {
      _freshSchemaBarrierForTests?.();
      db.exec("CREATE TABLE IF NOT EXISTS lifecycle_lock (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), value INTEGER NOT NULL)");
    }
    const initialized = db.prepare("SELECT value FROM lifecycle_lock WHERE singleton = 1").get();
    if (!initialized) db.prepare("INSERT OR IGNORE INTO lifecycle_lock(singleton, value) VALUES (1, 1)").run();
    db.exec(mode === "exclusive" ? "BEGIN EXCLUSIVE" : "BEGIN");
    db.prepare("SELECT value FROM lifecycle_lock WHERE singleton = 1").get();
  } catch (error) {
    db.close();
    throw error;
  }

  let released = false;
  return {
    release() {
      if (released) return;
      released = true;
      try {
        db.exec("COMMIT");
      } finally {
        db.close();
      }
    },
  };
}
