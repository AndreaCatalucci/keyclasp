import { execFileSync } from "node:child_process";
import fs from "node:fs";

export type OwnerOnlyPathKind = "file" | "directory";

export interface OwnerOnlyPathOptions {
  kind: OwnerOnlyPathKind;
  label: string;
  access?: "owner-only" | "safe-parent";
}

export interface VerifiedOwnerOnlyPath {
  device: number;
  inode: number;
  size: number;
  mode: number;
}

/**
 * Verify an existing path without repairing it. Recovery uses this before
 * moving live files so an unsafe path is never made to look trustworthy by
 * the restore operation itself.
 */
export function assertOwnerOnlyPath(filePath: string, options: OwnerOnlyPathOptions): VerifiedOwnerOnlyPath {
  const expectedMode = options.kind === "directory" ? 0o700 : 0o600;
  const before = fs.lstatSync(filePath);
  assertSafeIdentity(before, options);
  if (options.kind === "file" && before.nlink !== 1) {
    throw new Error(`Unsafe ${options.label}: expected exactly one filesystem link.`);
  }
  if ((before.mode & 0o777) !== expectedMode) {
    throw new Error(`Unsafe ${options.label}: expected owner-only mode ${expectedMode.toString(8)}.`);
  }
  if (process.platform === "darwin" && macOsAclEntries(filePath, options.label).length > 0) {
    throw new Error(`Unsafe ${options.label}: access-control entries are not allowed.`);
  }
  const after = fs.lstatSync(filePath);
  assertSameIdentity(before, after, options);
  return { device: after.dev, inode: after.ino, size: after.size, mode: after.mode & 0o777 };
}

export function enforceOwnerOnlyPath(filePath: string, options: OwnerOnlyPathOptions): void {
  const access = options.access ?? "owner-only";
  const expectedMode = options.kind === "directory" ? 0o700 : 0o600;
  const before = fs.lstatSync(filePath);
  assertSafeIdentity(before, options);
  if (access === "safe-parent") {
    assertSafeParentMode(before, options.label);
    if (process.platform === "darwin") assertNoWriteGrantingMacOsAcl(filePath, options.label);
    assertSameIdentity(before, fs.lstatSync(filePath), options);
    return;
  }

  if (process.platform === "darwin") {
    repairMacOsAcl(filePath, options.label);
    assertSameIdentity(before, fs.lstatSync(filePath), options);
  }

  if ((before.mode & 0o777) !== expectedMode) {
    try {
      fs.chmodSync(filePath, expectedMode);
    } catch (error: any) {
      throw new Error(`Cannot repair owner-only permissions for ${options.label}: ${error?.message ?? "permission change failed"}`);
    }
  }

  const after = fs.lstatSync(filePath);
  assertSafeIdentity(after, options);
  assertSameIdentity(before, after, options);
  const actualMode = after.mode & 0o777;
  if (actualMode !== expectedMode) {
    throw new Error(`Cannot verify owner-only permissions for ${options.label}; expected ${expectedMode.toString(8)}, found ${actualMode.toString(8)}.`);
  }
}

function assertSafeParentMode(stat: fs.Stats, label: string): void {
  const actualMode = stat.mode & 0o777;
  if ((actualMode & 0o022) !== 0) {
    throw new Error(`Unsafe ${label}: group or other users may write this directory (${actualMode.toString(8)}).`);
  }
}

function assertSameIdentity(before: fs.Stats, after: fs.Stats, options: OwnerOnlyPathOptions): void {
  assertSafeIdentity(after, options);
  if (before.dev !== after.dev || before.ino !== after.ino) {
    throw new Error(`Unsafe ${options.label}: the path changed while its ownership and permissions were being verified.`);
  }
}

function assertSafeIdentity(stat: fs.Stats, options: OwnerOnlyPathOptions): void {
  if (stat.isSymbolicLink()) throw new Error(`Unsafe ${options.label}: symbolic links are not allowed.`);
  if (options.kind === "directory" ? !stat.isDirectory() : !stat.isFile()) {
    throw new Error(`Unsafe ${options.label}: expected a real ${options.kind}.`);
  }
  if (process.platform === "win32") {
    throw new Error(`Cannot verify owner-only Windows ACLs for ${options.label}; Keyclasp access is blocked on this host.`);
  }
  const currentUid = process.getuid?.();
  if (currentUid !== undefined && stat.uid !== currentUid) {
    throw new Error(`Unsafe ${options.label}: owner UID ${stat.uid} does not match the current UID ${currentUid}.`);
  }
}

function repairMacOsAcl(filePath: string, label: string): void {
  if (macOsAclEntries(filePath, label).length === 0) return;
  try {
    execFileSync("/bin/chmod", ["-N", filePath], { stdio: ["ignore", "ignore", "pipe"] });
  } catch (error: any) {
    throw new Error(`Cannot remove macOS ACL entries from ${label}: ${error?.message ?? "ACL repair failed"}`);
  }
  if (macOsAclEntries(filePath, label).length > 0) {
    throw new Error(`Cannot verify an empty macOS ACL for ${label}.`);
  }
}

export function assertNoWriteGrantingMacOsAcl(filePath: string, label: string): void {
  const writePermission = /(?:^|,)(?:write|append|add_file|add_subdirectory|delete|delete_child|writeattr|writeextattr|writesecurity|chown)(?:,|$)/;
  const grantingEntry = macOsAclEntries(filePath, label).find((entry) => {
    const match = entry.match(/\ballow\s+([^\s]+)/);
    return match !== null && writePermission.test(match[1]);
  });
  if (grantingEntry) {
    throw new Error(`Unsafe ${label}: a macOS ACL grants write access to another identity.`);
  }
}

function macOsAclEntries(filePath: string, label: string): string[] {
  let output: string;
  try {
    output = execFileSync("/bin/ls", ["-lde", filePath], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (error: any) {
    throw new Error(`Cannot inspect the macOS ACL for ${label}: ${error?.message ?? "ACL inspection failed"}`);
  }
  return output.split("\n").filter((line) => /^\s*\d+:\s/.test(line));
}
