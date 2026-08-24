import crypto from "node:crypto";
import Database from "better-sqlite3";
import fs from "node:fs";
import path from "node:path";
import { getVaultDescriptor, getVaultLocation, validateScopeName } from "./vault.js";
import { enforceOwnerOnlyPath } from "./owner-only-path.js";
import type { OperatorAuthorizer } from "./runtime.js";

const POLICY_VERSION = 2;
const POLICY_TRANSACTION_VERSION = 1;
const LEGACY_POLICY_DOMAIN = "keyclasp:strict-policy:v1";
const POLICY_DOMAIN = "keyclasp:authorization-policy:v2";
const POLICY_FILE = "strict-policy.v1.json";
const POLICY_ANCHOR_FILE = ".strict-policy.key";
const POLICY_AUDIT_FILE = "strict-policy-audit.jsonl";
const POLICY_PENDING_FILE = ".strict-policy.pending";
export const AUTHORIZATION_POLICY_BACKUP_FILES = [POLICY_FILE, POLICY_ANCHOR_FILE] as const;

type PolicyMutationFault =
  | "after-document"
  | "after-anchor"
  | "after-commit-cleanup"
  | "crash-after-document"
  | "crash-after-anchor"
  | "crash-after-commit";
let _policyMutationFaultForTests: PolicyMutationFault | null = null;

export type AuthorizationState = "locked" | "unlocked";
export type AuthorizationMutation = "lock" | "unlock" | "inherit";

export interface AuthorizationSelector {
  project?: string;
  environment?: string;
  secret?: string;
}

export function authorizationSelectorFromCommand(
  project: string | undefined,
  environment: string | undefined,
  positionals: readonly string[],
): AuthorizationSelector {
  const secret = positionals[0];
  if ((project === undefined && environment === undefined) || positionals.length > 1 ||
      (secret !== undefined && (project === undefined || environment === undefined))) {
    throw new Error("Invalid authorization-rule scope.");
  }
  const selector: AuthorizationSelector = {
    ...(project === undefined ? {} : { project }),
    ...(environment === undefined ? {} : { environment }),
    ...(secret === undefined ? {} : { secret }),
  };
  validateAuthorizationSelector(selector);
  return selector;
}

interface PolicyRecord {
  project: string;
  environment: string;
  strict: boolean;
}

interface LegacyPolicyPayload {
  version: 1;
  vaultId: string;
  generation: number;
  records: PolicyRecord[];
}

export interface AuthorizationRule extends AuthorizationSelector {
  locked: boolean;
}

interface PolicyPayload {
  version: 2;
  vaultId: string;
  generation: number;
  rules: AuthorizationRule[];
}

type AnyPolicyPayload = LegacyPolicyPayload | PolicyPayload;

type PolicyDocument = AnyPolicyPayload & {
  mac: string;
};

interface PolicyAnchor {
  version: 1;
  key: string;
  generation: number;
  documentHash: string;
}

interface LoadedPolicy {
  generation: number;
  rules: AuthorizationRule[];
  key: Buffer;
  documentHash: string;
}

interface PolicyDatabaseAnchor {
  generation: number;
  documentHash: string;
}

function policyPaths(): { document: string; anchor: string; audit: string; pending: string } {
  const home = getVaultLocation();
  return {
    document: path.join(home, POLICY_FILE),
    anchor: path.join(home, POLICY_ANCHOR_FILE),
    audit: path.join(home, POLICY_AUDIT_FILE),
    pending: path.join(home, POLICY_PENDING_FILE),
  };
}

function canonicalPayload(payload: AnyPolicyPayload): string {
  if (payload.version === 1) {
    return JSON.stringify({
      version: payload.version,
      vaultId: payload.vaultId,
      generation: payload.generation,
      records: [...payload.records].sort((a, b) =>
        compareCanonicalStrings(a.project, b.project) || compareCanonicalStrings(a.environment, b.environment)),
    });
  }
  return JSON.stringify({
    version: payload.version,
    vaultId: payload.vaultId,
    generation: payload.generation,
    rules: [...payload.rules].sort((a, b) => compareCanonicalStrings(ruleIdentity(a), ruleIdentity(b))),
  });
}

function compareCanonicalStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function macPayload(payload: AnyPolicyPayload, key: Buffer): string {
  return crypto.createHmac("sha256", key)
    .update(payload.version === 1 ? LEGACY_POLICY_DOMAIN : POLICY_DOMAIN)
    .update("\0")
    .update(canonicalPayload(payload))
    .digest("base64");
}

function documentHash(document: PolicyDocument): string {
  return crypto.createHash("sha256").update(JSON.stringify(document)).digest("base64");
}

function readJson<T>(filePath: string, label: string): T {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8")) as T;
  } catch {
    throw new Error(`Keyclasp ${label} is corrupt. Restore a managed backup before using the vault.`);
  }
}

function assertOwnerFile(filePath: string): void {
  enforceOwnerOnlyPath(filePath, { kind: "file", label: "authorization-policy file" });
}

function loadPolicyFrom(paths: { document: string; anchor: string }, expectedVaultId: Buffer): LoadedPolicy | null {
  const hasDocument = fs.existsSync(paths.document);
  const hasAnchor = fs.existsSync(paths.anchor);
  if (!hasDocument && !hasAnchor) return null;
  if (!hasDocument || !hasAnchor) {
    throw new Error("Keyclasp authorization policy is incomplete. Restore a managed backup before using the vault.");
  }
  assertOwnerFile(paths.document);
  assertOwnerFile(paths.anchor);
  const document = readJson<PolicyDocument>(paths.document, "authorization policy");
  const anchor = readJson<PolicyAnchor>(paths.anchor, "authorization-policy anchor");
  const key = Buffer.from(anchor.key ?? "", "base64");
  const committedDocumentHash = documentHash(document);
  if ((document.version !== 1 && document.version !== POLICY_VERSION) || anchor.version !== 1 ||
      key.length !== 32 || document.vaultId !== expectedVaultId.toString("base64") ||
      document.generation !== anchor.generation || committedDocumentHash !== anchor.documentHash ||
      document.mac !== macPayload(document, key)) {
    throw new Error("Keyclasp authorization policy failed authentication. Restore a managed backup before using the vault.");
  }
  const rules: AuthorizationRule[] = [];
  const seen = new Set<string>();
  const candidates: AuthorizationRule[] = document.version === 1
    ? (() => {
        if (!Array.isArray(document.records)) throw new Error("Keyclasp authorization policy is corrupt.");
        return document.records.map((record) => {
          validateScopeName(record.project, "project");
          validateScopeName(record.environment, "environment");
          if (record.strict !== true) throw new Error("Keyclasp authorization policy is corrupt.");
          return { project: record.project, environment: record.environment, locked: true };
        });
      })()
    : (() => {
        if (!Array.isArray(document.rules)) throw new Error("Keyclasp authorization policy is corrupt.");
        return document.rules;
      })();
  for (const rule of candidates) {
    validateAuthorizationSelector(rule);
    if (typeof rule.locked !== "boolean") throw new Error("Keyclasp authorization policy is corrupt.");
    const identity = ruleIdentity(rule);
    if (seen.has(identity)) throw new Error("Keyclasp authorization policy contains duplicate rules.");
    seen.add(identity);
    rules.push({
      ...(rule.project === undefined ? {} : { project: rule.project }),
      ...(rule.environment === undefined ? {} : { environment: rule.environment }),
      ...(rule.secret === undefined ? {} : { secret: rule.secret }),
      locked: rule.locked,
    });
  }
  return { generation: document.generation, rules, key, documentHash: committedDocumentHash };
}

function validateAuthorizationSelector(selector: AuthorizationSelector): void {
  if (selector.project !== undefined) validateScopeName(selector.project, "project");
  if (selector.environment !== undefined) validateScopeName(selector.environment, "environment");
  if (selector.project === undefined && selector.environment === undefined) {
    throw new Error("Authorization policy requires --project, --environment, or both.");
  }
  if (selector.secret !== undefined) {
    if (selector.project === undefined || selector.environment === undefined) {
      throw new Error("A secret-specific authorization rule requires both --project and --environment.");
    }
    if (selector.secret.length === 0 || selector.secret.includes("\0")) {
      throw new Error("Invalid secret name for authorization policy.");
    }
  }
}

function ruleIdentity(selector: AuthorizationSelector): string {
  return JSON.stringify([selector.project ?? null, selector.environment ?? null, selector.secret ?? null]);
}

function loadPolicy(): LoadedPolicy | null {
  const paths = policyPaths();
  const hasPolicyFiles = fs.existsSync(paths.document) || fs.existsSync(paths.anchor);
  if (!hasPolicyFiles && !fs.existsSync(paths.pending)) {
    if (readPolicyDatabaseAnchor() !== null) {
      throw new Error("Keyclasp authorization policy is missing. Restore a managed backup before using the vault.");
    }
    return null;
  }
  const descriptor = getVaultDescriptor();
  if (fs.existsSync(paths.pending)) return recoverInterruptedPolicy(paths, descriptor.vaultId);
  const loaded = loadPolicyFrom(paths, descriptor.vaultId);
  const databaseAnchor = readPolicyDatabaseAnchor();
  if (!loaded) {
    if (databaseAnchor !== null) throw new Error("Keyclasp authorization policy is missing. Restore a managed backup before using the vault.");
    return null;
  }
  if (databaseAnchor === null || loaded.generation !== databaseAnchor.generation || loaded.documentHash !== databaseAnchor.documentHash) {
    throw new Error("Keyclasp authorization-policy commitment does not match the vault anchor. Restore a managed backup before using the vault.");
  }
  return loaded;
}

function atomicWrite(filePath: string, value: string): void {
  const tempPath = `${filePath}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  fs.writeFileSync(tempPath, value, { mode: 0o600 });
  const descriptor = fs.openSync(tempPath, "r");
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
  fs.renameSync(tempPath, filePath);
  enforceOwnerOnlyPath(filePath, { kind: "file", label: `authorization-policy file "${path.basename(filePath)}"` });
  fsyncPolicyDirectory();
}

function fsyncPolicyDirectory(): void {
  const descriptor = fs.openSync(getVaultLocation(), "r");
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}

interface PendingPolicyMutation {
  version: 1;
  previousDocument: string | null;
  previousAnchor: string | null;
  previousGeneration: number | null;
  previousDocumentHash: string | null;
}

function readPolicyDatabaseAnchor(databasePath = path.join(getVaultLocation(), "vault.db")): PolicyDatabaseAnchor | null {
  if (!fs.existsSync(databasePath)) return null;
  const db = new Database(databasePath, { readonly: true, fileMustExist: true });
  try {
    const columns = (db.pragma("table_info(vault_metadata)") as { name: string }[]).map((column) => column.name);
    if (!columns.includes("strict_policy_generation") || !columns.includes("strict_policy_required")) return null;
    if (!columns.includes("strict_policy_document_hash")) {
      const legacy = db.prepare("SELECT strict_policy_required FROM vault_metadata WHERE singleton = 1").get() as { strict_policy_required: number };
      if (legacy.strict_policy_required === 1) throw new Error("Keyclasp authorization-policy vault commitment is missing.");
      return null;
    }
    const row = db.prepare("SELECT strict_policy_required, strict_policy_generation, strict_policy_document_hash FROM vault_metadata WHERE singleton = 1").get() as
      | { strict_policy_required: number; strict_policy_generation: number | null; strict_policy_document_hash: string | null }
      | undefined;
    if (!row) throw new Error("Keyclasp authorization-policy vault anchor is missing.");
    if (row.strict_policy_required === 0 && row.strict_policy_generation === null && row.strict_policy_document_hash === null) return null;
    const hash = Buffer.from(row.strict_policy_document_hash ?? "", "base64");
    if (row.strict_policy_required !== 1 || !Number.isSafeInteger(row.strict_policy_generation) || row.strict_policy_generation! < 1 || hash.length !== 32) {
      throw new Error("Keyclasp authorization-policy vault anchor is corrupt.");
    }
    return { generation: row.strict_policy_generation!, documentHash: row.strict_policy_document_hash! };
  } finally {
    db.close();
  }
}

function writePolicyDatabaseAnchor(
  anchor: PolicyDatabaseAnchor | null,
  databasePath = path.join(getVaultLocation(), "vault.db"),
  databaseMutation?: (db: Database.Database) => void,
): void {
  const db = new Database(databasePath, { fileMustExist: true });
  try {
    db.pragma("synchronous = FULL");
    const update = db.transaction(() => {
      const columns = (db.pragma("table_info(vault_metadata)") as { name: string }[]).map((column) => column.name);
      if (!columns.includes("strict_policy_generation")) db.exec("ALTER TABLE vault_metadata ADD COLUMN strict_policy_generation INTEGER");
      if (!columns.includes("strict_policy_required")) db.exec("ALTER TABLE vault_metadata ADD COLUMN strict_policy_required INTEGER NOT NULL DEFAULT 0");
      if (!columns.includes("strict_policy_document_hash")) db.exec("ALTER TABLE vault_metadata ADD COLUMN strict_policy_document_hash TEXT");
      databaseMutation?.(db);
      db.prepare("UPDATE vault_metadata SET strict_policy_required = ?, strict_policy_generation = ?, strict_policy_document_hash = ? WHERE singleton = 1")
        .run(anchor === null ? 0 : 1, anchor?.generation ?? null, anchor?.documentHash ?? null);
    });
    update.immediate();
  } finally {
    db.close();
  }
}

function unlinkIfPresent(filePath: string): void {
  try {
    fs.unlinkSync(filePath);
  } catch (error: any) {
    if (error?.code !== "ENOENT") throw error;
  }
}

function recoverInterruptedPolicy(
  paths: { document: string; anchor: string; pending: string },
  vaultId: Buffer,
): LoadedPolicy | null {
  if (!fs.existsSync(paths.pending)) return loadPolicyFrom(paths, vaultId);
  assertOwnerFile(paths.pending);
  const pending = readJson<PendingPolicyMutation>(paths.pending, "authorization-policy transaction");
  const currentAnchor = readPolicyDatabaseAnchor();
  try {
    const current = loadPolicyFrom(paths, vaultId);
    if (current && currentAnchor && current.generation === currentAnchor.generation && current.documentHash === currentAnchor.documentHash) {
      try {
        unlinkIfPresent(paths.pending);
        fsyncPolicyDirectory();
      } catch {
        // The database anchor is the commit point. A later open retries cleanup.
      }
      return current;
    }
  } catch {
    // Restore the last committed pair below.
  }
  if (pending.version !== POLICY_TRANSACTION_VERSION || (pending.previousDocument === null) !== (pending.previousAnchor === null) ||
      (pending.previousGeneration === null) !== (pending.previousDocumentHash === null)) {
    throw new Error("Keyclasp authorization-policy transaction is corrupt. Restore a managed backup before using the vault.");
  }
  if (pending.previousGeneration !== (currentAnchor?.generation ?? null) ||
      pending.previousDocumentHash !== (currentAnchor?.documentHash ?? null)) {
    throw new Error("Keyclasp authorization-policy transaction does not match the committed vault generation.");
  }
  if (pending.previousDocument === null) {
    unlinkIfPresent(paths.document);
    unlinkIfPresent(paths.anchor);
  } else {
    atomicWrite(paths.document, Buffer.from(pending.previousDocument, "base64").toString("utf8"));
    atomicWrite(paths.anchor, Buffer.from(pending.previousAnchor!, "base64").toString("utf8"));
  }
  writePolicyDatabaseAnchor(pending.previousGeneration === null ? null : {
    generation: pending.previousGeneration,
    documentHash: pending.previousDocumentHash!,
  });
  fsyncPolicyDirectory();
  unlinkIfPresent(paths.pending);
  fsyncPolicyDirectory();
  const restored = loadPolicyFrom(paths, vaultId);
  if (restored && (restored.generation !== pending.previousGeneration || restored.documentHash !== pending.previousDocumentHash)) {
    throw new Error("Keyclasp authorization-policy recovery did not match the vault anchor.");
  }
  return restored;
}

function matchingSpecificity(rule: AuthorizationRule, project: string, environment: string, secret?: string): number | null {
  if (rule.project !== undefined && rule.project !== project) return null;
  if (rule.environment !== undefined && rule.environment !== environment) return null;
  if (rule.secret !== undefined && rule.secret !== secret) return null;
  if (rule.secret !== undefined) return 3;
  if (rule.project !== undefined && rule.environment !== undefined) return 2;
  return 1;
}

export function evaluateAuthorizationRules(rules: readonly AuthorizationRule[], project: string, environment: string, secret?: string): AuthorizationState {
  let bestSpecificity = 0;
  let locked = false;
  for (const rule of rules) {
    const specificity = matchingSpecificity(rule, project, environment, secret);
    if (specificity === null || specificity < bestSpecificity) continue;
    if (specificity > bestSpecificity) {
      bestSpecificity = specificity;
      locked = rule.locked;
    } else if (rule.locked) {
      locked = true;
    }
  }
  return locked ? "locked" : "unlocked";
}

export function readAuthorizationState(project: string, environment: string, secret?: string): AuthorizationState {
  validateScopeName(project, "project");
  validateScopeName(environment, "environment");
  if (secret !== undefined) validateAuthorizationSelector({ project, environment, secret });
  return evaluateAuthorizationRules(loadPolicy()?.rules ?? [], project, environment, secret);
}

export function summarizeAuthorizationState(
  project: string,
  environment: string,
  secretNames: readonly string[],
): { state: AuthorizationState | "mixed"; scopeDefault: AuthorizationState; locked: number; unlocked: number } {
  validateScopeName(project, "project");
  validateScopeName(environment, "environment");
  const rules = loadPolicy()?.rules ?? [];
  const scopeDefault = evaluateAuthorizationRules(rules, project, environment);
  let locked = 0;
  for (const name of secretNames) {
    if (evaluateAuthorizationRules(rules, project, environment, name) === "locked") locked += 1;
  }
  const unlocked = secretNames.length - locked;
  const state = locked > 0 && unlocked > 0 ? "mixed" : locked > 0 ? "locked" : unlocked > 0 ? "unlocked" : scopeDefault;
  return { state, scopeDefault, locked, unlocked };
}

export function validateLiveAuthorizationPolicy(): void {
  loadPolicy();
}

export function mutateAuthorizationRule(
  selector: AuthorizationSelector,
  action: AuthorizationMutation,
  databaseMutation?: (
    db: Database.Database,
    nextRules: readonly AuthorizationRule[],
    nextGeneration: number,
  ) => void,
): AuthorizationState | "inherited" {
  validateAuthorizationSelector(selector);
  if (action !== "lock" && action !== "unlock" && action !== "inherit") {
    throw new Error("Invalid authorization-policy mutation.");
  }
  const descriptor = getVaultDescriptor();
  const loaded = loadPolicy();
  const key = loaded?.key ?? crypto.randomBytes(32);
  const rules = loaded ? [...loaded.rules] : [];
  const identity = ruleIdentity(selector);
  const existingIndex = rules.findIndex((item) => ruleIdentity(item) === identity);
  const existing = existingIndex === -1 ? undefined : rules[existingIndex];
  const result = action === "lock" ? "locked" : action === "unlock" ? "unlocked" : "inherited";
  if (action === "inherit") {
    if (!existing) return result;
    rules.splice(existingIndex, 1);
  } else {
    const locked = action === "lock";
    if (existing?.locked === locked) return result;
    const nextRule: AuthorizationRule = {
      ...(selector.project === undefined ? {} : { project: selector.project }),
      ...(selector.environment === undefined ? {} : { environment: selector.environment }),
      ...(selector.secret === undefined ? {} : { secret: selector.secret }),
      locked,
    };
    if (existing) rules.splice(existingIndex, 1, nextRule);
    else rules.push(nextRule);
  }
  const nextGeneration = (loaded?.generation ?? 0) + 1;
  const payload: PolicyPayload = {
    version: POLICY_VERSION,
    vaultId: descriptor.vaultId.toString("base64"),
    generation: nextGeneration,
    rules,
  };
  const document: PolicyDocument = { ...payload, mac: macPayload(payload, key) };
  const anchor: PolicyAnchor = {
    version: 1,
    key: key.toString("base64"),
    generation: payload.generation,
    documentHash: documentHash(document),
  };
  const paths = policyPaths();
  const pending: PendingPolicyMutation = {
    version: POLICY_TRANSACTION_VERSION,
    previousDocument: fs.existsSync(paths.document) ? fs.readFileSync(paths.document).toString("base64") : null,
    previousAnchor: fs.existsSync(paths.anchor) ? fs.readFileSync(paths.anchor).toString("base64") : null,
    previousGeneration: loaded?.generation ?? null,
    previousDocumentHash: loaded?.documentHash ?? null,
  };
  atomicWrite(paths.pending, `${JSON.stringify(pending)}\n`);
  let committed = false;
  try {
    atomicWrite(paths.document, `${JSON.stringify(document)}\n`);
    if (_policyMutationFaultForTests === "after-document" || _policyMutationFaultForTests === "crash-after-document") {
      throw new Error("Injected authorization-policy interruption after document publication.");
    }
    atomicWrite(paths.anchor, `${JSON.stringify(anchor)}\n`);
    if (_policyMutationFaultForTests === "after-anchor" || _policyMutationFaultForTests === "crash-after-anchor") {
      throw new Error("Injected authorization-policy interruption after anchor publication.");
    }
    writePolicyDatabaseAnchor(
      { generation: payload.generation, documentHash: anchor.documentHash },
      path.join(getVaultLocation(), "vault.db"),
      databaseMutation === undefined ? undefined : (db) => databaseMutation(db, rules, nextGeneration),
    );
    committed = true;
    if (_policyMutationFaultForTests === "crash-after-commit") {
      throw new Error("Injected authorization-policy crash after the committed generation.");
    }
    unlinkIfPresent(paths.pending);
    fsyncPolicyDirectory();
    if (_policyMutationFaultForTests === "after-commit-cleanup") {
      throw new Error("Injected authorization-policy cleanup failure after the committed generation.");
    }
  } catch (error) {
    if (committed) {
      if (_policyMutationFaultForTests === "crash-after-commit") throw error;
      return result;
    }
    if (_policyMutationFaultForTests?.startsWith("crash-")) throw error;
    recoverInterruptedPolicy(paths, descriptor.vaultId);
    throw error;
  }
  return result;
}

export function setAuthorizationRule(selector: AuthorizationSelector, locked: boolean): AuthorizationState {
  return mutateAuthorizationRule(selector, locked ? "lock" : "unlock") as AuthorizationState;
}

export async function mutateAuthorizationRuleAuthorized(
  selector: AuthorizationSelector,
  action: AuthorizationMutation,
  dependencies: {
    authorize: OperatorAuthorizer;
    ensureUnlocked: () => Promise<void>;
    validatePolicy?: typeof validateLiveAuthorizationPolicy;
    mutate?: typeof mutateAuthorizationRule;
    databaseMutation?: Parameters<typeof mutateAuthorizationRule>[2];
  },
): Promise<AuthorizationState | "inherited"> {
  validateAuthorizationSelector(selector);
  (dependencies.validatePolicy ?? validateLiveAuthorizationPolicy)();
  const target = [selector.project ?? "*", selector.environment ?? "*", selector.secret].filter((part) => part !== undefined).join("/");
  const verb = action === "lock" ? "Lock" : action === "unlock" ? "Unlock" : "Inherit";
  await dependencies.authorize(`${verb} Keyclasp authorization for ${target}`);
  await dependencies.ensureUnlocked();
  return (dependencies.mutate ?? mutateAuthorizationRule)(selector, action, dependencies.databaseMutation);
}

export async function setAuthorizationRuleAuthorized(
  selector: AuthorizationSelector,
  locked: boolean,
  dependencies: {
    authorize: OperatorAuthorizer;
    ensureUnlocked: () => Promise<void>;
    validatePolicy?: typeof validateLiveAuthorizationPolicy;
    mutate?: typeof setAuthorizationRule;
  },
): Promise<AuthorizationState> {
  return mutateAuthorizationRuleAuthorized(selector, locked ? "lock" : "unlock", {
    authorize: dependencies.authorize,
    ensureUnlocked: dependencies.ensureUnlocked,
    ...(dependencies.validatePolicy === undefined ? {} : { validatePolicy: dependencies.validatePolicy }),
    ...(dependencies.mutate === undefined ? {} : {
      mutate: (target, action) => dependencies.mutate!(target, action === "lock"),
    }),
  }) as Promise<AuthorizationState>;
}

export function appendAuthorizationPolicyAudit(selector: AuthorizationSelector, action: string, outcome: "success" | "failure"): void {
  const paths = policyPaths();
  const line = JSON.stringify({ timestamp: new Date().toISOString(), ...selector, action, outcome });
  if (fs.existsSync(paths.audit)) {
    enforceOwnerOnlyPath(paths.audit, { kind: "file", label: "authorization-policy audit log" });
  }
  const descriptor = fs.openSync(
    paths.audit,
    fs.constants.O_APPEND | fs.constants.O_CREAT | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW,
    0o600,
  );
  try {
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile() || (process.getuid?.() !== undefined && opened.uid !== process.getuid?.())) {
      throw new Error("Unsafe authorization-policy audit log.");
    }
    fs.fchmodSync(descriptor, 0o600);
    fs.writeFileSync(descriptor, `${line}\n`);
    fs.fsyncSync(descriptor);
    const current = fs.lstatSync(paths.audit);
    if (current.isSymbolicLink() || current.dev !== opened.dev || current.ino !== opened.ino) {
      throw new Error("Authorization-policy audit log changed while it was open.");
    }
  } finally {
    fs.closeSync(descriptor);
  }
  enforceOwnerOnlyPath(paths.audit, { kind: "file", label: "authorization-policy audit log" });
}

export function authorizationPolicyFiles(): string[] {
  const paths = policyPaths();
  const byName: Record<(typeof AUTHORIZATION_POLICY_BACKUP_FILES)[number], string> = {
    [POLICY_FILE]: paths.document,
    [POLICY_ANCHOR_FILE]: paths.anchor,
  };
  return AUTHORIZATION_POLICY_BACKUP_FILES.map((name) => byName[name]).filter((candidate) => fs.existsSync(candidate));
}

export function validateAuthorizationPolicyBackup(directory: string, vaultId: Buffer, expectedGeneration: number, expectedDocumentHash: string): void {
  const loaded = loadPolicyFrom({
    document: path.join(directory, POLICY_FILE),
    anchor: path.join(directory, POLICY_ANCHOR_FILE),
  }, vaultId);
  if (!loaded || loaded.generation !== expectedGeneration || loaded.documentHash !== expectedDocumentHash) {
    throw new Error("Managed backup authorization policy does not match its database anchor.");
  }
}

export function setPolicyMutationFaultForTests(fault: PolicyMutationFault | null): void {
  _policyMutationFaultForTests = fault;
}

export function recoverInterruptedAuthorizationPolicy(): boolean {
  const paths = policyPaths();
  if (!fs.existsSync(paths.pending)) return false;
  const descriptor = getVaultDescriptor();
  recoverInterruptedPolicy(paths, descriptor.vaultId);
  return true;
}

export function hasInterruptedAuthorizationPolicy(): boolean {
  return fs.existsSync(policyPaths().pending);
}
