import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { storeSecret, resolveSecret, listSecretNamesByPrefixes } from "./vault.js";

function getProjectHash(): string {
  const cwd = process.cwd();
  return crypto.createHash("sha256").update(cwd).digest("hex").slice(0, 16);
}

function generateFakeValue(keyName: string, originalValue: string): string {
  const projectHash = getProjectHash();
  const hmac = crypto
    .createHmac("sha256", projectHash)
    .update(keyName)
    .digest("hex")
    .slice(0, 16);

  // Generate deterministic fakes that look realistic
  if (originalValue.startsWith("sk-") || originalValue.startsWith("pk-")) {
    return `sk_keyclasp_sandbox_${hmac}`;
  }
  if (originalValue.startsWith("ghp_") || originalValue.startsWith("gho_")) {
    return `ghp_keyclasp_sandbox_${hmac}`;
  }
  if (originalValue.includes("://")) {
    try {
      const url = new URL(originalValue);
      url.username = "keyclasp";
      url.password = "sandbox";
      url.hostname = "localhost";
      if (url.port) url.port = "5432";
      url.pathname = "/keyclasp_db";
      return url.toString();
    } catch {
      // Not a valid URL, fall through
    }
  }
  if (originalValue.length > 20) {
    return `KEYCLASP_SANDBOX_${hmac}`;
  }

  return `KEYCLASP_SANDBOX_${hmac}`;
}

// Backup prefix: the sandbox comment marks a file as keyclasp-managed
const BACKUP_COMMENT = "# @keyclasp-backup:";
const LEGACY_BACKUP_COMMENT = "# @keyblind-backup:";
const BACKUP_PREFIX = "__keyclasp_sandbox_backup__";
const LEGACY_BACKUP_PREFIX = "__keyblind_sandbox_backup__";
const BACKUP_PREFIXES = [BACKUP_PREFIX, LEGACY_BACKUP_PREFIX] as const;
const ENV_BACKUP_NAME = "__keyclasp_env_backup";
const LEGACY_ENV_BACKUP_NAME = "__keyblind_env_backup";

function listBackupSecretNames(): string[] {
  return listSecretNamesByPrefixes(BACKUP_PREFIXES);
}

function getBackedUpKey(name: string): string | null {
  const prefix = BACKUP_PREFIXES.find((candidate) => name.startsWith(candidate));
  return prefix ? name.slice(prefix.length) : null;
}

function parseEnvFile(content: string): Map<string, string> {
  const result = new Map<string, string>();
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    let value = trimmed.slice(eqIdx + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    result.set(key, value);
  }
  return result;
}

function getBackupSecretName(key: string): string {
  return `${BACKUP_PREFIX}${key}`;
}

function getEnvBackupName(content: string): string {
  const hasCurrentMarker = content.includes(BACKUP_COMMENT);
  const hasLegacyMarker = content.includes(LEGACY_BACKUP_COMMENT);

  if (hasCurrentMarker && hasLegacyMarker) {
    throw new Error("File contains both Keyclasp and Keyblind sandbox markers. Refusing to restore an ambiguous backup.");
  }

  return hasLegacyMarker ? LEGACY_ENV_BACKUP_NAME : ENV_BACKUP_NAME;
}

export function sandboxEnvFile(envPath?: string): { backedUp: string[]; sandboxed: string[] } {
  const cwd = process.cwd();
  const targetPath = envPath ? path.resolve(envPath) : path.join(cwd, ".env");

  if (!fs.existsSync(targetPath)) {
    throw new Error(`File not found: ${targetPath}`);
  }

  // Check if already sandboxed
  const currentContent = fs.readFileSync(targetPath, "utf-8");
  if (currentContent.includes(BACKUP_COMMENT) || currentContent.includes(LEGACY_BACKUP_COMMENT)) {
    throw new Error(`File ${targetPath} is already sandboxed by Keyclasp. Run: keyclasp unsandbox`);
  }

  const entries = parseEnvFile(currentContent);
  if (entries.size === 0) {
    throw new Error(`No KEY=VALUE pairs found in ${targetPath}`);
  }

  const backedUp: string[] = [];
  const sandboxed: string[] = [];
  let result = currentContent;

  for (const [key, value] of entries) {
    // Skip already-fake values and empty values
    if (!value || /KEY(?:CLASP|BLIND)_SANDBOX|key(?:clasp|blind)_sandbox/.test(value)) {
      continue;
    }

    // Backup real value to vault
    const backupName = getBackupSecretName(key);
    storeSecret(backupName, value);
    backedUp.push(key);

    // Generate and replace with fake
    const fakeValue = generateFakeValue(key, value);
    // Replace first occurrence of the value for this key
    const regex = new RegExp(`(${escapeRegex(key)}\\s*=\\s*)${escapeRegex(value)}`, "g");
    result = result.replace(regex, `$1${fakeValue}`);
    sandboxed.push(key);
  }

  // Add backup comment header
  const backupData = JSON.stringify({ backedUp, timestamp: new Date().toISOString() });
  result = `${BACKUP_COMMENT}${backupData}\n${result}`;

  // Back up original to vault before overwriting
  storeSecret(ENV_BACKUP_NAME, currentContent);

  fs.writeFileSync(targetPath, result, "utf-8");
  return { backedUp, sandboxed };
}

export function unsandboxEnvFile(envPath?: string): string[] {
  const cwd = process.cwd();
  const targetPath = envPath ? path.resolve(envPath) : path.join(cwd, ".env");

  if (!fs.existsSync(targetPath)) {
    throw new Error(`File not found: ${targetPath}`);
  }

  const content = fs.readFileSync(targetPath, "utf-8");
  if (!content.includes(BACKUP_COMMENT) && !content.includes(LEGACY_BACKUP_COMMENT)) {
    throw new Error(`File ${targetPath} is not sandboxed by Keyclasp. Nothing to restore.`);
  }

  // Restore from vault backup
  const originalContent = resolveSecret(getEnvBackupName(content));
  if (originalContent) {
    fs.writeFileSync(targetPath, originalContent, "utf-8");
  }

  // Clean up backup secrets
  const restored: string[] = [];
  for (const name of listBackupSecretNames()) {
    const key = getBackedUpKey(name);
    if (key) restored.push(key);
  }

  return restored;
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function getEnvBackups(): Map<string, string> {
  const result = new Map<string, string>();
  for (const name of listBackupSecretNames()) {
    const key = getBackedUpKey(name);
    const value = resolveSecret(name);
    if (key && value) result.set(key, value);
  }
  return result;
}
