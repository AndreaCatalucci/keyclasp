import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { storeSecret, resolveSecret, listSecrets } from "./vault.js";

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
    return `sk_keyblind_sandbox_${hmac}`;
  }
  if (originalValue.startsWith("ghp_") || originalValue.startsWith("gho_")) {
    return `ghp_keyblind_sandbox_${hmac}`;
  }
  if (originalValue.includes("://")) {
    try {
      const url = new URL(originalValue);
      url.username = "keyblind";
      url.password = "sandbox";
      url.hostname = "localhost";
      if (url.port) url.port = "5432";
      url.pathname = "/keyblind_db";
      return url.toString();
    } catch {
      // Not a valid URL, fall through
    }
  }
  if (originalValue.length > 20) {
    return `KEYBLIND_SANDBOX_${hmac}`;
  }

  return `KEYBLIND_SANDBOX_${hmac}`;
}

// Backup prefix: the sandbox comment marks a file as keyblind-managed
const BACKUP_COMMENT = "# @keyblind-backup:";

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
  return `__keyblind_sandbox_backup__${key}`;
}

export function sandboxEnvFile(envPath?: string): { backedUp: string[]; sandboxed: string[] } {
  const cwd = process.cwd();
  const targetPath = envPath ? path.resolve(envPath) : path.join(cwd, ".env");

  if (!fs.existsSync(targetPath)) {
    throw new Error(`File not found: ${targetPath}`);
  }

  // Check if already sandboxed
  const currentContent = fs.readFileSync(targetPath, "utf-8");
  if (currentContent.includes(BACKUP_COMMENT)) {
    throw new Error(`File ${targetPath} is already sandboxed by Keyblind. Run: keyblind unsandbox`);
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
    if (!value || value.includes("KEYBLIND_SANDBOX") || value.includes("keyblind_sandbox")) {
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
  storeSecret("__keyblind_env_backup", currentContent);

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
  if (!content.includes(BACKUP_COMMENT)) {
    throw new Error(`File ${targetPath} is not sandboxed by Keyblind. Nothing to restore.`);
  }

  // Restore from vault backup
  const originalContent = resolveSecret("__keyblind_env_backup");
  if (originalContent) {
    fs.writeFileSync(targetPath, originalContent, "utf-8");
  }

  // Clean up backup secrets
  const allSecrets = listSecrets();
  const restored: string[] = [];
  for (const name of allSecrets) {
    if (name.startsWith("__keyblind_sandbox_backup__")) {
      restored.push(name.replace("__keyblind_sandbox_backup__", ""));
    }
  }

  return restored;
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function getEnvBackups(): Map<string, string> {
  const result = new Map<string, string>();
  for (const name of listSecrets()) {
    if (name.startsWith("__keyblind_sandbox_backup__")) {
      const realKey = name.replace("__keyblind_sandbox_backup__", "");
      const value = resolveSecret(name);
      if (value) result.set(realKey, value);
    }
  }
  return result;
}
