import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

export interface ProjectConfig {
  /** Project name for vault isolation */
  projectName?: string;
  /** Default backend */
  backend?: string;
  /** Default secret expiry in days */
  expiryDays?: number;
  /** Auto-sandbox on file change */
  autoSandbox?: boolean;
  /** Path to watch for auto-sandbox */
  watchPath?: string;
}

const CONFIG_FILE = ".keyblind";

export function getConfigPath(dir?: string): string {
  return path.join(dir || process.cwd(), CONFIG_FILE);
}

export function readConfig(dir?: string): ProjectConfig | null {
  const configPath = getConfigPath(dir);
  if (!fs.existsSync(configPath)) return null;

  try {
    const raw = fs.readFileSync(configPath, "utf8");
    return JSON.parse(raw) as ProjectConfig;
  } catch {
    return null;
  }
}

export function writeConfig(config: ProjectConfig, dir?: string): void {
  const configPath = getConfigPath(dir);
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2), { mode: 0o644 });
  console.log(`Project config written to ${configPath}`);
}

export function mergeConfig(partial: Partial<ProjectConfig>, dir?: string): ProjectConfig {
  const existing = readConfig(dir) || {};
  const merged = { ...existing, ...partial };
  writeConfig(merged, dir);
  return merged;
}

export function generateSecret(length: number = 32, symbols: boolean = true): string {
  const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const chars = symbols ? alpha + "!@#$%^&*()_-+=<>?" : alpha;
  const bytes = crypto.randomBytes(length * 2);
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars[bytes[i] % chars.length];
  }
  return result;
}

export function parseEnvFile(content: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    // Skip blank lines and comments
    if (!trimmed || trimmed.startsWith("#")) continue;

    const eqIdx = trimmed.indexOf("=");
    if (eqIdx === -1) continue;

    const key = trimmed.slice(0, eqIdx).trim();
    let value = trimmed.slice(eqIdx + 1).trim();

    // Strip surrounding quotes
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }

    if (key) result[key] = value;
  }
  return result;
}

export function formatEnvFile(secrets: Record<string, string>): string {
  const lines: string[] = [];
  for (const [key, value] of Object.entries(secrets)) {
    // Quote values with special chars
    const needsQuotes = /[\s#]/.test(value);
    lines.push(needsQuotes ? `${key}="${value}"` : `${key}=${value}`);
  }
  return lines.join("\n") + "\n";
}
