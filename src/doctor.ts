import { isInitialized, getKey, listSecrets, checkExpired, resolveSecret } from "./vault.js";
import { getBackend, listAvailableBackends } from "./backends.js";
import { readConfig } from "./config.js";
import os from "node:os";
import fs from "node:fs";
import path from "node:path";

interface CheckResult {
  name: string;
  status: "ok" | "warn" | "error";
  detail: string;
}

export function runDoctor(): CheckResult[] {
  const checks: CheckResult[] = [];

  // 1. Vault initialization
  if (isInitialized()) {
    checks.push({ name: "Vault initialized", status: "ok", detail: "~/.keyblind/ exists and has a valid key" });
  } else {
    checks.push({ name: "Vault initialized", status: "error", detail: "Not initialized. Run: keyblind init" });
  }

  // 2. Key access
  try {
    getKey();
    checks.push({ name: "Encryption key", status: "ok", detail: "Machine-identity-bound key is readable" });
  } catch {
    checks.push({ name: "Encryption key", status: "error", detail: "Cannot read key. Vault may be corrupted. Try: keyblind init" });
  }

  // 3. Secret count
  if (isInitialized()) {
    const names = listSecrets();
    checks.push({ name: "Secret count", status: "ok", detail: `${names.length} secrets` });
  }

  // 4. Expired secrets
  if (isInitialized()) {
    try {
      const expired = checkExpired();
      if (expired.length === 0) {
        checks.push({ name: "Expired secrets", status: "ok", detail: "No expired secrets" });
      } else {
        checks.push({ name: "Expired secrets", status: "warn", detail: `${expired.length} expired: ${expired.join(", ")}. Run: keyblind rotate <name>` });
      }
    } catch {
      checks.push({ name: "Expired secrets", status: "warn", detail: "Could not check expiry" });
    }
  }


  // 6. Backend connectivity
  try {
    const backends = listAvailableBackends();
    const current = getBackend();
    const available = backends.filter(b => b.available);
    checks.push({
      name: "Backend",
      status: "ok",
      detail: `Current: ${current.name}. Available: ${available.map(b => b.name).join(", ")}`,
    });
  } catch {
    checks.push({ name: "Backend", status: "warn", detail: "Could not check backends" });
  }

  // 7. Disk space for vault
  try {
    const vaultDir = path.join(os.homedir(), ".keyblind");
    // Check disk space via statfs-like approach
    const free = getDiskFree(vaultDir);
    if (free === null) {
      checks.push({ name: "Disk space", status: "ok", detail: "Could not check (non-critical)" });
    } else if (free < 10 * 1024 * 1024) {
      checks.push({ name: "Disk space", status: "warn", detail: `Low: ${formatBytes(free)} free on vault disk` });
    } else {
      checks.push({ name: "Disk space", status: "ok", detail: `${formatBytes(free)} free` });
    }
  } catch {
    checks.push({ name: "Disk space", status: "ok", detail: "Could not check (non-critical)" });
  }

  // 8. Project config
  const config = readConfig();
  if (config) {
    const parts: string[] = [];
    if (config.backend) parts.push(`backend=${config.backend}`);
    if (config.projectName) parts.push(`project=${config.projectName}`);
    if (config.expiryDays) parts.push(`expiry=${config.expiryDays}d`);
    checks.push({ name: "Project config", status: "ok", detail: `.keyblind found (${parts.join(", ") || "minimal"})` });
  } else {
    checks.push({ name: "Project config", status: "ok", detail: "No .keyblind file (optional)" });
  }

  // 9. Sandbox audit — check if any .env has unsandboxed patterns
  if (fs.existsSync(".env")) {
    const envContent = fs.readFileSync(".env", "utf8");
    const hasRealSecrets = /^(?!#)(?!.*sandbox_)[A-Z_]+=.*(?:sk-|ghp_|xox[baprs]-|AKIA|ya29\.|SG\.|eyJ)/m.test(envContent);
    if (hasRealSecrets) {
      checks.push({ name: ".env safety", status: "warn", detail: ".env may contain real API keys. Run: keyblind sandbox" });
    } else {
      checks.push({ name: ".env safety", status: "ok", detail: "No obvious real secrets detected in .env" });
    }
  } else {
    checks.push({ name: ".env safety", status: "ok", detail: "No .env file in current directory" });
  }

  return checks;
}

function getDiskFree(dirPath: string): number | null {
  try {
    // macOS/Linux compatible — try various paths
    const testPath = path.resolve(dirPath);
    // Simple approach: just check we can stat the directory
    fs.statSync(testPath);
    // Can't easily get disk free in cross-platform Node without extra deps.
    // Return null to indicate "can't check" rather than erroring.
    return null;
  } catch {
    return null;
  }
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)}GB`;
}
