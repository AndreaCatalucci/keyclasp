import { isInitialized, getKey, getVaultLocation, listSecrets, checkExpired, checkVaultDecryptability } from "./vault.js";
import { getBackend, listAvailableBackends } from "./backends.js";
import { readConfig } from "./config.js";
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
    checks.push({ name: "Vault initialized", status: "ok", detail: `${getVaultLocation()} exists with a key file` });
  } else {
    checks.push({ name: "Vault initialized", status: "error", detail: "Not initialized. Run: keyclasp init" });
  }

  // 2. Key access
  try {
    getKey();
    checks.push({ name: "Encryption key", status: "ok", detail: "Key file is readable" });
  } catch {
    checks.push({ name: "Encryption key", status: "error", detail: "Cannot read key. Vault may be corrupted. Try: keyclasp init" });
  }

  // 3. Secret count
  if (isInitialized()) {
    const names = listSecrets();
    checks.push({ name: "Secret count", status: "ok", detail: `${names.length} secrets` });
  }

  // 4. Stored value decryptability
  if (isInitialized()) {
    try {
      const result = checkVaultDecryptability();
      if (result.checked === 0) {
        checks.push({ name: "Secret decryptability", status: "ok", detail: "No stored secret values to check" });
      } else if (result.failures.length === 0) {
        checks.push({ name: "Secret decryptability", status: "ok", detail: `${result.checked} stored secret value(s) decryptable` });
      } else {
        const examples = result.failures.slice(0, 5).map((failure) => failure.name).join(", ");
        const suffix = result.failures.length > 5 ? `, +${result.failures.length - 5} more` : "";
        checks.push({
          name: "Secret decryptability",
          status: "error",
          detail: `${result.failures.length}/${result.checked} stored secret value(s) cannot be decrypted by the current key: ${examples}${suffix}`,
        });
      }
    } catch (err: any) {
      checks.push({ name: "Secret decryptability", status: "error", detail: `Could not verify stored secret values: ${err?.message ?? "unknown error"}` });
    }
  }

  // 5. Expired secrets
  if (isInitialized()) {
    try {
      const expired = checkExpired();
      if (expired.length === 0) {
        checks.push({ name: "Expired secrets", status: "ok", detail: "No expired secrets" });
      } else {
        checks.push({ name: "Expired secrets", status: "warn", detail: `${expired.length} expired: ${expired.join(", ")}. Run: keyclasp rotate <name>` });
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
    const vaultDir = getVaultLocation();
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
    checks.push({ name: "Project config", status: "ok", detail: `.keyclasp found (${parts.join(", ") || "minimal"})` });
  } else {
    checks.push({ name: "Project config", status: "ok", detail: "No .keyclasp file (optional)" });
  }

  // 9. Sandbox audit — check if any .env has unsandboxed patterns
  if (fs.existsSync(".env")) {
    const envContent = fs.readFileSync(".env", "utf8");
    const hasRealSecrets = /^(?!#)(?!.*sandbox_)[A-Z_]+=.*(?:sk-|ghp_|xox[baprs]-|AKIA|ya29\.|SG\.|eyJ)/m.test(envContent);
    if (hasRealSecrets) {
      checks.push({ name: ".env safety", status: "warn", detail: ".env may contain real API keys. Run: keyclasp sandbox" });
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
