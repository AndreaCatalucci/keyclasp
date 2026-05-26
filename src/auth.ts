import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const SESSION_FILE = path.join(os.homedir(), ".keyblind", ".session");
const SESSION_TTL_MS = 15 * 60 * 1000; // 15 minutes

function isMacOS(): boolean {
  return process.platform === "darwin";
}

export function biometricAvailable(): boolean {
  if (!isMacOS()) return false;

  try {
    // Check if Touch ID is enrolled via bioutil
    const result = execSync("bioutil -r", { encoding: "utf-8", stdio: ["pipe", "pipe", "ignore"] });
    return result.includes("Touch ID") && !result.includes("Touch ID: 0 fingerprint");
  } catch {
    return false;
  }
}

export function authenticateWithBiometric(reason: string): boolean {
  if (!isMacOS()) {
    console.error("Biometric auth is only available on macOS.");
    return false;
  }

  try {
    // Drop any cached sudo credentials, then run a sudo command to trigger
    // Touch ID via PAM. The user sees the system Touch ID dialog.
    execSync("sudo -K", { stdio: "ignore" });
    execSync(`sudo -p "🔑 ${reason} — authenticate with Touch ID: " echo "keyblind-auth"`, {
      stdio: "inherit",
    });
    return true;
  } catch {
    return false;
  }
}

export function createSession(): string {
  const vaultDir = path.dirname(SESSION_FILE);
  if (!fs.existsSync(vaultDir)) {
    fs.mkdirSync(vaultDir, { mode: 0o700 });
  }

  // Write a session token with TTL
  const token = Buffer.from(`${Date.now() + SESSION_TTL_MS}`).toString("base64");
  fs.writeFileSync(SESSION_FILE, token, { mode: 0o600 });
  return token;
}

export function sessionActive(): boolean {
  try {
    const data = fs.readFileSync(SESSION_FILE, "utf-8");
    const expiry = Number(Buffer.from(data, "base64").toString("utf-8"));
    return Date.now() < expiry;
  } catch {
    return false;
  }
}

export function clearSession(): void {
  try {
    fs.unlinkSync(SESSION_FILE);
  } catch {
    // File doesn't exist, that's fine
  }
}
