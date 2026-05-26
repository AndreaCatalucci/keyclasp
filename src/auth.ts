import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const SESSION_FILE = path.join(os.homedir(), ".keyblind", ".session");
const SESSION_TTL_MS = 15 * 60 * 1000;

function platform(): "darwin" | "win32" | "linux" | "other" {
  const p = process.platform;
  if (p === "darwin" || p === "win32" || p === "linux") return p;
  return "other";
}

// --- Biometric availability ---

export function biometricAvailable(): boolean {
  const p = platform();
  try {
    switch (p) {
      case "darwin": {
        const result = execSync("bioutil -r", { encoding: "utf-8", stdio: ["pipe", "pipe", "ignore"] });
        return result.includes("Touch ID") && !result.includes("Touch ID: 0 fingerprint");
      }
      case "win32": {
        try {
          const result = execSync(
            'powershell -Command "(Get-WmiObject -Namespace root\\cimv2\\security\\MicrosoftTpm -Class Win32_Tpm).IsActivated_InitialValue"',
            { encoding: "utf-8", stdio: ["pipe", "pipe", "ignore"] },
          );
          return result.trim() === "True";
        } catch {
          // Fallback: check via registry
          try {
            execSync(
              'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers" 2>nul',
              { stdio: "ignore" },
            );
            return true; // Windows Hello credential providers exist
          } catch {
            return false;
          }
        }
      }
      case "linux":
        return execSync("which pkexec", { stdio: "ignore" }) !== null;
      default:
        return false;
    }
  } catch {
    return false;
  }
}

// --- Biometric authentication ---

export function authenticateWithBiometric(reason: string): boolean {
  const p = platform();
  if (p === "other") {
    console.error("Biometric auth is only available on macOS, Windows, and Linux.");
    return false;
  }

  const prompt = `🔑 ${reason}`;

  try {
    switch (p) {
      case "darwin": {
        execSync("sudo -K", { stdio: "ignore" });
        execSync(`sudo -p "${prompt} — authenticate with Touch ID: " echo "keyblind-auth"`, {
          stdio: "inherit",
        });
        return true;
      }
      case "win32": {
        const script = `
          Add-Type -AssemblyName System.Windows.Forms
          Add-Type -AssemblyName System.Security
          $verify = [Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync("${prompt}")
          while (-not $verify.AsyncWaitHandle.WaitOne(200)) { }
          exit ($verify.GetAwaiter().GetResult() -eq [Windows.Security.Credentials.UI.UserConsentVerificationResult]::Verified ? 0 : 1)
        `;
        execSync(`powershell -NoProfile -Command "${script.replace(/\n/g, " ").replace(/"/g, '\\"')}"`, {
          stdio: "inherit",
        });
        return true;
      }
      case "linux": {
        execSync(`pkexec --user $(whoami) echo "keyblind-auth"`, {
          stdio: "inherit",
        });
        return true;
      }
      default:
        return false;
    }
  } catch {
    return false;
  }
}

// --- Session management ---

export function createSession(): string {
  const vaultDir = path.dirname(SESSION_FILE);
  if (!fs.existsSync(vaultDir)) {
    fs.mkdirSync(vaultDir, { mode: 0o700 });
  }

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
