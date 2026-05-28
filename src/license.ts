import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

// Ed25519 public key (baked into binary — the private key never ships)
const PUBLIC_KEY_BASE64 = process.env.KEYBLIND_PUBLIC_KEY || "";

function getPublicKey(): crypto.KeyObject {
  if (!PUBLIC_KEY_BASE64) {
    throw new Error(
      "License validation is not available in this build. " +
      "Use the official npm package: npm install -g keyblind"
    );
  }
  return crypto.createPublicKey({
    key: Buffer.from(PUBLIC_KEY_BASE64, "base64"),
    format: "der",
    type: "spki",
  });
}

export interface LicenseInfo {
  tier: "free" | "pro" | "team";
  email: string;
  exp: string; // YYYY-MM-DD
  iat: string; // YYYY-MM-DD
  id: string;
}

interface StoredLicense {
  key: string;
  activatedAt: string;
  info: LicenseInfo;
}

function getLicensePath(): string {
  return path.join(os.homedir(), ".keyblind", "license.json");
}

function parseLicenseKey(key: string): { payload: LicenseInfo; signature: Buffer } | null {
  try {
    // Format: keyblind.<base64url(payload)>.<base64url(sig)>
    if (!key.startsWith("keyblind.")) return null;
    const parts = key.slice("keyblind.".length).split(".");
    if (parts.length !== 2) return null;

    const payloadJson = Buffer.from(parts[0], "base64url").toString("utf8");
    const signature = Buffer.from(parts[1], "base64url");

    const payload: LicenseInfo = JSON.parse(payloadJson);

    // Validate required fields
    if (!payload.tier || !payload.email || !payload.exp || !payload.iat || !payload.id) {
      return null;
    }
    if (!["free", "pro", "team"].includes(payload.tier)) {
      return null;
    }

    return { payload, signature };
  } catch {
    return null;
  }
}

function verifyLicenseKey(key: string): LicenseInfo | null {
  const parsed = parseLicenseKey(key);
  if (!parsed) return null;

  const { payload, signature } = parsed;

  // Reconstruct the signed data
  const data = Buffer.from(JSON.stringify(payload));

  // Verify Ed25519 signature
  try {
    const pubKey = getPublicKey();
    const valid = crypto.verify(null, data, pubKey, signature);
    if (!valid) return null;
  } catch {
    return null;
  }

  // Check expiry
  const expDate = new Date(payload.exp + "T23:59:59Z");
  if (Date.now() > expDate.getTime()) {
    return null; // Expired
  }

  return payload;
}

export function isActivated(): boolean {
  try {
    const info = getLicenseInfo();
    return info !== null && info.tier !== "free";
  } catch {
    return false;
  }
}

export function isPro(): boolean {
  try {
    const info = getLicenseInfo();
    return info !== null && (info.tier === "pro" || info.tier === "team");
  } catch {
    return false;
  }
}

export function isTeam(): boolean {
  try {
    const info = getLicenseInfo();
    return info !== null && info.tier === "team";
  } catch {
    return false;
  }
}

export function getLicenseInfo(): LicenseInfo | null {
  const licensePath = getLicensePath();
  if (!fs.existsSync(licensePath)) return null;

  try {
    const stored: StoredLicense = JSON.parse(fs.readFileSync(licensePath, "utf8"));
    // Re-verify on every read (catches tampering)
    const info = verifyLicenseKey(stored.key);
    if (!info) {
      // License is no longer valid — clean up
      fs.unlinkSync(licensePath);
      return null;
    }
    return info;
  } catch {
    return null;
  }
}

export function activateLicense(key: string): { success: boolean; message: string; info?: LicenseInfo } {
  // Check if already activated
  const existing = getLicenseInfo();
  if (existing) {
    return {
      success: false,
      message: `Already activated with ${existing.tier} tier (${existing.email}). Run 'keyblind deactivate' first to switch.`,
      info: existing,
    };
  }

  const info = verifyLicenseKey(key);
  if (!info) {
    return {
      success: false,
      message: "Invalid or expired license key. Please check the key and try again.",
    };
  }

  // Store activation
  const licensePath = getLicensePath();
  const dir = path.dirname(licensePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  const stored: StoredLicense = {
    key,
    activatedAt: new Date().toISOString(),
    info,
  };

  fs.writeFileSync(licensePath, JSON.stringify(stored, null, 2), { mode: 0o600 });

  const tierLabel = info.tier === "team" ? "Team" : info.tier === "pro" ? "Pro" : "Free";
  return {
    success: true,
    message: `Keyblind ${tierLabel} activated for ${info.email}. Expires ${info.exp}.`,
    info,
  };
}

export function deactivateLicense(): { success: boolean; message: string } {
  const licensePath = getLicensePath();
  if (!fs.existsSync(licensePath)) {
    return { success: false, message: "No license is currently activated." };
  }

  try {
    const stored: StoredLicense = JSON.parse(fs.readFileSync(licensePath, "utf8"));
    fs.unlinkSync(licensePath);
    return {
      success: true,
      message: `Deactivated ${stored.info.tier} tier license (${stored.info.email}).`,
    };
  } catch {
    // Corrupt license file — just remove it
    try { fs.unlinkSync(licensePath); } catch {}
    return { success: true, message: "License file removed." };
  }
}

export function getSecretLimit(): number {
  // Dev/CI mode — bypass limit for testing
  if (process.env.KEYBLIND_DEV === "true") return Infinity;
  const info = getLicenseInfo();
  if (info && info.tier !== "free") return Infinity;
  return 5; // Free tier: 5 secrets
}

export function featuresEnabled(): {
  teamVaults: boolean;
  auditLog: boolean;
  secretRotation: boolean;
  ciAction: boolean;
  biometricGate: boolean;
  cloudBackends: boolean;
  unlimitedSecrets: boolean;
} {
  const pro = isPro();
  const team = isTeam();
  return {
    teamVaults: pro,
    auditLog: pro,
    secretRotation: pro,
    ciAction: pro,
    biometricGate: pro,
    cloudBackends: pro,
    unlimitedSecrets: pro,
  };
}
