import crypto from "node:crypto";

// Same Ed25519 public key baked into the CLI binary
const PUBLIC_KEY_BASE64 =
  process.env.KEYBLIND_PUBLIC_KEY ||
  "MCowBQYDK2VwAyEAaxu7ncsxw3rW0Sycd9iIVu4prMKbsjN9hZghJYI2LoY=";

export interface LicenseInfo {
  tier: "free" | "pro" | "team";
  email: string;
  exp: string; // YYYY-MM-DD
  iat: string; // YYYY-MM-DD
  id: string;
}

export function verifyLicenseKey(key: string): LicenseInfo | null {
  try {
    if (!key || !key.startsWith("keyblind.")) return null;

    const parts = key.slice("keyblind.".length).split(".");
    if (parts.length !== 2) return null;

    const payloadJson = Buffer.from(parts[0], "base64url").toString("utf8");
    const signature = Buffer.from(parts[1], "base64url");
    const payload: LicenseInfo = JSON.parse(payloadJson);

    // Validate required fields
    if (!payload.tier || !payload.email || !payload.exp || !payload.iat || !payload.id) return null;
    if (!["free", "pro", "team"].includes(payload.tier)) return null;

    // Check expiry
    const expDate = new Date(payload.exp + "T23:59:59Z");
    if (expDate < new Date()) return null;

    // Verify Ed25519 signature
    const pubKey = crypto.createPublicKey({
      key: Buffer.from(PUBLIC_KEY_BASE64, "base64"),
      format: "der",
      type: "spki",
    });

    const data = Buffer.from(JSON.stringify(payload));
    const valid = crypto.verify(null, data, pubKey, signature);

    return valid ? payload : null;
  } catch {
    return null;
  }
}
