import crypto from "node:crypto";
import * as jose from "jose";
import { getKey } from "./vault.js";

function getPairingSecret(): Uint8Array {
  const vaultKey = getKey();
  return new Uint8Array(crypto.createHash("sha256").update(vaultKey).digest());
}

export async function generatePairingToken(port: number = 3100): Promise<{ token: string; url: string }> {
  const nonce = crypto.randomBytes(16).toString("base64url");
  const secret = getPairingSecret();

  const token = await new jose.SignJWT({ sub: "dashboard-pair", nonce, port })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(secret);

  const url = `https://app.keyblind.dev/connect?token=${token}&port=${port}`;
  return { token, url };
}

export async function verifyPairingToken(token: string): Promise<{ valid: boolean }> {
  const secret = getPairingSecret();
  try {
    await jose.jwtVerify(token, secret);
    return { valid: true };
  } catch {
    return { valid: false };
  }
}
