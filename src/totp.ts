import crypto from "node:crypto";
import { storeSecret, resolveSecret, listSecrets, deleteSecret } from "./vault.js";

const TOTP_PREFIX = "_totp:";

export interface TOTPConfig {
  name: string;
  uri: string;
  secret: string;
  algorithm: "SHA1" | "SHA256" | "SHA512";
  digits: number;
  period: number;
  issuer?: string;
  account?: string;
}

function base32ToBuffer(base32: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  base32 = base32.toUpperCase().replace(/=+$/, "").replace(/\s/g, "");
  const bits: number[] = [];
  for (const char of base32) {
    const val = alphabet.indexOf(char);
    if (val === -1) continue;
    for (let i = 4; i >= 0; i--) bits.push((val >> i) & 1);
  }
  const bytes: number[] = [];
  for (let i = 0; i + 7 < bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i + j];
    bytes.push(byte);
  }
  return Buffer.from(bytes);
}

export function parseOTPAuthURI(uri: string): TOTPConfig {
  const url = new URL(uri);
  if (url.protocol !== "otpauth:") throw new Error("Invalid OTP auth URI: must use otpauth://");

  const type = url.hostname;
  if (type !== "totp" && type !== "hotp") throw new Error(`Unsupported OTP type: ${type}`);

  const label = decodeURIComponent(url.pathname.replace(/^\//, ""));
  const [issuerFromLabel, account] = label.includes(":") ? label.split(":", 2) : [undefined, label];

  const params = url.searchParams;
  const secret = params.get("secret");
  if (!secret) throw new Error("Missing secret parameter in OTP URI");

  return {
    name: label,
    uri,
    secret,
    algorithm: (params.get("algorithm") || "SHA1") as "SHA1" | "SHA256" | "SHA512",
    digits: parseInt(params.get("digits") || "6", 10),
    period: parseInt(params.get("period") || "30", 10),
    issuer: params.get("issuer") || issuerFromLabel || undefined,
    account: account || label,
  };
}

export function generateHOTP(
  secret: Buffer,
  counter: number,
  digits: number = 6,
  algorithm: string = "SHA1"
): string {
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigInt64BE(BigInt(counter));
  const hmac = crypto.createHmac(algorithm.replace("SHA", "sha"), secret).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  const otp = binary % Math.pow(10, digits);
  return String(otp).padStart(digits, "0");
}

export function generateTOTP(
  secret: Buffer,
  digits: number = 6,
  period: number = 30,
  algorithm: string = "SHA1"
): string {
  const counter = Math.floor(Date.now() / 1000 / period);
  return generateHOTP(secret, counter, digits, algorithm);
}

export function timeRemaining(period: number = 30): number {
  return period - (Math.floor(Date.now() / 1000) % period);
}

export function storeTOTP(name: string, uri: string): void {
  parseOTPAuthURI(uri); // validate
  storeSecret(`${TOTP_PREFIX}${name}`, uri);
}

export function getTOTP(name: string): TOTPConfig | null {
  const uri = resolveSecret(`${TOTP_PREFIX}${name}`);
  if (!uri) return null;
  try {
    return parseOTPAuthURI(uri);
  } catch {
    return null;
  }
}

export function listTOTP(): string[] {
  return listSecrets()
    .filter((n) => n.startsWith(TOTP_PREFIX))
    .map((n) => n.slice(TOTP_PREFIX.length));
}

export function deleteTOTP(name: string): boolean {
  return deleteSecret(`${TOTP_PREFIX}${name}`);
}

export function generateTOTPCode(name: string): { code: string; remaining: number } | null {
  const config = getTOTP(name);
  if (!config) return null;
  const secretBuffer = base32ToBuffer(config.secret);
  const code = generateTOTP(secretBuffer, config.digits, config.period, config.algorithm);
  const remaining = timeRemaining(config.period);
  return { code, remaining };
}
