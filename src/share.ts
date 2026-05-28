import crypto from "node:crypto";
import { resolveSecret, storeSecret } from "./vault.js";

const SHARE_VERSION = 1;

export interface SharePayload {
  version: number;
  iv: string;
  authTag: string;
  encrypted: string;
  config: { name: string; ttl: number; maxViews: number; createdAt: string; expiresAt: string };
}

export function parseTTL(ttl: string): number {
  const match = ttl.match(/^(\d+)([smhd])$/);
  if (!match) throw new Error(`Invalid TTL format: ${ttl}. Use like 24h, 7d, 30m, 60s`);
  const value = parseInt(match[1], 10);
  switch (match[2]) {
    case "s": return value;
    case "m": return value * 60;
    case "h": return value * 3600;
    case "d": return value * 86400;
    default: return value * 3600;
  }
}

export function createShareLink(
  secretName: string,
  options: { ttl?: string; maxViews?: number } = {}
): { url: string; fragment: string } {
  const value = resolveSecret(secretName);
  if (value === null) throw new Error(`Secret "${secretName}" not found`);

  const ttl = parseTTL(options.ttl || "24h");
  const maxViews = options.maxViews || 1;
  const now = new Date();
  const expiresAt = new Date(now.getTime() + ttl * 1000);

  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });
  const payload = JSON.stringify({ name: secretName, value, maxViews, expiresAt: expiresAt.toISOString() });
  const encrypted = Buffer.concat([cipher.update(payload, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const sharePayload: SharePayload = {
    version: SHARE_VERSION,
    iv: iv.toString("base64"),
    authTag: authTag.toString("base64"),
    encrypted: encrypted.toString("base64"),
    config: {
      name: secretName,
      ttl,
      maxViews,
      createdAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
    },
  };

  const payloadB64 = Buffer.from(JSON.stringify(sharePayload)).toString("base64url");
  const keyB64 = key.toString("base64url");

  return {
    url: `https://keyblind.dev/share#v${SHARE_VERSION}.${keyB64}.${payloadB64}`,
    fragment: `v${SHARE_VERSION}.${keyB64}.${payloadB64}`,
  };
}

export function receiveShare(fragment: string, targetName?: string): { name: string; value: string } {
  // Strip URL prefix if full URL was pasted
  if (fragment.includes("#")) fragment = fragment.split("#")[1];
  fragment = fragment.trim();

  // Parse: v<version>.<key>.<payload>
  const parts = fragment.split(".");
  if (parts.length < 3) throw new Error("Invalid share fragment format");

  const version = parseInt(parts[0].replace("v", ""), 10);
  if (version !== 1) throw new Error(`Unsupported share version: ${version}`);

  const keyB64 = parts[1];
  const payloadB64 = parts.slice(2).join("."); // payload may contain dots from base64

  const key = Buffer.from(keyB64, "base64url");
  const sharePayload: SharePayload = JSON.parse(
    Buffer.from(payloadB64, "base64url").toString("utf8")
  );

  // Check expiry
  if (new Date(sharePayload.config.expiresAt) < new Date()) {
    throw new Error("Share link has expired");
  }

  // Decrypt
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(sharePayload.iv, "base64"), { authTagLength: 16 });
  decipher.setAuthTag(Buffer.from(sharePayload.authTag, "base64"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(sharePayload.encrypted, "base64")),
    decipher.final(),
  ]);
  const { name, value } = JSON.parse(decrypted.toString("utf8"));

  // Store in vault
  const storeName = targetName || name;
  storeSecret(storeName, value);

  return { name: storeName, value };
}
