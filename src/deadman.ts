import crypto from "node:crypto";
import { storeSecret, resolveSecret, deleteSecret, getKey } from "./vault.js";

const DEADMAN_PREFIX = "_keyblind_deadman";
const CONFIG_KEY = `${DEADMAN_PREFIX}:config`;
const CHECKIN_KEY = `${DEADMAN_PREFIX}:last_checkin`;

export interface DeadmanConfig {
  enabled: boolean;
  days: number;
  contactEmail: string;
  contactPublicKey?: string;
  message?: string;
  createdAt: string;
  updatedAt: string;
}

export interface DeadmanStatus {
  enabled: boolean;
  daysConfigured: number;
  daysSinceCheckin: number;
  daysRemaining: number;
  contactEmail: string;
  lastCheckin: string | null;
  nextDeadline: string;
  triggered: boolean;
}

function getDefaultConfig(): DeadmanConfig {
  return {
    enabled: false,
    days: 30,
    contactEmail: "",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
}

export function setupDeadman(config: {
  days: number;
  contactEmail: string;
  contactPublicKey?: string;
  message?: string;
}): void {
  const existing = getDeadmanConfig();
  const cfg: DeadmanConfig = {
    enabled: true,
    days: config.days,
    contactEmail: config.contactEmail,
    contactPublicKey: config.contactPublicKey,
    message: config.message,
    createdAt: existing?.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  storeSecret(CONFIG_KEY, JSON.stringify(cfg));
}

export function getDeadmanConfig(): DeadmanConfig | null {
  const raw = resolveSecret(CONFIG_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export function checkin(): void {
  storeSecret(CHECKIN_KEY, new Date().toISOString());
}

export function getDeadmanStatus(): DeadmanStatus {
  const config = getDeadmanConfig();
  if (!config || !config.enabled) {
    return {
      enabled: false,
      daysConfigured: 0,
      daysSinceCheckin: 0,
      daysRemaining: 0,
      contactEmail: "",
      lastCheckin: null,
      nextDeadline: "",
      triggered: false,
    };
  }

  const lastRaw = resolveSecret(CHECKIN_KEY);
  const lastCheckin = lastRaw ? new Date(lastRaw) : null;
  const now = new Date();
  const daysSinceCheckin = lastCheckin
    ? Math.floor((now.getTime() - lastCheckin.getTime()) / (24 * 60 * 60 * 1000))
    : Math.floor((now.getTime() - new Date(config.createdAt).getTime()) / (24 * 60 * 60 * 1000));

  const daysRemaining = Math.max(0, config.days - daysSinceCheckin);
  const nextDeadline = lastCheckin
    ? new Date(lastCheckin.getTime() + config.days * 24 * 60 * 60 * 1000)
    : new Date(new Date(config.createdAt).getTime() + config.days * 24 * 60 * 60 * 1000);

  return {
    enabled: true,
    daysConfigured: config.days,
    daysSinceCheckin,
    daysRemaining,
    contactEmail: config.contactEmail,
    lastCheckin: lastCheckin?.toISOString() || null,
    nextDeadline: nextDeadline.toISOString(),
    triggered: daysSinceCheckin >= config.days,
  };
}

export function disableDeadman(): void {
  const config = getDeadmanConfig();
  if (config) {
    config.enabled = false;
    config.updatedAt = new Date().toISOString();
    storeSecret(CONFIG_KEY, JSON.stringify(config));
  }
}

export function checkDeadmanTrigger(): boolean {
  const status = getDeadmanStatus();
  return status.triggered;
}

export function encryptKeyShard(): string | null {
  const config = getDeadmanConfig();
  if (!config || !config.contactPublicKey) return null;

  const key = getKey();
  const shard = crypto.createHash("sha256").update(key).update("deadman-shard-v1").digest();

  try {
    const publicKey = crypto.createPublicKey({
      key: config.contactPublicKey,
      format: "pem",
      type: "spki",
    });
    return crypto.publicEncrypt(publicKey, shard).toString("base64");
  } catch {
    return null;
  }
}
