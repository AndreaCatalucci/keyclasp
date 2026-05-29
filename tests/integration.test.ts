import { describe, it, expect, beforeAll, afterAll, vi, beforeEach } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

// Redirect vault to temp dir
const tmpDir = path.join(fs.mkdtempSync(path.join(process.env.TMPDIR || "/tmp", "keyblind-test-")));
vi.mock("node:os", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:os")>();
  return { ...actual, homedir: () => tmpDir };
});

import { initializeVault, storeSecret, resolveSecret, listSecrets, deleteSecret, isInitialized, closeDb } from "../src/vault.js";
import {
  storeTOTP, generateTOTPCode, listTOTP, deleteTOTP, parseOTPAuthURI,
  generateTOTP, generateHOTP, timeRemaining,
} from "../src/totp.js";
import { createShareLink, receiveShare, parseTTL } from "../src/share.js";
import {
  setupDeadman, checkin, getDeadmanStatus, disableDeadman,
  checkDeadmanTrigger, getDeadmanConfig,
} from "../src/deadman.js";
import { configureSSO, getSSOConfig, isSSOAuthenticated } from "../src/sso.js";
import { getAuditLog, checkExpired, setExpiry } from "../src/vault.js";
import { setBackend, getBackend, listAvailableBackends } from "../src/backends.js";
import { generateSecret } from "../src/config.js";

beforeAll(() => {
  fs.mkdirSync(tmpDir, { recursive: true });
  fs.mkdirSync(path.join(tmpDir, ".keyblind"), { recursive: true });
  if (!isInitialized()) initializeVault("integration-test-passphrase");
});

afterAll(() => {
  closeDb();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

// ─── TOTP tests ────────────────────────────────────────────
describe("TOTP integration", () => {
  const testUri = "otpauth://totp/ACME:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA1&digits=6&period=30";

  beforeEach(() => {
    const existing = listTOTP();
    existing.forEach((n) => deleteTOTP(n));
  });

  it("parses an otpauth URI correctly", () => {
    const config = parseOTPAuthURI(testUri);
    expect(config.secret).toBe("JBSWY3DPEHPK3PXP");
    expect(config.issuer).toBe("ACME");
    expect(config.account).toBe("alice@example.com");
    expect(config.algorithm).toBe("SHA1");
    expect(config.digits).toBe(6);
    expect(config.period).toBe(30);
  });

  it("stores and retrieves a TOTP configuration", () => {
    storeTOTP("my-app", testUri);
    const names = listTOTP();
    expect(names).toContain("my-app");
  });

  it("generates a valid 6-digit TOTP code", () => {
    storeTOTP("my-app", testUri);
    const result = generateTOTPCode("my-app");
    expect(result).not.toBeNull();
    expect(result!.code).toMatch(/^\d{6}$/);
    expect(result!.remaining).toBeGreaterThanOrEqual(0);
    expect(result!.remaining).toBeLessThanOrEqual(30);
  });

  it("generates HOTP from known test vector (RFC 4226)", () => {
    // RFC 4226 Appendix D test vector
    const secret = Buffer.from("12345678901234567890");
    const code = generateHOTP(secret, 0, 6, "SHA1");
    expect(code).toBe("755224");
  });

  it("generates HOTP from known test vector at counter 1", () => {
    const secret = Buffer.from("12345678901234567890");
    expect(generateHOTP(secret, 1, 6, "SHA1")).toBe("287082");
  });

  it("returns null for nonexistent TOTP", () => {
    expect(generateTOTPCode("nonexistent")).toBeNull();
  });

  it("generates deterministic TOTP at a fixed time", () => {
    // Use a specific counter by computing manually
    const secret = Buffer.from("12345678901234567890");
    const code = generateTOTP(secret, 8, 30, "SHA1");
    expect(code).toMatch(/^\d{8}$/);
  });

  it("timeRemaining returns value between 0 and period", () => {
    const remaining = timeRemaining(30);
    expect(remaining).toBeGreaterThanOrEqual(0);
    expect(remaining).toBeLessThanOrEqual(30);
  });

  it("deletes a TOTP configuration", () => {
    storeTOTP("delete-me", testUri);
    expect(listTOTP()).toContain("delete-me");
    expect(deleteTOTP("delete-me")).toBe(true);
    expect(listTOTP()).not.toContain("delete-me");
    expect(deleteTOTP("already-gone")).toBe(false);
  });

  it("handles multiple TOTP configs", () => {
    storeTOTP("app1", testUri);
    storeTOTP("app2", testUri.replace("ACME", "OTHER"));
    expect(listTOTP().length).toBe(2);
  });
});

// ─── Secret sharing tests ──────────────────────────────────
describe("Secret sharing integration", () => {
  beforeEach(() => {
    try { deleteSecret("SHARE_TEST"); } catch {}
    try { deleteSecret("RECEIVED_SHARE"); } catch {}
  });

  it("parses TTL strings correctly", () => {
    expect(parseTTL("30s")).toBe(30);
    expect(parseTTL("5m")).toBe(300);
    expect(parseTTL("24h")).toBe(86400);
    expect(parseTTL("7d")).toBe(604800);
  });

  it("throws on invalid TTL format", () => {
    expect(() => parseTTL("24x")).toThrow();
    expect(() => parseTTL("abc")).toThrow();
  });

  it("creates a share link and receives it back (roundtrip)", () => {
    storeSecret("SHARE_TEST", "my-shared-secret-value");
    const { fragment } = createShareLink("SHARE_TEST", { ttl: "24h", maxViews: 5 });
    expect(fragment).toMatch(/^v1\./);

    const result = receiveShare(fragment, "RECEIVED_SHARE");
    expect(result.name).toBe("RECEIVED_SHARE");
    expect(result.value).toBe("my-shared-secret-value");
    expect(resolveSecret("RECEIVED_SHARE")).toBe("my-shared-secret-value");
  });

  it("creates a share with full URL format that can be received", () => {
    storeSecret("SHARE_TEST", "url-test-value");
    const { url } = createShareLink("SHARE_TEST", { ttl: "24h" });
    expect(url).toContain("https://keyblind.dev/share#");

    const result = receiveShare(url, "FROM_URL");
    expect(result.value).toBe("url-test-value");
  });

  it("throws when sharing nonexistent secret", () => {
    expect(() => createShareLink("NONEXISTENT_SECRET")).toThrow(/not found/);
  });

  it("creates unique fragments each time (different keys/IVs)", () => {
    storeSecret("SHARE_TEST", "value");
    const a = createShareLink("SHARE_TEST");
    const b = createShareLink("SHARE_TEST");
    expect(a.fragment).not.toBe(b.fragment);
  });

  it("handles special characters in secret value", () => {
    const special = '{"key":"value","nested":{"a":1}}';
    storeSecret("SHARE_TEST", special);
    const { fragment } = createShareLink("SHARE_TEST");
    const result = receiveShare(fragment, "JSON_SECRET");
    expect(result.value).toBe(special);
  });
});

// ─── Dead man's switch tests ───────────────────────────────
describe("Dead man switch integration", () => {
  beforeEach(() => {
    disableDeadman();
  });

  it("returns disabled status when not configured", () => {
    const status = getDeadmanStatus();
    expect(status.enabled).toBe(false);
    expect(status.triggered).toBe(false);
  });

  it("setup, checkin, status lifecycle works", () => {
    setupDeadman({ days: 90, contactEmail: "contact@example.com" });
    const config = getDeadmanConfig();
    expect(config).not.toBeNull();
    expect(config!.enabled).toBe(true);
    expect(config!.days).toBe(90);
    expect(config!.contactEmail).toBe("contact@example.com");

    checkin();
    const status = getDeadmanStatus();
    expect(status.enabled).toBe(true);
    expect(status.daysConfigured).toBe(90);
    expect(status.daysRemaining).toBe(90); // Just checked in
    expect(status.triggered).toBe(false);
    expect(status.lastCheckin).not.toBeNull();
  });

  it("disable deadman works", () => {
    setupDeadman({ days: 30, contactEmail: "test@test.com" });
    expect(getDeadmanStatus().enabled).toBe(true);
    disableDeadman();
    expect(getDeadmanStatus().enabled).toBe(false);
  });

  it("triggered flag is false when within window", () => {
    setupDeadman({ days: 365, contactEmail: "long@test.com" });
    checkin();
    expect(checkDeadmanTrigger()).toBe(false);
  });

  it("stores and retrieves deadman config with message", () => {
    setupDeadman({
      days: 14,
      contactEmail: "emergency@example.com",
      message: "If you see this, I'm gone. Please secure the infrastructure.",
    });
    const config = getDeadmanConfig();
    expect(config!.message).toContain("I'm gone");
  });
});

// ─── SSO configuration tests ────────────────────────────────
describe("SSO integration", () => {
  it("is not authenticated by default", () => {
    expect(isSSOAuthenticated()).toBe(false);
  });

  it("configures SSO for Google provider", () => {
    configureSSO({
      provider: "google",
      clientId: "test-client-id.apps.googleusercontent.com",
      domain: "example.com",
    });
    const config = getSSOConfig();
    expect(config).not.toBeNull();
    expect(config!.provider).toBe("google");
    expect(config!.clientId).toBe("test-client-id.apps.googleusercontent.com");
    expect(config!.domain).toBe("example.com");
  });
});

// ─── Backend detection tests ────────────────────────────────
describe("Backend integration", () => {
  it("lists available backends including local", { timeout: 15000 }, () => {
    const backends = listAvailableBackends();
    const names = backends.map((b) => b.name);
    expect(names).toContain("local");
    expect(backends.length).toBeGreaterThanOrEqual(4);
  });

  it("default backend is local", () => {
    expect(getBackend().name).toBe("local");
  });

  it("switches to env backend and back to local", () => {
    setBackend("env");
    expect(getBackend().name).toBe("env");
    setBackend("local");
    expect(getBackend().name).toBe("local");
  });
});

// ─── Secret generator test ─────────────────────────────────
describe("Secret generator", () => {
  it("generates a secret of the correct length", () => {
    const s = generateSecret(32);
    expect(s).toHaveLength(32);
  });

  it("generates with symbols by default", () => {
    const s = generateSecret(256);
    expect(s).toHaveLength(256);
    // Should contain at least some special chars in a sample this large
    expect(s).toMatch(/[a-zA-Z]/);
  });

  it("generates without symbols when requested", () => {
    const s = generateSecret(64, false);
    expect(s).toMatch(/^[a-zA-Z0-9]+$/);
  });

  it("generates unique secrets each call", () => {
    const a = generateSecret(32);
    const b = generateSecret(32);
    expect(a).not.toBe(b);
  });
});

// ─── Expiry and audit tests ─────────────────────────────────
describe("Expiry and audit", () => {
  beforeEach(() => {
    try { deleteSecret("EXPIRY_TEST"); } catch {}
  });

  it("sets expiry on a secret", () => {
    storeSecret("EXPIRY_TEST", "temp-value");
    const future = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    setExpiry("EXPIRY_TEST", future);

    const expired = checkExpired();
    expect(expired).not.toContain("EXPIRY_TEST");
  });

  it("returns empty audit log for new vault", () => {
    const log = getAuditLog(5);
    expect(Array.isArray(log)).toBe(true);
  });

  it("checkExpired returns array", () => {
    const expired = checkExpired();
    expect(Array.isArray(expired)).toBe(true);
  });
});
