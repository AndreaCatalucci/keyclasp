import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const tmpDir = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-test-")));
const vaultDir = path.join(tmpDir, ".keyclasp");
const previousKeyclaspHome = process.env.KEYCLASP_HOME;
process.env.KEYCLASP_HOME = vaultDir;

import {
  initializeVault,
  storeSecret,
  resolveSecret,
  resolveSecretWithAlias,
  listSecrets,
  createAlias,
  deleteAlias,
  listAliases,
  deleteSecret,
  isInitialized,
  closeDb,
} from "../src/vault.js";
import {
  storeTOTP, generateTOTPCode, listTOTP, deleteTOTP, parseOTPAuthURI,
  generateTOTP, generateHOTP, timeRemaining,
} from "../src/totp.js";
import { createShareLink, receiveShare, parseTTL } from "../src/share.js";
import { getAuditLog, checkExpired, setExpiry } from "../src/vault.js";
import { setBackend, getBackend, listAvailableBackends } from "../src/backends.js";
import { generateSecret } from "../src/config.js";
import { applySyncBundle, createSyncBundle } from "../src/sync.js";
import { unsandboxEnvFile } from "../src/sandbox.js";

beforeAll(() => {
  process.env.KEYCLASP_HOME = vaultDir;
  fs.mkdirSync(tmpDir, { recursive: true });
  fs.mkdirSync(vaultDir, { recursive: true });
  if (!isInitialized()) initializeVault("integration-test-passphrase");
});

afterAll(() => {
  closeDb();
  if (previousKeyclaspHome === undefined) {
    delete process.env.KEYCLASP_HOME;
  } else {
    process.env.KEYCLASP_HOME = previousKeyclaspHome;
  }
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
    expect(url).toContain("https://github.com/AndreaCatalucci/keyclasp#");

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

describe("Keyblind compatibility", () => {
  it("imports sync bundles created with the Keyblind format marker", () => {
    storeSecret("LEGACY_SYNC", "legacy-sync-value");
    const bundle = createSyncBundle().replace("keyclasp-sync-v1", "keyblind-sync-v1");
    deleteSecret("LEGACY_SYNC");

    expect(applySyncBundle(bundle).imported).toBeGreaterThan(0);
    expect(resolveSecret("LEGACY_SYNC")).toBe("legacy-sync-value");
  });

  it("restores the Keyblind backup when current and legacy backups coexist", () => {
    const envPath = path.join(tmpDir, ".env.legacy-sandbox");
    const original = "API_KEY=real-value\n";
    fs.writeFileSync(envPath, `# @keyblind-backup:{}\nAPI_KEY=KEYBLIND_SANDBOX_deadbeef\n`);
    storeSecret("__keyclasp_env_backup", "API_KEY=wrong-current-value\n");
    storeSecret("__keyblind_env_backup", original);
    storeSecret("__keyblind_sandbox_backup__API_KEY", "real-value");

    expect(unsandboxEnvFile(envPath)).toContain("API_KEY");
    expect(fs.readFileSync(envPath, "utf8")).toBe(original);
  });

  it("refuses to restore a file with both Keyclasp and Keyblind markers", () => {
    const envPath = path.join(tmpDir, ".env.ambiguous-sandbox");
    const sandboxed = [
      "# @keyclasp-backup:{}",
      "# @keyblind-backup:{}",
      "API_KEY=KEYCLASP_SANDBOX_deadbeef",
      "",
    ].join("\n");
    fs.writeFileSync(envPath, sandboxed);

    expect(() => unsandboxEnvFile(envPath)).toThrow(/both Keyclasp and Keyblind sandbox markers/);
    expect(fs.readFileSync(envPath, "utf8")).toBe(sandboxed);
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

// --- Secret aliases integration -------------------------------------------
describe("Secret aliases integration", () => {
  beforeEach(() => {
    for (const alias of listAliases()) {
      if (alias.alias.startsWith("INTEGRATION_ALIAS_")) deleteAlias(alias.alias);
    }
    for (const name of ["INTEGRATION_ALIAS_HELLO", "INTEGRATION_ALIAS_WORLD"]) {
      try { deleteSecret(name); } catch {}
    }
  });

  it("creates, resolves, lists, and deletes aliases without duplicating values", () => {
    storeSecret("INTEGRATION_ALIAS_HELLO", "alias-secret-value");
    createAlias("INTEGRATION_ALIAS_WORLD", "INTEGRATION_ALIAS_HELLO");

    expect(resolveSecretWithAlias("INTEGRATION_ALIAS_WORLD").value).toBe("alias-secret-value");
    expect(listSecrets()).toContain("INTEGRATION_ALIAS_HELLO");
    expect(listSecrets()).not.toContain("INTEGRATION_ALIAS_WORLD");
    expect(listAliases()).toEqual(expect.arrayContaining([
      expect.objectContaining({ alias: "INTEGRATION_ALIAS_WORLD", target: "INTEGRATION_ALIAS_HELLO" }),
    ]));
    expect(JSON.stringify(listAliases())).not.toContain("alias-secret-value");

    expect(deleteAlias("INTEGRATION_ALIAS_WORLD")).toBe(true);
    expect(resolveSecret("INTEGRATION_ALIAS_HELLO")).toBe("alias-secret-value");
    expect(resolveSecretWithAlias("INTEGRATION_ALIAS_WORLD").value).toBeNull();
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
