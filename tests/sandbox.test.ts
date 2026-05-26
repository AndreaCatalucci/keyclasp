import { describe, it, expect } from "vitest";
import crypto from "node:crypto";

// We test the deterministic fake generation logic inline since generateFakeValue
// is not exported. This mirrors the logic in sandbox.ts.
function getProjectHash(): string {
  const cwd = process.cwd();
  return crypto.createHash("sha256").update(cwd).digest("hex").slice(0, 16);
}

function generateFakeValue(keyName: string, originalValue: string): string {
  const projectHash = getProjectHash();
  const hmac = crypto
    .createHmac("sha256", projectHash)
    .update(keyName)
    .digest("hex")
    .slice(0, 16);

  if (originalValue.startsWith("sk-") || originalValue.startsWith("pk-")) {
    return `sk_keyblind_sandbox_${hmac}`;
  }
  if (originalValue.startsWith("ghp_") || originalValue.startsWith("gho_")) {
    return `ghp_keyblind_sandbox_${hmac}`;
  }
  if (originalValue.includes("://")) {
    try {
      const url = new URL(originalValue);
      url.username = "keyblind";
      url.password = "sandbox";
      url.hostname = "localhost";
      if (url.port) url.port = "5432";
      url.pathname = "/keyblind_db";
      return url.toString();
    } catch {
      // fall through
    }
  }
  if (originalValue.length > 20) {
    return `KEYBLIND_SANDBOX_${hmac}`;
  }
  return `KEYBLIND_SANDBOX_${hmac}`;
}

describe("generateFakeValue", () => {
  it("replaces OpenAI-style keys with deterministic fake", () => {
    const fake = generateFakeValue("OPENAI_API_KEY", "sk-proj-abc123xyz");
    expect(fake).toMatch(/^sk_keyblind_sandbox_[a-f0-9]{16}$/);
  });

  it("replaces GitHub-style tokens with deterministic fake", () => {
    const fake = generateFakeValue("GITHUB_TOKEN", "ghp_abcdef123456");
    expect(fake).toMatch(/^ghp_keyblind_sandbox_[a-f0-9]{16}$/);
  });

  it("replaces URLs with localhost equivalents", () => {
    const fake = generateFakeValue("DATABASE_URL", "postgres://user:pass@db.example.com:5432/mydb");
    expect(fake).toContain("localhost");
    expect(fake).toContain("keyblind");
    expect(fake).toContain("sandbox");
  });

  it("replaces long values with KEYBLIND_SANDBOX prefix", () => {
    const fake = generateFakeValue("JWT_SECRET", "a-very-long-jwt-secret-that-is-more-than-20-chars");
    expect(fake).toMatch(/^KEYBLIND_SANDBOX_[a-f0-9]{16}$/);
  });

  it("is deterministic — same input produces same output", () => {
    const a = generateFakeValue("MY_KEY", "sk-abc123");
    const b = generateFakeValue("MY_KEY", "sk-abc123");
    expect(a).toBe(b);
  });

  it("different key names produce different fakes", () => {
    const a = generateFakeValue("KEY_A", "sk-abc123");
    const b = generateFakeValue("KEY_B", "sk-abc123");
    expect(a).not.toBe(b);
  });
});
