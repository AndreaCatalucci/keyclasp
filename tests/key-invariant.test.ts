import { describe, it, expect, beforeEach, afterEach } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  clearKey,
  checkVaultDecryptability,
  closeDb,
  initializeVault,
  isInitialized,
  listSecrets,
  resolveSecret,
  setProjectName,
  storeSecret,
} from "../src/vault.js";
import { runDoctor } from "../src/doctor.js";

const previousKeyblindHome = process.env.KEYBLIND_HOME;
let tmpDir: string;
let vaultHome: string;

function resetRuntime(): void {
  closeDb();
  clearKey();
}

function restartRuntime(): void {
  resetRuntime();
}

function keyPath(project?: string): string {
  return project
    ? path.join(vaultHome, "projects", project, ".keyblind.key")
    : path.join(vaultHome, ".keyblind.key");
}

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "keyblind-key-invariant-"));
  vaultHome = path.join(tmpDir, ".keyblind");
  process.env.KEYBLIND_HOME = vaultHome;
  setProjectName(null);
  resetRuntime();
});

afterEach(() => {
  setProjectName(null);
  resetRuntime();
  if (previousKeyblindHome === undefined) {
    delete process.env.KEYBLIND_HOME;
  } else {
    process.env.KEYBLIND_HOME = previousKeyblindHome;
  }
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("vault key invariants", () => {
  it("round-trips many secrets after a fresh runtime reload for every read", () => {
    initializeVault("long-lived-passphrase");

    const fixtures = [
      ["PLAIN", "ordinary-value"],
      ["EMPTY", ""],
      ["MULTILINE", "line1\nline2\nline3"],
      ["UNICODE", "secret with unicode cafe"],
      ["NULL_BYTE", "before\x00after"],
      ["JSON", JSON.stringify({ token: "abc", nested: { count: 3 } })],
      ["LONG", crypto.randomBytes(128 * 1024).toString("base64")],
    ] as const;

    for (const [name, value] of fixtures) {
      storeSecret(name, value);
      restartRuntime();
      expect(resolveSecret(name)).toBe(value);
    }

    restartRuntime();
    for (const [name, value] of fixtures) {
      expect(resolveSecret(name)).toBe(value);
    }
  });

  it("keeps resolving a repeatedly overwritten secret across runtime restarts", () => {
    initializeVault("overwrite-passphrase");

    for (let i = 0; i < 75; i++) {
      const value = `version-${i}-${crypto.randomBytes(512).toString("hex")}`;
      storeSecret("ROTATING_SECRET", value);
      restartRuntime();
      expect(resolveSecret("ROTATING_SECRET")).toBe(value);
    }
  });

  it("does not rewrite the key file when init is called on an initialized vault", () => {
    initializeVault("stable-passphrase");
    storeSecret("SURVIVES_REINIT", "stable-value");
    const before = fs.readFileSync(keyPath());

    restartRuntime();
    expect(isInitialized()).toBe(true);
    expect(() => initializeVault("different-passphrase")).toThrow(/already initialized/);

    const after = fs.readFileSync(keyPath());
    expect(after.equals(before)).toBe(true);

    restartRuntime();
    expect(resolveSecret("SURVIVES_REINIT")).toBe("stable-value");
  });

  it("does not let a cached key from one vault poison a newly initialized vault", () => {
    const firstHome = path.join(tmpDir, "first-home");
    const secondHome = path.join(tmpDir, "second-home");

    process.env.KEYBLIND_HOME = firstHome;
    initializeVault("first-passphrase");
    storeSecret("FIRST_SECRET", "first-value");
    expect(resolveSecret("FIRST_SECRET")).toBe("first-value");
    const firstKey = fs.readFileSync(path.join(firstHome, ".keyblind.key"));

    process.env.KEYBLIND_HOME = secondHome;
    initializeVault("second-passphrase");
    storeSecret("SECOND_SECRET", "second-value");
    expect(resolveSecret("SECOND_SECRET")).toBe("second-value");
    const secondKey = fs.readFileSync(path.join(secondHome, ".keyblind.key"));
    expect(secondKey.equals(firstKey)).toBe(false);

    restartRuntime();
    expect(resolveSecret("SECOND_SECRET")).toBe("second-value");

    process.env.KEYBLIND_HOME = firstHome;
    restartRuntime();
    expect(resolveSecret("FIRST_SECRET")).toBe("first-value");
  });

  it("keeps project vault keys isolated across project switches and restarts", () => {
    setProjectName("alpha");
    initializeVault("alpha-passphrase");
    storeSecret("PROJECT_SECRET", "alpha-value");
    const alphaKey = fs.readFileSync(keyPath("alpha"));

    setProjectName("beta");
    initializeVault("beta-passphrase");
    storeSecret("PROJECT_SECRET", "beta-value");
    const betaKey = fs.readFileSync(keyPath("beta"));
    expect(betaKey.equals(alphaKey)).toBe(false);

    setProjectName("alpha");
    restartRuntime();
    expect(resolveSecret("PROJECT_SECRET")).toBe("alpha-value");

    setProjectName("beta");
    restartRuntime();
    expect(resolveSecret("PROJECT_SECRET")).toBe("beta-value");
  });

  it("detects key/vault drift when names are visible but values are unrecoverable", () => {
    const homeA = path.join(tmpDir, "home-a", ".keyblind");
    const homeB = path.join(tmpDir, "home-b", ".keyblind");

    process.env.KEYBLIND_HOME = homeA;
    initializeVault("");
    storeSecret("REPRO_SECRET", "not-a-real-secret");
    expect(resolveSecret("REPRO_SECRET")).toBe("not-a-real-secret");

    process.env.KEYBLIND_HOME = homeB;
    restartRuntime();
    initializeVault("");

    fs.copyFileSync(path.join(homeB, ".keyblind.key"), path.join(homeA, ".keyblind.key"));

    process.env.KEYBLIND_HOME = homeA;
    restartRuntime();
    expect(listSecrets()).toContain("REPRO_SECRET");
    expect(() => resolveSecret("REPRO_SECRET")).toThrow(/authenticate data|decrypt/i);

    const decryptability = checkVaultDecryptability();
    expect(decryptability.checked).toBe(1);
    expect(decryptability.failures).toEqual([
      expect.objectContaining({ name: "REPRO_SECRET" }),
    ]);

    const checks = runDoctor();
    expect(checks).toEqual(expect.arrayContaining([
      expect.objectContaining({
        name: "Secret decryptability",
        status: "error",
      }),
    ]));
  });
});
