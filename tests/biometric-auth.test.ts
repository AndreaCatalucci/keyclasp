import { afterEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const tempHomes: string[] = [];
let previousKeyblindHome: string | undefined;

async function loadVaultWithAuth(authenticated: boolean = true) {
  vi.resetModules();

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "keyblind-biometric-test-"));
  const vaultDir = path.join(tmpDir, ".keyblind");
  tempHomes.push(tmpDir);
  previousKeyblindHome = process.env.KEYBLIND_HOME;
  process.env.KEYBLIND_HOME = vaultDir;

  const authMock = {
    authenticateWithBiometric: vi.fn(() => authenticated),
    sessionActive: vi.fn(() => true),
  };

  vi.doMock("../src/auth.js", () => authMock);

  const vault = await import("../src/vault.js");
  return { vault, authMock };
}

afterEach(async () => {
  const { closeDb } = await import("../src/vault.js");
  closeDb();
  vi.doUnmock("../src/auth.js");
  vi.resetModules();
  if (previousKeyblindHome === undefined) {
    delete process.env.KEYBLIND_HOME;
  } else {
    process.env.KEYBLIND_HOME = previousKeyblindHome;
  }
  previousKeyblindHome = undefined;
  for (const dir of tempHomes.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe("biometric secret access policy", () => {
  it("requires biometric authentication for each secret resolution when per-use auth is enabled", async () => {
    const { vault, authMock } = await loadVaultWithAuth();

    vault.initializeVault("test-passphrase");
    vault.storeSecret("BIOMETRIC_EACH_TIME", "secret-value");
    vault.setRequireBiometricPerSecretAccess(true);

    expect(vault.resolveSecret("BIOMETRIC_EACH_TIME")).toBe("secret-value");
    expect(vault.resolveSecret("BIOMETRIC_EACH_TIME")).toBe("secret-value");

    expect(authMock.authenticateWithBiometric).toHaveBeenCalledTimes(2);
  });

  it("denies secret resolution when per-use biometric authentication fails", async () => {
    const { vault, authMock } = await loadVaultWithAuth(false);

    vault.initializeVault("test-passphrase");
    vault.storeSecret("BIOMETRIC_DENIED", "secret-value");
    vault.setRequireBiometricPerSecretAccess(true);

    expect(() => vault.resolveSecret("BIOMETRIC_DENIED")).toThrow("Biometric authentication required to access secret.");
    expect(authMock.authenticateWithBiometric).toHaveBeenCalledTimes(1);
  });

  it("requires biometric authentication before reading decrypted secret history", async () => {
    const { vault, authMock } = await loadVaultWithAuth();
    const sync = await import("../src/sync.js");

    vault.initializeVault("test-passphrase");
    sync.saveHistory("BIOMETRIC_HISTORY", "previous-value");
    vault.setRequireBiometricPerSecretAccess(true);

    expect(sync.getSecretHistory("BIOMETRIC_HISTORY")[0].value).toBe("previous-value");
    expect(authMock.authenticateWithBiometric).toHaveBeenCalledTimes(1);
  });
});
