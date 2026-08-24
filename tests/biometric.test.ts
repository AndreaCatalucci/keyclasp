// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Keyclasp

import { describe, expect, it, vi } from "vitest";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  requireBiometricAuthentication,
  requireOperatorAuthentication,
  processPassphraseInput,
  resolveSecretForOperator,
  type BiometricRunner,
} from "../src/biometric.js";
import { closeDb, clearKey, getKey, initializeVault } from "../src/vault.js";

describe("biometric authentication", () => {
  it("accepts a pasted passphrase and submission from one terminal chunk", () => {
    expect(processPassphraseInput("", "pässphrase\nignored")).toEqual({
      value: "pässphrase",
      actions: Array.from({ length: 10 }, () => "mask"),
      submitted: true,
      cancelled: false,
    });
  });

  it("treats terminal end-of-transmission as cancellation", () => {
    expect(processPassphraseInput("partial", "\u0004")).toEqual({
      value: "partial",
      actions: [],
      submitted: false,
      cancelled: true,
    });
  });

  it("resolves the real bundled helper next to the compiled module", () => {
    const runner = vi.fn<BiometricRunner>((_command, args) => {
      expect(args.slice(0, 2)).toEqual(["-l", "JavaScript"]);
      expect(args[2]).toMatch(/native\/macos-biometric\.js$/);
      expect(fs.existsSync(args[2])).toBe(true);
      return { status: 0 };
    });

    requireBiometricAuthentication("Reveal API_KEY", {
      platform: "darwin",
      runner,
    });
  });

  it.runIf(process.platform === "darwin")("compiles the real JXA helper", () => {
    const helperPath = path.join(process.cwd(), "native", "macos-biometric.js");
    const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-biometric-compile-"));
    const outputPath = path.join(outputDir, "macos-biometric.scpt");

    try {
      const result = spawnSync(
        "/usr/bin/osacompile",
        ["-l", "JavaScript", "-o", outputPath, helperPath],
        { encoding: "utf8" },
      );

      expect(result.status, result.stderr).toBe(0);
      expect(fs.existsSync(outputPath)).toBe(true);
    } finally {
      fs.rmSync(outputDir, { recursive: true, force: true });
    }
  });

  it("runs the bundled macOS helper with a human-readable reason", () => {
    const runner = vi.fn<BiometricRunner>(() => ({ status: 0 }));

    requireBiometricAuthentication("Reveal API_KEY", {
      platform: "darwin",
      helperPath: "/package/native/macos-biometric.js",
      runner,
    });

    expect(runner).toHaveBeenCalledWith(
      "/usr/bin/osascript",
      ["-l", "JavaScript", "/package/native/macos-biometric.js", "Reveal API_KEY"],
    );
  });

  it("fails closed outside macOS without starting a helper", () => {
    const runner = vi.fn<BiometricRunner>();

    expect(() => requireBiometricAuthentication("Reveal API_KEY", {
      platform: "linux",
      runner,
    })).toThrow("requires macOS Touch ID");
    expect(runner).not.toHaveBeenCalled();
  });

  it("fails closed when biometric authentication is denied", () => {
    const runner = vi.fn<BiometricRunner>(() => ({ status: 1 }));

    expect(() => requireBiometricAuthentication("Reveal API_KEY", {
      platform: "darwin",
      helperPath: "/package/native/macos-biometric.js",
      runner,
    })).toThrow("Biometric authentication failed.");
  });

  it("distinguishes an explicit operator cancellation from denial", () => {
    const runner = vi.fn<BiometricRunner>(() => ({
      status: 1,
      stderr: "execution error: Error: KEYCLASP_BIOMETRIC_USER_CANCELLED (-2700)",
    }));

    expect(() => requireBiometricAuthentication("Reveal API_KEY", {
      platform: "darwin",
      helperPath: "/package/native/macos-biometric.js",
      runner,
    })).toThrow("Biometric authentication was cancelled by the operator.");
  });

  it("reports a missing LocalAuthentication runtime without falling back", () => {
    const runner = vi.fn<BiometricRunner>(() => ({
      status: null,
      error: Object.assign(new Error("spawn failed"), { code: "ENOENT" }),
    }));

    expect(() => requireBiometricAuthentication("Reveal API_KEY", {
      platform: "darwin",
      helperPath: "/package/native/macos-biometric.js",
      runner,
    })).toThrow("could not start");
  });

  it("authenticates before resolving a secret for get", async () => {
    const events: string[] = [];
    const authenticate = vi.fn(() => { events.push("biometric"); });
    const resolveSecret = vi.fn(() => {
      events.push("resolve");
      return "secret-value";
    });

    expect(await resolveSecretForOperator("API_KEY", resolveSecret, authenticate)).toBe("secret-value");
    expect(authenticate).toHaveBeenCalledWith('Reveal secret "API_KEY"');
    expect(events).toEqual(["biometric", "resolve"]);
  });

  it("never resolves a get when biometric authentication fails", async () => {
    const resolveSecret = vi.fn(() => "secret-value");
    const authenticate = vi.fn(() => {
      throw new Error("Biometric authentication failed or was cancelled.");
    });

    await expect(resolveSecretForOperator("API_KEY", resolveSecret, authenticate)).rejects.toThrow(
      "failed or was cancelled",
    );
    expect(resolveSecret).not.toHaveBeenCalled();
  });

  it("uses one Linux passphrase entry for authorization", async () => {
    const promptPassphrase = vi.fn(async () => "correct-passphrase");
    const verifyPassphrase = vi.fn(() => true);
    const vaultHasPassphrase = vi.fn(() => true);

    const authorization = await requireOperatorAuthentication("Reveal API_KEY", {
      platform: "linux",
      promptPassphrase,
      verifyPassphrase,
      vaultHasPassphrase,
    });

    expect(promptPassphrase).toHaveBeenCalledOnce();
    expect(verifyPassphrase).toHaveBeenCalledWith("correct-passphrase");
    expect(authorization).toEqual({ method: "passphrase", passphrase: "correct-passphrase" });
  });

  it("rejects an incorrect vault passphrase fallback", async () => {
    await expect(requireOperatorAuthentication("Reveal API_KEY", {
      platform: "linux",
      promptPassphrase: async () => "wrong",
      verifyPassphrase: () => false,
      vaultHasPassphrase: () => true,
    })).rejects.toThrow("Vault passphrase is incorrect.");
  });

  it("does not accept an empty machine-only key as operator fallback", async () => {
    const promptPassphrase = vi.fn(async () => "");

    await expect(requireOperatorAuthentication("Reveal API_KEY", {
      platform: "linux",
      promptPassphrase,
      verifyPassphrase: () => true,
      vaultHasPassphrase: () => false,
    })).rejects.toThrow("machine-only vaults fail closed");
    expect(promptPassphrase).not.toHaveBeenCalled();
  });

  it("does not fall back to the passphrase when Touch ID is denied", async () => {
    const promptPassphrase = vi.fn(async () => "correct-passphrase");
    const runner = vi.fn<BiometricRunner>(() => ({ status: 1 }));

    await expect(requireOperatorAuthentication("Reveal API_KEY", {
      platform: "darwin",
      helperPath: "/package/native/macos-biometric.js",
      runner,
      promptPassphrase,
      verifyPassphrase: () => true,
      vaultHasPassphrase: () => true,
    })).rejects.toThrow("Biometric authentication failed.");
    expect(promptPassphrase).not.toHaveBeenCalled();
  });

  it("does not fall back to a passphrase when Touch ID is not enrolled", async () => {
    const promptPassphrase = vi.fn(async () => "correct-passphrase");
    const runner = vi.fn<BiometricRunner>(() => ({
      status: 1,
      stderr: "execution error: Touch ID is unavailable or not enrolled. (-2700)",
    }));

    await expect(requireOperatorAuthentication("Reveal API_KEY", {
      platform: "darwin",
      helperPath: "/package/native/macos-biometric.js",
      runner,
      promptPassphrase,
      verifyPassphrase: () => true,
      vaultHasPassphrase: () => true,
    })).rejects.toThrow("Touch ID is unavailable or not enrolled.");

    expect(promptPassphrase).not.toHaveBeenCalled();
  });

  it("checks the entered passphrase against the real vault key", async () => {
    const previous = process.env.KEYCLASP_HOME;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-operator-"));
    process.env.KEYCLASP_HOME = path.join(dir, ".keyclasp");
    closeDb();
    clearKey();
    initializeVault("operator-passphrase");

    try {
      await requireOperatorAuthentication("Reveal API_KEY", {
        platform: "linux",
        promptPassphrase: async () => "operator-passphrase",
      });
      expect(getKey()).toHaveLength(32);

      await expect(requireOperatorAuthentication("Reveal API_KEY", {
        platform: "linux",
        promptPassphrase: async () => "wrong-passphrase",
      })).rejects.toThrow("Vault passphrase is incorrect.");
    } finally {
      closeDb();
      clearKey();
      if (previous === undefined) delete process.env.KEYCLASP_HOME;
      else process.env.KEYCLASP_HOME = previous;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
