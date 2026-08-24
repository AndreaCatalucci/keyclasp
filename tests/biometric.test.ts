// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Keyclasp

import { describe, expect, it, vi } from "vitest";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  evaluateBiometricAuthentication,
  requireOperatorAuthentication,
  processPassphraseInput,
  type BiometricRunner,
} from "../src/biometric.js";
import { revealSecretReason } from "../src/runtime.js";
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
    const runner = vi.fn<BiometricRunner>((command, args, input) => {
      expect(command).toMatch(/native\/Keyclasp\.app\/Contents\/MacOS\/keyclasp-biometric$/);
      expect(fs.existsSync(command)).toBe(true);
      expect(args).toEqual([]);
      expect(input).toBe("Reveal API_KEY");
      return { status: 0 };
    });

    expect(evaluateBiometricAuthentication("Reveal API_KEY", {
      platform: "darwin",
      runner,
    })).toEqual({ kind: "ok" });
  });

  it.runIf(process.platform === "darwin")("ships an arm64 ad-hoc-signed Keyclasp app", () => {
    const bundle = path.join(process.cwd(), "native", "Keyclasp.app");
    const executable = path.join(bundle, "Contents", "MacOS", "keyclasp-biometric");
    const signature = spawnSync("/usr/bin/codesign", ["--verify", "--strict", bundle], { encoding: "utf8" });
    const architectures = spawnSync("/usr/bin/lipo", ["-archs", executable], { encoding: "utf8" });
    const sourceBuild = spawnSync(process.execPath, ["scripts/build-macos-biometric-helper.mjs", "--check"], { encoding: "utf8" });
    const displayName = spawnSync("/usr/bin/plutil", ["-extract", "CFBundleDisplayName", "raw", path.join(bundle, "Contents", "Info.plist")], { encoding: "utf8" });
    const uiAgent = spawnSync("/usr/bin/plutil", ["-extract", "LSUIElement", "raw", path.join(bundle, "Contents", "Info.plist")], { encoding: "utf8" });
    const backgroundOnly = spawnSync("/usr/bin/plutil", ["-extract", "LSBackgroundOnly", "raw", path.join(bundle, "Contents", "Info.plist")], { encoding: "utf8" });
    const signatureDetails = spawnSync("/usr/bin/codesign", ["-dvvv", bundle], { encoding: "utf8" });

    expect(signature.status, signature.stderr).toBe(0);
    expect(architectures.status, architectures.stderr).toBe(0);
    expect(sourceBuild.status, sourceBuild.stderr).toBe(0);
    expect(architectures.stdout.trim()).toBe("arm64");
    expect(fs.constants.X_OK & fs.statSync(executable).mode).not.toBe(0);
    expect(displayName.stdout.trim()).toBe("Keyclasp");
    expect(uiAgent.stdout.trim()).toBe("true");
    expect(backgroundOnly.status).not.toBe(0);
    expect(signatureDetails.stderr).toContain("Identifier=dev.keyclasp.biometric");
    expect(signatureDetails.stderr).toContain("Signature=adhoc");
  });

  it("runs the bundled macOS helper with a human-readable reason", () => {
    const runner = vi.fn<BiometricRunner>(() => ({ status: 0 }));

    expect(evaluateBiometricAuthentication("Reveal API_KEY", {
      platform: "darwin",
      helperPath: "/package/native/Keyclasp.app/Contents/MacOS/keyclasp-biometric",
      runner,
    })).toEqual({ kind: "ok" });

    expect(runner).toHaveBeenCalledWith(
      "/package/native/Keyclasp.app/Contents/MacOS/keyclasp-biometric",
      [],
      "Reveal API_KEY",
    );
  });

  it("fails closed outside macOS without starting a helper", () => {
    const runner = vi.fn<BiometricRunner>();

    expect(evaluateBiometricAuthentication("Reveal API_KEY", {
      platform: "linux",
      runner,
    })).toEqual({ kind: "unavailable", message: "Touch ID is unavailable on this platform." });
    expect(runner).not.toHaveBeenCalled();
  });

  it("fails closed when biometric authentication is denied", () => {
    const runner = vi.fn<BiometricRunner>(() => ({ status: 4 }));

    expect(evaluateBiometricAuthentication("Reveal API_KEY", {
      platform: "darwin",
      helperPath: "/package/native/Keyclasp.app/Contents/MacOS/keyclasp-biometric",
      runner,
    })).toEqual({ kind: "denied", message: "Biometric authentication failed." });
  });

  it("distinguishes an explicit operator cancellation from denial", () => {
    const runner = vi.fn<BiometricRunner>(() => ({
      status: 2,
    }));

    expect(evaluateBiometricAuthentication("Reveal API_KEY", {
      platform: "darwin",
      helperPath: "/package/native/Keyclasp.app/Contents/MacOS/keyclasp-biometric",
      runner,
    })).toEqual({ kind: "cancelled", message: "Biometric authentication was cancelled by the operator." });
  });

  it("reports a missing LocalAuthentication runtime without falling back", () => {
    const runner = vi.fn<BiometricRunner>(() => ({
      status: null,
      error: Object.assign(new Error("spawn failed"), { code: "ENOENT" }),
    }));

    expect(evaluateBiometricAuthentication("Reveal API_KEY", {
      platform: "darwin",
      helperPath: "/package/native/Keyclasp.app/Contents/MacOS/keyclasp-biometric",
      runner,
    })).toEqual({ kind: "unavailable", message: "The macOS biometric authentication helper could not start." });
  });

  it("maps native invalid-input status without authentication fallback", () => {
    const runner = vi.fn<BiometricRunner>(() => ({ status: 64 }));
    expect(evaluateBiometricAuthentication("valid reason", { platform: "darwin", runner })).toEqual({
      kind: "invalid",
      message: "The macOS biometric authentication helper rejected its input.",
    });
  });

  it.each([
    [{ status: 5 }, "Biometric authentication timed out."],
    [{ status: null, error: Object.assign(new Error("timed out"), { code: "ETIMEDOUT" }) }, "Biometric authentication timed out."],
  ])("maps a helper deadline without treating it as a launch failure", (result, message) => {
    const runner = vi.fn<BiometricRunner>(() => result);
    expect(evaluateBiometricAuthentication("valid reason", { platform: "darwin", runner })).toEqual({
      kind: "timeout",
      message,
    });
  });

  it.runIf(process.platform === "darwin")("rejects invalid native-helper protocol input without showing Touch ID", () => {
    const executable = path.join(process.cwd(), "native", "Keyclasp.app", "Contents", "MacOS", "keyclasp-biometric");
    const cases = [
      spawnSync(executable, ["unexpected-argument"], { input: "valid reason" }),
      spawnSync(executable, [], { input: "bad\tcontrol" }),
      spawnSync(executable, [], { input: "bad\u0085control" }),
      spawnSync(executable, [], { input: "x".repeat(1025) }),
      spawnSync(executable, [], { input: Buffer.from([0xff]) }),
    ];
    expect(cases.map((result) => result.status)).toEqual([64, 64, 64, 64, 64]);
  });

  it("renders unusual get names without injecting prompt structure", () => {
    expect(revealSecretReason(['project"', "prod\\", "A\nB\u202E"])).toBe(
      'Reveal secret "project\\""/"prod\\\\"/"A\\u{A}B\\u{202E}"',
    );
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
    const runner = vi.fn<BiometricRunner>(() => ({ status: 4 }));

    await expect(requireOperatorAuthentication("Reveal API_KEY", {
      platform: "darwin",
      helperPath: "/package/native/Keyclasp.app/Contents/MacOS/keyclasp-biometric",
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
      status: 3,
    }));

    await expect(requireOperatorAuthentication("Reveal API_KEY", {
      platform: "darwin",
      helperPath: "/package/native/Keyclasp.app/Contents/MacOS/keyclasp-biometric",
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
