// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Keyblind

import { describe, expect, it, vi } from "vitest";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  requireBiometricAuthentication,
  resolveSecretForOperator,
  type BiometricRunner,
} from "../src/biometric.js";

describe("biometric authentication", () => {
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

  it("fails closed when biometric authentication is unavailable or denied", () => {
    const runner = vi.fn<BiometricRunner>(() => ({ status: 1 }));

    expect(() => requireBiometricAuthentication("Reveal API_KEY", {
      platform: "darwin",
      helperPath: "/package/native/macos-biometric.js",
      runner,
    })).toThrow("failed or was cancelled");
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

  it("authenticates before resolving a secret for get", () => {
    const events: string[] = [];
    const authenticate = vi.fn(() => { events.push("biometric"); });
    const resolveSecret = vi.fn(() => {
      events.push("resolve");
      return "secret-value";
    });

    expect(resolveSecretForOperator("API_KEY", resolveSecret, authenticate)).toBe("secret-value");
    expect(authenticate).toHaveBeenCalledWith('Reveal secret "API_KEY"');
    expect(events).toEqual(["biometric", "resolve"]);
  });

  it("never resolves a get when biometric authentication fails", () => {
    const resolveSecret = vi.fn(() => "secret-value");
    const authenticate = vi.fn(() => {
      throw new Error("Biometric authentication failed or was cancelled.");
    });

    expect(() => resolveSecretForOperator("API_KEY", resolveSecret, authenticate)).toThrow(
      "failed or was cancelled",
    );
    expect(resolveSecret).not.toHaveBeenCalled();
  });
});
