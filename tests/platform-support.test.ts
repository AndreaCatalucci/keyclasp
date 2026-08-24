import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  assertSoftwarePlatformSupported,
  MUSL_UNSUPPORTED_MESSAGE,
  SUPPORTED_SOFTWARE_TARGETS,
  SUPPORTED_SOFTWARE_PLATFORMS,
  WINDOWS_UNSUPPORTED_MESSAGE,
} from "../src/platform.js";

describe("software platform support", () => {
  it("freezes macOS and Linux as the software-beta platforms", () => {
    expect(SUPPORTED_SOFTWARE_PLATFORMS).toEqual(["darwin", "linux"]);
    expect(SUPPORTED_SOFTWARE_TARGETS).toEqual(["darwin-arm64", "linux-arm64", "linux-x64"]);
    expect(() => assertSoftwarePlatformSupported("darwin", "glibc", "arm64")).not.toThrow();
    expect(() => assertSoftwarePlatformSupported("linux", "glibc", "arm64")).not.toThrow();
    expect(() => assertSoftwarePlatformSupported("linux", "glibc", "x64")).not.toThrow();
    expect(() => assertSoftwarePlatformSupported("linux", "other")).toThrow(MUSL_UNSUPPORTED_MESSAGE);
  });

  it("fails closed on macOS x64 and every undeclared CPU architecture", () => {
    expect(() => assertSoftwarePlatformSupported("darwin", "glibc", "x64")).toThrow(
      "unsupported on darwin-x64",
    );
    expect(() => assertSoftwarePlatformSupported("linux", "glibc", "riscv64")).toThrow(
      "Supported targets: macOS arm64 and glibc Linux arm64 or x64. No vault state was created or changed.",
    );
  });

  it("fails closed on Windows with an explicit no-mutation result", () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-windows-closed-"));
    try {
      expect(() => assertSoftwarePlatformSupported("win32")).toThrow(WINDOWS_UNSUPPORTED_MESSAGE);
      expect(fs.readdirSync(home)).toEqual([]);
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  it("fails closed on every undeclared platform", () => {
    expect(() => assertSoftwarePlatformSupported("aix")).toThrow(
      "Supported platforms: macOS and Linux. No vault state was created or changed.",
    );
  });
});
