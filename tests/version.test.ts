import { describe, expect, it } from "vitest";
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import {
  formatDisplayVersion,
  getDeclaredPackageVersion,
  getDisplayVersion,
  getGitState,
} from "../src/version.js";

function withTempPackage(version: unknown, callback: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-version-test-"));
  try {
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ version }), "utf8");
    callback(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe("version metadata", () => {
  it("formats local git metadata as semver-compatible dev identity", () => {
    expect(formatDisplayVersion("0.6.0", { available: true, shortSha: "abc1234", dirty: false })).toBe("0.6.0-dev+git.abc1234");
  });

  it("includes dirty state in local git metadata", () => {
    expect(formatDisplayVersion("0.6.0", { available: true, shortSha: "abc1234", dirty: true })).toBe("0.6.0-dev+git.abc1234.dirty");
  });

  it("falls back to plain package semver when git metadata is unavailable", () => {
    expect(formatDisplayVersion("0.6.0", { available: false, dirty: false })).toBe("0.6.0");
  });

  it("returns plain package semver when explicitly requested", () => {
    expect(formatDisplayVersion("0.6.0", { available: true, shortSha: "abc1234", dirty: true }, { plain: true })).toBe("0.6.0");
  });

  it("reads package version by walking up from a compiled dist-like directory", () => {
    withTempPackage("1.2.3", (dir) => {
      const distDir = path.join(dir, "dist");
      fs.mkdirSync(distDir);

      expect(getDeclaredPackageVersion({ startDir: distDir })).toBe("1.2.3");
    });
  });

  it("throws a clear error for malformed package metadata", () => {
    withTempPackage(undefined, (dir) => {
      expect(() => getDeclaredPackageVersion({ startDir: dir })).toThrow("missing a string version");
    });
  });

  it("returns unavailable git state when git commands fail", () => {
    const state = getGitState({
      cwd: "/not-a-real-directory",
      runGit: () => {
        throw new Error("git failed");
      },
    });

    expect(state).toEqual({ available: false, dirty: false });
  });

  it("derives display version from package version and git state", () => {
    withTempPackage("2.0.0", (dir) => {
      const version = getDisplayVersion({
        startDir: dir,
        cwd: dir,
        runGit: (args) => {
          if (args.join(" ") === "rev-parse --is-inside-work-tree") return "true";
          if (args.join(" ") === "rev-parse --short HEAD") return "def5678";
          if (args.join(" ") === "status --porcelain") return " M src/version.ts";
          throw new Error(`unexpected git args: ${args.join(" ")}`);
        },
      });

      expect(version).toBe("2.0.0-dev+git.def5678.dirty");
    });
  });

  it("ignores a dirty parent repository for an installed package", () => {
    const outer = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-version-parent-"));
    try {
      execFileSync("git", ["init", "--quiet"], { cwd: outer });
      fs.writeFileSync(path.join(outer, "dirty.txt"), "untracked\n");
      const installed = path.join(outer, "node_modules", "keyclasp");
      fs.mkdirSync(installed, { recursive: true });
      fs.writeFileSync(path.join(installed, "package.json"), JSON.stringify({ version: "0.2.0-beta.1" }));

      expect(getDisplayVersion({ startDir: installed })).toBe("0.2.0-beta.1");
    } finally {
      fs.rmSync(outer, { recursive: true, force: true });
    }
  });

  it("keeps package-lock root version aligned with package version", () => {
    const packageJson = JSON.parse(fs.readFileSync(path.join(process.cwd(), "package.json"), "utf8")) as { version: string };
    const packageLock = JSON.parse(fs.readFileSync(path.join(process.cwd(), "package-lock.json"), "utf8")) as {
      version: string;
      packages: Record<string, { version?: string }>;
    };

    expect(packageLock.version).toBe(packageJson.version);
    expect(packageLock.packages[""].version).toBe(packageJson.version);
  });
});
