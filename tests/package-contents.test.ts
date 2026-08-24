import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";

interface PackedFile {
  path: string;
}

describe("npm package contents", () => {
  it("blocks deep imports around the reviewed public entrypoint", () => {
    const packageJson = JSON.parse(
      fs.readFileSync(path.join(process.cwd(), "package.json"), "utf8"),
    );

    expect(packageJson.exports).toEqual({
      ".": {
        types: "./dist/index.d.ts",
        import: "./dist/index.js",
      },
    });
  });

  it("ships the active biometric helper and excludes the native spike", () => {
    const result = spawnSync(
      "npm",
      ["--silent", "pack", "--dry-run", "--json", "--ignore-scripts"],
      {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          ...process.env,
          npm_config_cache: path.join(os.tmpdir(), "keyclasp-package-test-cache"),
        },
      },
    );
    expect(result.status, result.stderr).toBe(0);
    const packages = JSON.parse(result.stdout) as Array<{ files: PackedFile[] }>;
    const files = packages[0]?.files.map((file) => file.path) ?? [];

    expect(files).toContain("native/macos-biometric.js");
    expect(files.some((file) => file.startsWith("native/keyclasp-core/"))).toBe(false);
  }, 20_000);
});
