import fs from "node:fs";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { collectNativeSourceFiles } from "../scripts/native-source-manifest.mjs";

interface PackedFile {
  path: string;
  mode?: number;
}

describe("npm package contents", () => {
  it("freezes the prerelease platform and Node matrix", () => {
    const packageJson = JSON.parse(
      fs.readFileSync(path.join(process.cwd(), "package.json"), "utf8"),
    );

    expect(packageJson.version).toBe("0.2.0-beta.1");
    expect(packageJson.engines).toEqual({ node: "24.x || 26.x" });
    expect(packageJson.os).toEqual(["darwin", "linux"]);
    expect(packageJson.cpu).toEqual(["arm64", "x64"]);
    expect(packageJson.dependencies).toEqual({ "better-sqlite3": "13.0.3" });
    expect(packageJson.bundleDependencies).toEqual(["better-sqlite3"]);
    expect(packageJson.allowScripts).toEqual({
      "better-sqlite3@13.0.3": true,
      "fsevents@2.3.3": false,
    });
    const bundledManifest = JSON.parse(
      fs.readFileSync(path.join(process.cwd(), "software-beta-dependencies.json"), "utf8"),
    );
    const lockfileBytes = fs.readFileSync(path.join(process.cwd(), "package-lock.json"));
    const lockfile = JSON.parse(lockfileBytes.toString("utf8"));
    expect(bundledManifest.package).toBe("keyclasp@0.2.0-beta.1");
    expect(bundledManifest.lockfileSha256).toBe(
      crypto.createHash("sha256").update(lockfileBytes).digest("hex"),
    );
    expect(bundledManifest.dependencies.map((dependency: { location: string; version: string }) => [dependency.location, dependency.version])).toEqual(
      Object.entries(lockfile.packages)
        .filter(([location, descriptor]) => location !== "" && (descriptor as { dev?: boolean }).dev !== true)
        .map(([location, descriptor]) => [location, (descriptor as { version: string }).version])
        .sort((left, right) => String(left[0]).localeCompare(String(right[0]))),
    );
    expect(bundledManifest.dependencies).toContainEqual(
      expect.objectContaining({ name: "better-sqlite3", version: "13.0.3" }),
    );
    const prebuildManifest = JSON.parse(
      fs.readFileSync(path.join(process.cwd(), "software-beta-native-prebuilds.json"), "utf8"),
    );
    const sourceManifest = JSON.parse(
      fs.readFileSync(path.join(process.cwd(), "software-beta-better-sqlite3-source.json"), "utf8"),
    );
    const nodeAddonApiManifest = JSON.parse(
      fs.readFileSync(path.join(process.cwd(), "software-beta-node-addon-api-source.json"), "utf8"),
    );
    const biometricManifest = JSON.parse(
      fs.readFileSync(path.join(process.cwd(), "keyclasp-macos-helper-candidate.json"), "utf8"),
    );
    expect(biometricManifest).toEqual(expect.objectContaining({
      schemaVersion: 2,
      status: "local-source-candidate",
      qualified: false,
      bundle: "Keyclasp.app",
      bundleIdentifier: "dev.keyclasp.biometric",
      architecture: "arm64",
      signature: expect.objectContaining({
        kind: "ad-hoc",
        hardenedRuntime: true,
        entitlements: [],
      }),
    }));
    for (const descriptor of [...biometricManifest.sourceFiles, ...biometricManifest.bundleFiles]) {
      expect(crypto.createHash("sha256").update(fs.readFileSync(path.join(process.cwd(), descriptor.path))).digest("hex")).toBe(descriptor.sha256);
    }
    expect(nodeAddonApiManifest.package).toBe("node-addon-api@8.9.2");
    expect(nodeAddonApiManifest.files).toEqual(
      collectNativeSourceFiles(path.join(process.cwd(), "node_modules", "node-addon-api")),
    );
    expect(Object.keys(prebuildManifest.prebuilds).sort()).toEqual([
      "darwin-arm64", "linux-arm64", "linux-x64",
    ]);
    for (const [target, reviewed] of Object.entries(prebuildManifest.prebuilds) as Array<[string, { bindingSha256: string }]>) {
      expect(reviewed.bindingSha256).toMatch(/^[a-f0-9]{64}$/);
      expect(sourceManifest.files).toContainEqual({
        path: `prebuilds/${target}.node`,
        sha256: reviewed.bindingSha256,
      });
    }
  });

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

  it("ships the active biometric helper and excludes development and native-spike files", () => {
    const biometricManifest = JSON.parse(
      fs.readFileSync(path.join(process.cwd(), "keyclasp-macos-helper-candidate.json"), "utf8"),
    );
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

    expect(files).toContain("software-beta-dependencies.json");
    expect(files).toContain("software-beta-better-sqlite3-source.json");
    expect(files).toContain("software-beta-node-addon-api-source.json");
    expect(files).toContain("software-beta-native-prebuilds.json");
    expect(files).toContain("keyclasp-macos-helper-candidate.json");
    expect(files).not.toContain("software-beta-macos-biometric.json");
    expect(files).toContain("scripts/install-native-binding.mjs");
    expect(files).toContain("scripts/native-source-manifest.mjs");
    expect(files).toContain("scripts/verify-native-binding.mjs");
    expect(files).toContain("node_modules/better-sqlite3/package.json");
    expect(files.filter((file) => file.endsWith(".node")).sort()).toEqual([
      "node_modules/better-sqlite3/prebuilds/darwin-arm64.node",
      "node_modules/better-sqlite3/prebuilds/darwin-x64.node",
      "node_modules/better-sqlite3/prebuilds/linux-arm64.node",
      "node_modules/better-sqlite3/prebuilds/linux-x64.node",
      "node_modules/better-sqlite3/prebuilds/linuxmusl-arm64.node",
      "node_modules/better-sqlite3/prebuilds/linuxmusl-x64.node",
      "node_modules/better-sqlite3/prebuilds/win32-arm64.node",
      "node_modules/better-sqlite3/prebuilds/win32-x64.node",
    ]);
    expect(files).toContain("native/Keyclasp.app/Contents/Info.plist");
    expect(files).toContain("native/Keyclasp.app/Contents/MacOS/keyclasp-biometric");
    expect(files).toContain("native/Keyclasp.app/Contents/_CodeSignature/CodeResources");
    expect(files.filter((file) => file.startsWith("native/Keyclasp.app/"))).toEqual(
      biometricManifest.bundleFiles.map((descriptor: { path: string }) => descriptor.path),
    );
    const helperEntry = packages[0]?.files.find((file) => file.path === "native/Keyclasp.app/Contents/MacOS/keyclasp-biometric") as PackedFile & { mode?: number };
    expect(helperEntry.mode).toBe(0o755);
    expect(files).not.toContain("native/macos-biometric.js");
    expect(files.some((file) => file.startsWith("native/keyclasp-core/"))).toBe(false);
    expect(files.some((file) => file.startsWith("tests/"))).toBe(false);
    expect(files.some((file) => file.startsWith("docs/"))).toBe(false);
    expect(files.some((file) => file.startsWith(".github/"))).toBe(false);
  }, 20_000);
});
