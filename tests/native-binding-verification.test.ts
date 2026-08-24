import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { collectNativeSourceFiles } from "../scripts/native-source-manifest.mjs";
import { verifyBundledNativeSource, verifyNativeBinding } from "../scripts/verify-native-binding.mjs";

describe("reviewed native binding verification", () => {
  function fixture() {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-native-review-"));
    const dependencyRoot = path.join(directory, "better-sqlite3");
    const prebuiltPath = path.join(dependencyRoot, "prebuilds", "darwin-arm64.node");
    const sourceManifestPath = path.join(directory, "source.json");
    const prebuildManifestPath = path.join(directory, "prebuilds.json");
    fs.mkdirSync(path.dirname(prebuiltPath), { recursive: true });
    fs.writeFileSync(prebuiltPath, "reviewed native bytes");
    fs.writeFileSync(path.join(dependencyRoot, "package.json"), "reviewed source bytes");
    const bindingSha256 = crypto.createHash("sha256").update(fs.readFileSync(prebuiltPath)).digest("hex");
    fs.writeFileSync(prebuildManifestPath, JSON.stringify({ prebuilds: { "darwin-arm64": { bindingSha256 } } }));
    fs.writeFileSync(sourceManifestPath, JSON.stringify({ files: collectNativeSourceFiles(dependencyRoot) }));
    return { dependencyRoot, prebuiltPath, sourceManifestPath, prebuildManifestPath };
  }

  it("accepts only the reviewed bundled source tree and prebuilt bytes for the exact target", () => {
    const paths = fixture();
    expect(() => verifyBundledNativeSource(paths.dependencyRoot, paths.sourceManifestPath)).not.toThrow();
    expect(verifyNativeBinding({ dependencyRoot: paths.dependencyRoot, manifestPath: paths.prebuildManifestPath, target: "darwin-arm64", sourceBuild: false }))
      .toContain("verified the bundled better-sqlite3 prebuilt SHA-256");
    fs.appendFileSync(paths.prebuiltPath, "changed");
    expect(() => verifyBundledNativeSource(paths.dependencyRoot, paths.sourceManifestPath)).toThrow("differs from its reviewed source manifest");
    expect(() => verifyNativeBinding({ dependencyRoot: paths.dependencyRoot, manifestPath: paths.prebuildManifestPath, target: "darwin-arm64", sourceBuild: false }))
      .toThrow("failed its reviewed SHA-256 check");
  });

  it("rejects mutated and non-regular native dependency inputs", () => {
    const paths = fixture();
    const staged = path.join(path.dirname(paths.dependencyRoot), "staged-node-addon-api");
    fs.cpSync(paths.dependencyRoot, staged, { recursive: true });
    expect(() => verifyBundledNativeSource(staged, paths.sourceManifestPath)).not.toThrow();
    fs.appendFileSync(path.join(staged, "package.json"), "changed");
    expect(() => verifyBundledNativeSource(staged, paths.sourceManifestPath)).toThrow("differs from its reviewed source manifest");

    fs.unlinkSync(path.join(paths.dependencyRoot, "package.json"));
    fs.symlinkSync(paths.prebuiltPath, path.join(paths.dependencyRoot, "package.json"));
    expect(() => verifyBundledNativeSource(paths.dependencyRoot, paths.sourceManifestPath)).toThrow("Unsupported native dependency package entry");
  });

  it("requires a compiled binding and disables the target prebuilt for a source build", () => {
    const paths = fixture();
    const compiled = path.join(paths.dependencyRoot, "build", "Release", "better_sqlite3.node");
    fs.mkdirSync(path.dirname(compiled), { recursive: true });
    fs.writeFileSync(compiled, "compiled source bytes");
    expect(() => verifyNativeBinding({ dependencyRoot: paths.dependencyRoot, manifestPath: paths.prebuildManifestPath, target: "darwin-arm64", sourceBuild: true }))
      .toThrow("still contains the target prebuilt");
    fs.unlinkSync(paths.prebuiltPath);
    expect(verifyNativeBinding({ dependencyRoot: paths.dependencyRoot, manifestPath: paths.prebuildManifestPath, target: "darwin-arm64", sourceBuild: true }))
      .toContain("explicit better-sqlite3 source build");
  });

  it("rejects an unknown prebuilt target", () => {
    const paths = fixture();
    expect(() => verifyNativeBinding({ dependencyRoot: paths.dependencyRoot, manifestPath: paths.prebuildManifestPath, target: "darwin-riscv64", sourceBuild: false }))
      .toThrow("No reviewed better-sqlite3 prebuilt is available");
  });
});
