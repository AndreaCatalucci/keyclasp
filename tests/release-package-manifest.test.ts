import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";
import { buildReleasePackageManifest, validateArchiveEntries } from "../scripts/release-package-manifest.mjs";

const roots: string[] = [];

function pack(root: string, output: string): void {
  const archivedPaths: string[] = [];
  function collect(directory: string): void {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) collect(absolute);
      else archivedPaths.push(path.relative(root, absolute));
    }
  }
  collect(path.join(root, "package"));
  const result = spawnSync("tar", ["-czf", output, "-C", root, ...archivedPaths], { encoding: "utf8" });
  expect(result.status, result.stderr).toBe(0);
}

function writeManifest(artifact: string, output: string): void {
  fs.writeFileSync(output, `${JSON.stringify(buildReleasePackageManifest(artifact), null, 2)}\n`);
}

function runVerifier(artifact: string, manifest: string) {
  return spawnSync(process.execPath, [
    "scripts/release-package-manifest.mjs",
    artifact,
    "--check",
    manifest,
  ], { cwd: process.cwd(), encoding: "utf8" });
}

function setArchivedMode(artifact: string, archivedPath: string, mode: number): void {
  const archive = zlib.gunzipSync(fs.readFileSync(artifact));
  let offset = 0;
  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512);
    const name = header.subarray(0, 100).toString("utf8").replace(/\0.*$/, "");
    const size = Number.parseInt(header.subarray(124, 136).toString("ascii").replace(/\0.*$/, "").trim() || "0", 8);
    if (name === archivedPath) {
      header.write(`${mode.toString(8).padStart(7, "0")}\0`, 100, 8, "ascii");
      header.fill(0x20, 148, 156);
      const checksum = header.reduce((sum, byte) => sum + byte, 0);
      header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
      fs.writeFileSync(artifact, zlib.gzipSync(archive));
      return;
    }
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  throw new Error(`Archive entry not found: ${archivedPath}`);
}

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

describe("release package content manifest", () => {
  it("identifies package paths, modes, sizes, and contents independently of archive bytes", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-manifest-test-"));
    roots.push(root);
    const packageRoot = path.join(root, "package");
    fs.mkdirSync(path.join(packageRoot, "bin"), { recursive: true });
    fs.writeFileSync(path.join(packageRoot, "package.json"), '{"name":"example","version":"1.2.3"}\n');
    fs.writeFileSync(path.join(packageRoot, "bin", "run"), "first\n", { mode: 0o755 });
    const first = path.join(root, "first.tgz");
    pack(root, first);
    const firstManifest = buildReleasePackageManifest(first);

    fs.utimesSync(path.join(packageRoot, "bin", "run"), new Date(1_000), new Date(1_000));
    const second = path.join(root, "second.tgz");
    pack(root, second);
    const secondManifest = buildReleasePackageManifest(second);

    expect(firstManifest).toEqual(secondManifest);
    expect(firstManifest).toEqual({
      schemaVersion: 1,
      package: "example@1.2.3",
      files: [
        {
          path: "bin/run",
          mode: 0o755,
          size: 6,
          sha256: crypto.createHash("sha256").update("first\n").digest("hex"),
        },
        {
          path: "package.json",
          mode: 0o644,
          size: 37,
          sha256: crypto.createHash("sha256").update('{"name":"example","version":"1.2.3"}\n').digest("hex"),
        },
      ],
    });
  });

  it("detects changed package contents", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-manifest-test-"));
    roots.push(root);
    const packageRoot = path.join(root, "package");
    fs.mkdirSync(packageRoot);
    fs.writeFileSync(path.join(packageRoot, "package.json"), '{"name":"example","version":"1.2.3"}\n');
    const payload = path.join(packageRoot, "payload");
    fs.writeFileSync(payload, "before\n");
    const first = path.join(root, "first.tgz");
    pack(root, first);
    const before = buildReleasePackageManifest(first);

    fs.writeFileSync(payload, "change\n");
    const second = path.join(root, "second.tgz");
    pack(root, second);

    expect(buildReleasePackageManifest(second)).not.toEqual(before);
  });

  it("runs the same check CLI used by release CI", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-manifest-test-"));
    roots.push(root);
    const packageRoot = path.join(root, "package");
    fs.mkdirSync(packageRoot);
    const packageJson = path.join(packageRoot, "package.json");
    fs.writeFileSync(packageJson, '{"name":"example","version":"1.2.3"}\n');
    const payload = path.join(packageRoot, "payload");
    fs.writeFileSync(payload, "before\n");
    const first = path.join(root, "first.tgz");
    const second = path.join(root, "second.tgz");
    const manifest = path.join(root, "manifest.json");
    pack(root, first);
    writeManifest(first, manifest);
    expect(runVerifier(first, manifest).status).toBe(0);

    fs.writeFileSync(payload, "change\n");
    pack(root, second);
    const mismatch = runVerifier(second, manifest);
    expect(mismatch.status).not.toBe(0);
    expect(mismatch.stderr).toContain("Packed package contents differ");
  });

  it("binds archive permission bits instead of the extraction umask", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-manifest-test-"));
    roots.push(root);
    const packageRoot = path.join(root, "package");
    fs.mkdirSync(packageRoot);
    fs.writeFileSync(path.join(packageRoot, "package.json"), '{"name":"example","version":"1.2.3"}\n');
    const target = path.join(packageRoot, "mode");
    fs.writeFileSync(target, "same\n", { mode: 0o644 });
    const first = path.join(root, "first.tgz");
    pack(root, first);
    const firstManifest = buildReleasePackageManifest(first);

    fs.chmodSync(target, 0o666);
    const second = path.join(root, "second.tgz");
    pack(root, second);
    const secondManifest = buildReleasePackageManifest(second);

    expect(firstManifest.files.find((file) => file.path === "mode")?.mode).toBe(0o644);
    expect(secondManifest.files.find((file) => file.path === "mode")?.mode).toBe(0o666);
    expect(secondManifest).not.toEqual(firstManifest);
  });

  it("rejects special permission bits from raw tar headers", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-manifest-test-"));
    roots.push(root);
    const packageRoot = path.join(root, "package");
    fs.mkdirSync(packageRoot);
    fs.writeFileSync(path.join(packageRoot, "package.json"), '{"name":"example","version":"1.2.3"}\n');
    const target = path.join(packageRoot, "executable");
    fs.writeFileSync(target, "same\n", { mode: 0o755 });
    fs.chmodSync(target, 0o6755);
    const artifact = path.join(root, "special-mode.tgz");
    pack(root, artifact);
    setArchivedMode(artifact, "package/executable", 0o6755);

    expect(() => buildReleasePackageManifest(artifact)).toThrow("special permission bits");
  });

  it("rejects duplicate, traversing, and ambiguous archive paths", () => {
    expect(() => validateArchiveEntries(["package/file", "package/file"]))
      .toThrow("duplicate or conflicting path");
    expect(() => validateArchiveEntries(["package/../escape"]))
      .toThrow("unsafe path");
    expect(() => validateArchiveEntries(["package/dir/./file"]))
      .toThrow("unsafe path");
    expect(() => validateArchiveEntries(["package/empty/"]))
      .toThrow("unexpected directory entry");
  });

  it("rejects symlink package entries", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-manifest-test-"));
    roots.push(root);
    const packageRoot = path.join(root, "package");
    fs.mkdirSync(packageRoot);
    fs.writeFileSync(path.join(packageRoot, "package.json"), '{"name":"example","version":"1.2.3"}\n');
    fs.symlinkSync("package.json", path.join(packageRoot, "link"));
    const artifact = path.join(root, "symlink.tgz");
    pack(root, artifact);

    expect(() => buildReleasePackageManifest(artifact)).toThrow("regular file");
  });

  it("rejects special package entries", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-manifest-test-"));
    roots.push(root);
    const packageRoot = path.join(root, "package");
    fs.mkdirSync(packageRoot);
    fs.writeFileSync(path.join(packageRoot, "package.json"), '{"name":"example","version":"1.2.3"}\n');
    const fifo = path.join(packageRoot, "fifo");
    const created = spawnSync("mkfifo", [fifo], { encoding: "utf8" });
    expect(created.status, created.stderr).toBe(0);
    const artifact = path.join(root, "special.tgz");
    pack(root, artifact);

    expect(() => buildReleasePackageManifest(artifact)).toThrow("regular file");
  });
});
