#!/usr/bin/env node

import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import zlib from "node:zlib";

function fail(message) {
  throw new Error(message);
}

function runTar(args) {
  const result = spawnSync("tar", args, { encoding: "utf8" });
  if (result.error) fail(`tar could not start: ${result.error.message}`);
  if (result.status !== 0) fail(`tar failed (${String(result.status)}): ${result.stderr}`);
  return result.stdout;
}

function readTarOctal(field, label) {
  if ((field[0] & 0x80) !== 0) fail(`Archive uses an unsupported binary ${label} field.`);
  const value = field.toString("ascii").replace(/\0.*$/, "").trim();
  if (!/^[0-7]+$/.test(value)) fail(`Archive has an invalid ${label} field.`);
  return Number.parseInt(value, 8);
}

function validateTarHeaders(artifact) {
  const archive = zlib.gunzipSync(fs.readFileSync(artifact));
  let offset = 0;
  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) return;
    const mode = readTarOctal(header.subarray(100, 108), "mode");
    if ((mode & 0o7000) !== 0) fail("Archive entries must not have special permission bits.");
    const size = readTarOctal(header.subarray(124, 136), "size");
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  fail("Archive is missing its terminating tar block.");
}

export function validateArchiveEntries(entries) {
  if (entries.length === 0) fail("The package archive is empty.");
  const seen = new Map();
  for (const entry of entries) {
    if (entry === "package/" || entry === "package") continue;
    if (!entry.startsWith("package/")) fail(`Archive entry is outside package/: ${entry}`);
    const directory = entry.endsWith("/");
    const relative = entry.slice("package/".length).replace(/\/$/, "");
    if (!relative || relative.includes("\\") || relative.split("/").some((part) => part === "." || part === "..") ||
        path.posix.isAbsolute(relative) || path.posix.normalize(relative) !== relative) {
      fail(`Archive entry has an unsafe path: ${entry}`);
    }
    if (directory) fail(`Archive contains an unexpected directory entry: ${relative}`);
    const previous = seen.get(relative);
    if (previous !== undefined) {
      fail(`Archive contains a duplicate or conflicting path: ${relative}`);
    }
    seen.set(relative, "file");
  }
}

function validateArchivePaths(artifact) {
  validateTarHeaders(artifact);
  validateArchiveEntries(runTar(["-tzf", artifact]).split("\n").filter(Boolean));
}

function collectFiles(root, directory = root, output = []) {
  const entries = fs.readdirSync(directory, { withFileTypes: true })
    .sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
  for (const entry of entries) {
    const absolute = path.join(directory, entry.name);
    const relative = path.relative(root, absolute).split(path.sep).join("/");
    const stat = fs.lstatSync(absolute);
    if (stat.isDirectory()) {
      collectFiles(root, absolute, output);
      continue;
    }
    if (!stat.isFile()) fail(`Package content must be a regular file: ${relative}`);
    output.push({
      path: relative,
      mode: stat.mode & 0o7777,
      size: stat.size,
      sha256: crypto.createHash("sha256").update(fs.readFileSync(absolute)).digest("hex"),
    });
  }
  return output;
}

export function buildReleasePackageManifest(artifactPath) {
  const artifact = path.resolve(artifactPath);
  if (!fs.statSync(artifact).isFile()) fail(`Package archive is not a regular file: ${artifact}`);
  validateArchivePaths(artifact);
  const extractionRoot = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-package-manifest-"));
  fs.chmodSync(extractionRoot, 0o700);
  try {
    runTar(["-xzpf", artifact, "-C", extractionRoot]);
    const packageRoot = path.join(extractionRoot, "package");
    const packageJson = JSON.parse(fs.readFileSync(path.join(packageRoot, "package.json"), "utf8"));
    if (typeof packageJson.name !== "string" || typeof packageJson.version !== "string") {
      fail("The packed package.json has no string name and version.");
    }
    return {
      schemaVersion: 1,
      package: `${packageJson.name}@${packageJson.version}`,
      files: collectFiles(packageRoot),
    };
  } finally {
    fs.rmSync(extractionRoot, { recursive: true, force: true });
  }
}

function serializedManifest(artifactPath) {
  return `${JSON.stringify(buildReleasePackageManifest(artifactPath), null, 2)}\n`;
}

function main() {
  const [artifactPath, operation, manifestPath] = process.argv.slice(2);
  if (!artifactPath || !["--check", "--write"].includes(operation) || !manifestPath) {
    fail("Usage: node scripts/release-package-manifest.mjs <tarball> (--check|--write) <manifest.json>");
  }
  const generated = serializedManifest(artifactPath);
  const target = path.resolve(manifestPath);
  if (operation === "--write") {
    fs.writeFileSync(target, generated, { mode: 0o644 });
    return;
  }
  if (fs.readFileSync(target, "utf8") !== generated) {
    fail(`Packed package contents differ from the reviewed manifest: ${target}`);
  }
  process.stdout.write(`Verified package content manifest: ${target}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
