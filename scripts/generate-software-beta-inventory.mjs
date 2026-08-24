#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { collectNativeSourceFiles } from "./native-source-manifest.mjs";

const repository = path.resolve(import.meta.dirname, "..");
const outputDirectory = path.join(repository, "docs", "releases");
const packageManifest = JSON.parse(fs.readFileSync(path.join(repository, "package.json"), "utf8"));
const lockfile = JSON.parse(fs.readFileSync(path.join(repository, "package-lock.json"), "utf8"));
const version = packageManifest.version;
if (typeof version !== "string" || lockfile.version !== version || lockfile.packages?.[""]?.version !== version) {
  throw new Error("package.json and package-lock.json must declare the same release version.");
}
const betterSqliteVersion = packageManifest.dependencies?.["better-sqlite3"];
if (typeof betterSqliteVersion !== "string" || !/^\d+\.\d+\.\d+$/.test(betterSqliteVersion)) {
  throw new Error("package.json must pin better-sqlite3 to one exact release version.");
}
const lockfileBytes = fs.readFileSync(path.join(repository, "package-lock.json"));
const lockfileSha256 = crypto.createHash("sha256").update(lockfileBytes).digest("hex");

function packageNameFromLocation(location) {
  const marker = "/node_modules/";
  const index = location.lastIndexOf(marker);
  return index === -1 ? location.replace(/^node_modules\//, "") : location.slice(index + marker.length);
}

const productionDependencies = Object.entries(lockfile.packages)
  .filter(([location, descriptor]) => location !== "" && descriptor.dev !== true)
  .map(([location, descriptor]) => ({
    location,
    name: packageNameFromLocation(location),
    version: descriptor.version,
    integrity: descriptor.integrity,
    optional: descriptor.optional === true,
  }))
  .sort((left, right) => left.location.localeCompare(right.location));

const dependencyManifest = `${JSON.stringify({
    schemaVersion: 1,
    package: `${packageManifest.name}@${version}`,
    lockfileSha256,
    dependencies: productionDependencies,
  }, null, 2)}\n`;
const dependencyManifestPath = path.join(repository, "software-beta-dependencies.json");
const betterSqliteRoot = path.join(repository, "node_modules", "better-sqlite3");
const installedBetterSqliteVersion = JSON.parse(
  fs.readFileSync(path.join(betterSqliteRoot, "package.json"), "utf8"),
).version;
if (installedBetterSqliteVersion !== betterSqliteVersion) {
  throw new Error(`Installed better-sqlite3 ${String(installedBetterSqliteVersion)} does not match package.json ${betterSqliteVersion}.`);
}
const betterSqliteIdentity = `better-sqlite3@${betterSqliteVersion}`;
const betterSqliteSourceManifest = `${JSON.stringify({
  schemaVersion: 1,
  package: betterSqliteIdentity,
  files: collectNativeSourceFiles(betterSqliteRoot),
}, null, 2)}\n`;
const betterSqliteSourceManifestPath = path.join(repository, "software-beta-better-sqlite3-source.json");
const nodeAddonApiRoot = path.join(repository, "node_modules", "node-addon-api");
const nodeAddonApiVersion = lockfile.packages?.["node_modules/node-addon-api"]?.version;
const installedNodeAddonApiVersion = JSON.parse(
  fs.readFileSync(path.join(nodeAddonApiRoot, "package.json"), "utf8"),
).version;
if (typeof nodeAddonApiVersion !== "string" || installedNodeAddonApiVersion !== nodeAddonApiVersion) {
  throw new Error(`Installed node-addon-api ${String(installedNodeAddonApiVersion)} does not match package-lock.json ${String(nodeAddonApiVersion)}.`);
}
const nodeAddonApiSourceManifest = `${JSON.stringify({
  schemaVersion: 1,
  package: `node-addon-api@${nodeAddonApiVersion}`,
  files: collectNativeSourceFiles(nodeAddonApiRoot),
}, null, 2)}\n`;
const nodeAddonApiSourceManifestPath = path.join(repository, "software-beta-node-addon-api-source.json");
const nativePrebuilds = Object.fromEntries(
  ["darwin-arm64", "linux-arm64", "linux-x64"].map((target) => {
    const binding = fs.readFileSync(path.join(betterSqliteRoot, "prebuilds", `${target}.node`));
    return [target, { bindingSha256: crypto.createHash("sha256").update(binding).digest("hex") }];
  }),
);
const nativePrebuildManifest = `${JSON.stringify({ schemaVersion: 1, package: betterSqliteIdentity, prebuilds: nativePrebuilds }, null, 2)}\n`;
const nativePrebuildManifestPath = path.join(repository, "software-beta-native-prebuilds.json");
function collectPrefixedFiles(directory, prefix) {
  return collectNativeSourceFiles(directory).map((descriptor) => ({
    ...descriptor,
    path: path.posix.join(prefix, descriptor.path),
  }));
}

const biometricSourceFiles = collectPrefixedFiles(
  path.join(repository, "native", "macos-biometric"),
  "native/macos-biometric",
);
const biometricBundleFiles = collectPrefixedFiles(
  path.join(repository, "native", "Keyclasp.app"),
  "native/Keyclasp.app",
);
const biometricManifest = `${JSON.stringify({
  schemaVersion: 1,
  bundle: "Keyclasp.app",
  bundleIdentifier: "dev.keyclasp.biometric",
  architecture: "arm64",
  signature: "ad-hoc",
  sourceFiles: biometricSourceFiles,
  bundleFiles: biometricBundleFiles,
}, null, 2)}\n`;
const biometricManifestPath = path.join(repository, "software-beta-macos-biometric.json");
if (process.argv.includes("--check")) {
  if (fs.readFileSync(dependencyManifestPath, "utf8") !== dependencyManifest) {
    throw new Error("software-beta-dependencies.json is stale; regenerate and review the release inventory before packing.");
  }
  if (fs.readFileSync(betterSqliteSourceManifestPath, "utf8") !== betterSqliteSourceManifest) {
    throw new Error("software-beta-better-sqlite3-source.json is stale; regenerate it from the reviewed dependency source before packing.");
  }
  if (fs.readFileSync(nodeAddonApiSourceManifestPath, "utf8") !== nodeAddonApiSourceManifest) {
    throw new Error("software-beta-node-addon-api-source.json is stale; regenerate it from the reviewed dependency source before packing.");
  }
  if (fs.readFileSync(nativePrebuildManifestPath, "utf8") !== nativePrebuildManifest) {
    throw new Error("software-beta-native-prebuilds.json is stale; regenerate it from the reviewed bundled prebuilds before packing.");
  }
  if (fs.readFileSync(biometricManifestPath, "utf8") !== biometricManifest) {
    throw new Error("software-beta-macos-biometric.json is stale; rebuild and review the Touch ID helper before packing.");
  }
  console.log("The bundled production and native-source manifests match the reviewed dependency trees.");
  process.exit(0);
}
fs.writeFileSync(dependencyManifestPath, dependencyManifest, { mode: 0o644 });
fs.writeFileSync(betterSqliteSourceManifestPath, betterSqliteSourceManifest, { mode: 0o644 });
fs.writeFileSync(nodeAddonApiSourceManifestPath, nodeAddonApiSourceManifest, { mode: 0o644 });
fs.writeFileSync(nativePrebuildManifestPath, nativePrebuildManifest, { mode: 0o644 });
fs.writeFileSync(biometricManifestPath, biometricManifest, { mode: 0o644 });

const licenses = Object.entries(lockfile.packages)
  .filter(([location]) => location !== "")
  .map(([location, descriptor]) => ({
    name: location.replace(/^node_modules\//, ""),
    version: descriptor.version,
    license: descriptor.license ?? "UNKNOWN",
    development: descriptor.dev === true,
    optional: descriptor.optional === true,
    resolved: descriptor.resolved,
    integrity: descriptor.integrity,
  }))
  .sort((left, right) => left.name.localeCompare(right.name) || String(left.version).localeCompare(String(right.version)));

fs.mkdirSync(outputDirectory, { recursive: true });
fs.writeFileSync(
  path.join(outputDirectory, `${version}-licenses.json`),
  `${JSON.stringify({ package: `${packageManifest.name}@${version}`, lockfileVersion: lockfile.lockfileVersion, dependencies: licenses }, null, 2)}\n`,
  { mode: 0o644 },
);

const sbom = spawnSync("npm", ["sbom", "--package-lock-only", "--sbom-format", "spdx", "--sbom-type", "application"], {
  cwd: repository,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
});
if (sbom.status !== 0) {
  throw new Error(`npm sbom failed: ${sbom.stderr}`);
}
JSON.parse(sbom.stdout);
fs.writeFileSync(path.join(outputDirectory, `${version}-sbom.spdx.json`), sbom.stdout, { mode: 0o644 });

console.log(`Wrote the bundled dependency, native-source, and Touch ID helper manifests, ${licenses.length} dependency license records, and one SPDX SBOM.`);
