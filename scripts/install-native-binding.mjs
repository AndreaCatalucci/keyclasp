#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { verifyBundledNativeSource, verifyNativeBinding } from "./verify-native-binding.mjs";

const packageRoot = path.resolve(import.meta.dirname, "..");
const dependencyRoot = path.join(packageRoot, "node_modules", "better-sqlite3");
const nodeAddonApiRoot = path.join(packageRoot, "node_modules", "node-addon-api");
const nodeMajor = Number.parseInt(process.versions.node.split(".", 1)[0] ?? "", 10);
if (![24, 26].includes(nodeMajor)) {
  throw new Error(`Keyclasp requires Node.js 24 or 26; found ${process.versions.node}. No vault state was created or changed.`);
}
const sourceBuild = ![undefined, "", "0", "false"].includes(process.env.npm_config_build_from_source?.toLowerCase());
const glibcLinux = process.platform !== "linux" || Boolean(process.report.getReport().header?.glibcVersionRuntime);
const target = `${process.platform}-${process.arch}`;
if (!glibcLinux || !["darwin-arm64", "linux-arm64", "linux-x64"].includes(target)) {
  throw new Error("Keyclasp has no reviewed native binding for this OS, libc, and architecture.");
}
verifyBundledNativeSource(dependencyRoot, path.join(packageRoot, "software-beta-better-sqlite3-source.json"));
verifyBundledNativeSource(nodeAddonApiRoot, path.join(packageRoot, "software-beta-node-addon-api-source.json"));

if (sourceBuild) {
  const npmExecutable = process.env.npm_execpath;
  const nodeGyp = npmExecutable
    ? path.resolve(path.dirname(npmExecutable), "..", "node_modules", "node-gyp", "bin", "node-gyp.js")
    : null;
  if (!nodeGyp || !fs.existsSync(nodeGyp)) {
    throw new Error("npm did not expose its supported node-gyp tool for the requested source build.");
  }
  const buildWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-native-build-"));
  const buildNodeModules = path.join(buildWorkspace, "node_modules");
  const buildDependencyRoot = path.join(buildNodeModules, "better-sqlite3");
  try {
    fs.mkdirSync(buildNodeModules);
    fs.cpSync(dependencyRoot, buildDependencyRoot, { recursive: true });
    const buildNodeAddonApiRoot = path.join(buildNodeModules, "node-addon-api");
    fs.cpSync(nodeAddonApiRoot, buildNodeAddonApiRoot, { recursive: true });
    verifyBundledNativeSource(buildDependencyRoot, path.join(packageRoot, "software-beta-better-sqlite3-source.json"));
    verifyBundledNativeSource(buildNodeAddonApiRoot, path.join(packageRoot, "software-beta-node-addon-api-source.json"));
    const rebuilt = spawnSync(process.execPath, [nodeGyp, "rebuild", "--release", "--force_build=1"], {
      cwd: buildDependencyRoot,
      env: process.env,
      stdio: "inherit",
    });
    if (rebuilt.status !== 0 || rebuilt.error) {
      throw new Error("The bundled better-sqlite3 sources could not produce a native binding. Check the supported compiler toolchain.");
    }
    const compiledBinding = path.join(buildDependencyRoot, "build", "Release", "better_sqlite3.node");
    if (!fs.existsSync(compiledBinding)) {
      throw new Error("The isolated better-sqlite3 source build did not produce its native binding.");
    }
    const installedBinding = path.join(dependencyRoot, "build", "Release", "better_sqlite3.node");
    fs.rmSync(path.join(dependencyRoot, "build"), { recursive: true, force: true });
    fs.mkdirSync(path.dirname(installedBinding), { recursive: true });
    fs.copyFileSync(compiledBinding, installedBinding);
  } finally {
    fs.rmSync(buildWorkspace, { recursive: true, force: true });
  }
  fs.unlinkSync(path.join(dependencyRoot, "prebuilds", `${target}.node`));
}

console.log(verifyNativeBinding({
  dependencyRoot,
  manifestPath: path.join(packageRoot, "software-beta-native-prebuilds.json"),
  target,
  sourceBuild,
}));
