#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const repository = path.resolve(import.meta.dirname, "..");
const sourceDirectory = path.join(repository, "native", "macos-biometric");
const outputPath = path.join(repository, "native", "Keyclasp.app");

if (process.platform !== "darwin" || process.arch !== "arm64") {
  throw new Error("The Keyclasp Touch ID helper must be built on macOS arm64.");
}

function run(command, args) {
  const result = spawnSync(command, args, { encoding: "utf8" });
  if (result.status !== 0 || result.error) {
    throw new Error(`${command} failed: ${result.error?.message ?? result.stderr}`);
  }
  return result.stdout.trim();
}

const temporaryRoot = fs.mkdtempSync(path.join(repository, "native", ".keyclasp-biometric-build-"));
const bundle = path.join(temporaryRoot, "Keyclasp.app");
const contents = path.join(bundle, "Contents");
const executableDirectory = path.join(contents, "MacOS");
const executable = path.join(executableDirectory, "keyclasp-biometric");

function describeTree(root) {
  const files = [];
  const visit = (directory, relative = "") => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const entryRelative = path.posix.join(relative, entry.name);
      const entryPath = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(entryPath, entryRelative);
      else if (entry.isFile()) files.push({
        path: entryRelative,
        mode: fs.statSync(entryPath).mode & 0o777,
        bytes: fs.readFileSync(entryPath).toString("base64"),
      });
      else throw new Error(`Unsupported helper bundle entry: ${entryRelative}`);
    }
  };
  visit(root);
  return files.sort((left, right) => left.path.localeCompare(right.path));
}

try {
  fs.mkdirSync(executableDirectory, { recursive: true, mode: 0o755 });
  fs.copyFileSync(path.join(sourceDirectory, "Info.plist"), path.join(contents, "Info.plist"));
  fs.chmodSync(path.join(contents, "Info.plist"), 0o644);

  run("/usr/bin/clang", [
    "-arch", "arm64",
    "-mmacosx-version-min=13.0",
    "-fobjc-arc",
    "-framework", "Foundation",
    "-framework", "AppKit",
    "-framework", "LocalAuthentication",
    path.join(sourceDirectory, "main.m"),
    "-o", executable,
  ]);
  fs.chmodSync(executable, 0o755);
  run("/usr/bin/codesign", [
    "--force", "--sign", "-", "--timestamp=none",
    "--identifier", "dev.keyclasp.biometric",
    bundle,
  ]);
  run("/usr/bin/codesign", ["--verify", "--strict", bundle]);
  if (run("/usr/bin/lipo", ["-archs", executable]) !== "arm64") {
    throw new Error("The Keyclasp Touch ID helper must contain only arm64 code.");
  }

  if (process.argv.includes("--check")) {
    if (JSON.stringify(describeTree(bundle)) !== JSON.stringify(describeTree(outputPath))) {
      throw new Error("The reviewed Keyclasp.app differs from a clean build of its checked-in source.");
    }
    console.log(`Verified a clean source build matches ${outputPath}`);
  } else {
    if (!fs.existsSync(outputPath)) {
      fs.renameSync(bundle, outputPath);
      console.log(`Built and ad-hoc signed ${outputPath}`);
    } else if (JSON.stringify(describeTree(bundle)) === JSON.stringify(describeTree(outputPath))) {
      console.log(`The reviewed helper already matches a clean source build: ${outputPath}`);
    } else {
      throw new Error("The reviewed Keyclasp.app differs from the clean source build. Refusing to replace a runnable authorization helper in place; review and replace it only while Keyclasp is idle.");
    }
  }
} finally {
  fs.rmSync(temporaryRoot, { recursive: true, force: true });
}
