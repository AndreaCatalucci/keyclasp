#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { collectNativeSourceFiles } from "./native-source-manifest.mjs";

export function verifyBundledNativeSource(dependencyRoot, sourceManifestPath) {
  const expected = JSON.parse(fs.readFileSync(sourceManifestPath, "utf8")).files;
  if (JSON.stringify(collectNativeSourceFiles(dependencyRoot)) !== JSON.stringify(expected)) {
    throw new Error("A bundled native dependency tree differs from its reviewed source manifest.");
  }
}

export function verifyNativeBinding({ dependencyRoot, manifestPath, target, sourceBuild }) {
  const prebuiltPath = path.join(dependencyRoot, "prebuilds", `${target}.node`);
  if (sourceBuild) {
    const bindingPath = path.join(dependencyRoot, "build", "Release", "better_sqlite3.node");
    if (!fs.existsSync(bindingPath)) {
      throw new Error("better-sqlite3 did not produce a source-built native binding; refusing to install Keyclasp.");
    }
    if (fs.existsSync(prebuiltPath)) {
      throw new Error("The source-build installation still contains the target prebuilt and could load the wrong native binding.");
    }
    return "Keyclasp verified an explicit better-sqlite3 source build from the bundled reviewed sources.";
  }

  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const reviewed = manifest.prebuilds[target];
  if (!reviewed) {
    throw new Error(`No reviewed better-sqlite3 prebuilt is available for ${target}; retry with npm_config_build_from_source=true and a supported compiler toolchain.`);
  }
  if (!fs.existsSync(prebuiltPath)) {
    throw new Error(`The reviewed better-sqlite3 prebuilt is missing for ${target}.`);
  }
  const received = crypto.createHash("sha256").update(fs.readFileSync(prebuiltPath)).digest("hex");
  if (received !== reviewed.bindingSha256) {
    throw new Error(`The better-sqlite3 native binding failed its reviewed SHA-256 check for ${target}; expected ${reviewed.bindingSha256}, received ${received}.`);
  }
  return `Keyclasp verified the bundled better-sqlite3 prebuilt SHA-256 for ${target}.`;
}
