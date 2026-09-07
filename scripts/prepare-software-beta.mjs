#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const root = path.resolve(import.meta.dirname, "..");
process.chdir(root);
const { name, version } = JSON.parse(fs.readFileSync("package.json", "utf8"));
if (name !== "keyclasp" || !/^\d+\.\d+\.\d+-beta\.\d+$/.test(version)) {
  throw new Error("The release must have a numeric beta version, such as 0.2.0-beta.3.");
}
const directory = path.join(root, "release-artifacts");
const artifact = path.join(directory, "keyclasp.tgz");
const receipt = path.join(directory, "verified.json");
const manifest = `docs/releases/${version}-package-manifest.json`;
const hash = file => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
function run(command, args, options = {}) {
  const result = spawnSync(command, args, { stdio: "inherit", ...options });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} ${args.join(" ")} failed; publication stopped.`);
  return result;
}
function node(script, ...args) { return run(process.execPath, [script, ...args]); }

if (process.argv.includes("--check")) {
  const checked = JSON.parse(fs.readFileSync(receipt, "utf8"));
  if (checked.version !== version || checked.sha256 !== hash(artifact)) {
    throw new Error("The package changed after verification. Run release:prepare again.");
  }
  node("scripts/release-package-manifest.mjs", artifact, "--check", manifest);
  console.log(`Verified ${name}@${version}: ${checked.sha256}`);
} else {
  if (process.argv.length > 2) throw new Error("Usage: node scripts/prepare-software-beta.mjs [--check]");
  fs.mkdirSync(directory, { recursive: true });
  // A failed retry must never leave a publishable success receipt behind.
  fs.rmSync(receipt, { force: true });
  node("scripts/build-macos-biometric-helper.mjs", "--check");
  run("npm", ["run", "release:inventory"]);
  run("npm", ["test"]);
  run("npm", ["run", "release:inventory:check"]);
  const packed = run("npm", ["pack", "--ignore-scripts", "--json", "--pack-destination", directory], {
    encoding: "utf8", stdio: ["ignore", "pipe", "inherit"],
  });
  const filename = JSON.parse(packed.stdout)[0].filename;
  const versionedArtifact = path.join(directory, filename);
  const sha256 = hash(versionedArtifact);
  // release-it publishes this fixed path, never a rebuilt working directory.
  fs.copyFileSync(versionedArtifact, artifact);
  node("scripts/release-package-manifest.mjs", artifact, "--write", manifest);
  run(process.execPath, ["scripts/verify-packed-software-beta.mjs", artifact], {
    env: { ...process.env, EXPECTED_SHA256: sha256 },
  });
  fs.writeFileSync(`docs/releases/${version}.md`, `# Keyclasp ${version}\n\nSoftware beta for local coding-agent workflows. See the Git release commit for the source changes.\n\nInstall or update with \`npm install -g keyclasp@beta\`.\n\nPackage: \`${filename}\`\n\nSHA-256: \`${sha256}\`\n\nSource tests and exact-package checks passed on ${process.platform}/${process.arch}, Node ${process.version}. Physical authorization, other platform combinations, and independent security review are not established by this release command. The broader manual qualification workflow remains separate.\n`);
  fs.writeFileSync(receipt, JSON.stringify({ version, sha256 }, null, 2) + "\n");
  console.log(`Prepared ${name}@${version}: ${artifact}`);
}
