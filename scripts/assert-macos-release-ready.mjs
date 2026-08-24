#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const channel = process.argv[2];
if (channel !== "beta" && channel !== "ga") {
  console.error("Usage: assert-macos-release-ready.mjs <beta|ga>");
  process.exit(2);
}

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const evidencePath = path.join(root, "docs/security/macos-release-evidence.json");
const evidence = JSON.parse(fs.readFileSync(evidencePath, "utf8"));
if (evidence.schemaVersion !== 1) {
  console.error("macOS release evidence has an unsupported schema version.");
  process.exit(1);
}

const required = ["slice1Acceptance", "recoveryAndRollback", "physicalDeviceMatrix"];
if (channel === "ga") {
  required.push("cleanMacBeta", "independentSecurityReview", "cleanMacGa");
}

const missing = required.filter((name) => {
  const gate = evidence[name];
  return gate?.passed !== true || typeof gate.evidence !== "string" || gate.evidence.trim() === "";
});
if (missing.length > 0) {
  console.error(`macOS ${channel} release blocked by evidence gates: ${missing.join(", ")}`);
  process.exit(1);
}

console.log(`macOS ${channel} release evidence gates passed.`);
