#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const [binaryPath, outputDirectory, channel, tag, commit, sourceEpochText] = process.argv.slice(2);
if (!binaryPath || !outputDirectory || !channel || !tag || !commit || !sourceEpochText) {
  console.error("Usage: generate-macos-release-metadata.mjs <binary> <output-dir> <channel> <tag> <commit> <source-epoch>");
  process.exit(2);
}
const sourceEpoch = Number(sourceEpochText);
if (!Number.isSafeInteger(sourceEpoch) || sourceEpoch < 0) {
  console.error("Source epoch must be a non-negative integer.");
  process.exit(2);
}

const bytes = fs.readFileSync(binaryPath);
const sha256 = crypto.createHash("sha256").update(bytes).digest("hex");
const sha1 = crypto.createHash("sha1").update(bytes).digest("hex");
const packageVerificationCode = crypto.createHash("sha1").update(sha1).digest("hex");
const binaryName = path.basename(binaryPath);
const created = new Date(sourceEpoch * 1_000).toISOString();
const namespaceTag = tag.replace(/[^A-Za-z0-9.-]/g, "-");

fs.mkdirSync(outputDirectory, { recursive: true, mode: 0o755 });
fs.writeFileSync(path.join(outputDirectory, "manifest.json"), `${JSON.stringify({
  schemaVersion: 1,
  channel,
  tag,
  sourceCommit: commit,
  binary: binaryName,
  sha256,
}, null, 2)}\n`, { mode: 0o644 });

const sbom = {
  spdxVersion: "SPDX-2.3",
  dataLicense: "CC0-1.0",
  SPDXID: "SPDXRef-DOCUMENT",
  name: `keyclasp-macos-${namespaceTag}`,
  documentNamespace: `https://github.com/AndreaCatalucci/keyclasp/releases/${namespaceTag}/spdx-${channel}-${commit}-${sha256}`,
  creationInfo: {
    created,
    creators: ["Tool: keyclasp-generate-macos-release-metadata"],
  },
  packages: [{
    name: "keyclasp-core",
    SPDXID: "SPDXRef-Package-keyclasp-core",
    versionInfo: tag,
    downloadLocation: "NOASSERTION",
    filesAnalyzed: true,
    packageVerificationCode: {
      packageVerificationCodeValue: packageVerificationCode,
    },
    licenseConcluded: "MIT",
    licenseDeclared: "MIT",
    copyrightText: "NOASSERTION",
  }],
  files: [{
    fileName: binaryName,
    SPDXID: "SPDXRef-File-keyclasp-core",
    checksums: [
      { algorithm: "SHA1", checksumValue: sha1 },
      { algorithm: "SHA256", checksumValue: sha256 },
    ],
    licenseConcluded: "MIT",
    copyrightText: "NOASSERTION",
  }],
  relationships: [{
    spdxElementId: "SPDXRef-Package-keyclasp-core",
    relationshipType: "CONTAINS",
    relatedSpdxElement: "SPDXRef-File-keyclasp-core",
  }],
};
fs.writeFileSync(path.join(outputDirectory, "sbom.spdx.json"), `${JSON.stringify(sbom, null, 2)}\n`, { mode: 0o644 });
