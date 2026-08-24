import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";

const root = process.cwd();
const read = (relativePath: string) => fs.readFileSync(path.join(root, relativePath), "utf8");

describe("macOS release contracts", () => {
  it("pins every GitHub Action to an immutable commit", () => {
    const workflow = read(".github/workflows/macos-release.yml");
    const uses = [...workflow.matchAll(/^\s*- uses:\s*(\S+)/gm)].map((match) => match[1]);

    expect(uses.length).toBeGreaterThan(0);
    for (const action of uses) {
      expect(action).toMatch(/^[^@\s]+@[0-9a-f]{40}$/);
    }
    expect(workflow).toContain("persist-credentials: false");
    expect(workflow).toContain("assert-exact-release-source.sh");
  });

  it("keeps beta and GA behind separate protected environments and evidence gates", () => {
    const workflow = read(".github/workflows/macos-release.yml");

    expect(workflow).toContain("environment: macos-beta");
    expect(workflow).toContain("environment: macos-ga");
    expect(workflow).toContain("assert-macos-release-ready.mjs ga");
    expect(read("scripts/package-macos-core.sh")).toContain("assert-macos-release-ready.mjs\" beta");

    const evidence = JSON.parse(read("docs/security/macos-release-evidence.json"));
    const gates = Object.values(evidence).filter((value) => typeof value === "object");
    expect(gates.every((gate: any) => gate.passed === false && gate.evidence === null)).toBe(true);
  });

  it("requires a release-capable native protocol instead of packaging the status spike", () => {
    const capabilityGate = read("scripts/assert-native-release-capability.sh");

    expect(capabilityGate).toContain("protocol_version 1");
    expect(capabilityGate).toContain("required_access_policy biometric_current_set");
    expect(capabilityGate).toContain('require_exactly_once lifecycle_operations "$expected_lifecycle"');
    expect(read("native/keyclasp-core/scripts/build-adhoc.sh")).toContain('"$candidate" "$profile"');
    expect(read("native/keyclasp-core/src/main.rs")).toContain("lifecycle_operations=disabled");
  });

  it("executes the native release gate against every critical status field", () => {
    const temporary = fs.mkdtempSync(path.join(process.env.TMPDIR ?? "/tmp", "keyclasp-core-gate-"));
    const gate = path.join(root, "scripts/assert-native-release-capability.sh");
    const writeCore = (name: string, backend: string) => {
      const core = path.join(temporary, name);
      fs.writeFileSync(core, `#!/bin/sh
printf '%s\\n' \\
  protocol_version=1 \\
  adapter=keyclasp_macos_v1 \\
  reported_backend=${backend} \\
  hardware_presence_available=false \\
  touch_id_available=false \\
  code_identity=ad_hoc \\
  required_access_policy=biometric_current_set \\
  current_set_policy_available=true \\
  lifecycle_operations=enabled \\
  enrollment_state=unavailable
`);
      fs.chmodSync(core, 0o755);
      return core;
    };

    try {
      const passing = spawnSync(gate, [writeCore("passing", "secure_enclave"), "beta"], { encoding: "utf8" });
      expect(passing.status, passing.stderr).toBe(0);
      const unsafe = spawnSync(gate, [writeCore("unsafe", "unsupported"), "beta"], { encoding: "utf8" });
      expect(unsafe.status).toBe(1);
      expect(unsafe.stderr).toContain("reported_backend=secure_enclave");
    } finally {
      fs.rmSync(temporary, { recursive: true, force: true });
    }
  });

  it("requires an exact immutable tag rather than a branch-like revision", () => {
    const sourceGate = read("scripts/assert-exact-release-source.sh");

    expect(sourceGate).toContain('show-ref --verify --quiet "refs/tags/$tag"');
    expect(sourceGate).toContain('rev-parse "refs/tags/$tag^{}"');
    expect(sourceGate).not.toContain("rev-list -n 1");
    const packageScript = read("scripts/package-macos-core.sh");
    expect(packageScript).toContain('archive "$commit"');
    expect(packageScript).toContain('mkdir "$lock_dir"');
    expect(packageScript).toContain('mv "$output_candidate" "$output_dir"');
    expect(packageScript).toContain("trap on_signal HUP INT TERM");
  });

  it("uses an ephemeral signing boundary and verifies notarization before candidate upload", () => {
    const workflow = read(".github/workflows/macos-release.yml");
    const ga = read("scripts/sign-notarize-macos-ga.sh");

    const build = workflow.indexOf("- name: Build GA candidate");
    const sign = workflow.indexOf("- name: Sign, notarize, staple, and assess");
    const cleanup = workflow.indexOf("trap cleanup EXIT HUP INT TERM");
    expect(build).toBeGreaterThan(-1);
    expect(sign).toBeGreaterThan(build);
    expect(cleanup).toBeGreaterThan(sign);
    expect(workflow).toContain('security create-keychain -p "$KEYCHAIN_PASSWORD" "$keychain"');
    expect(workflow).toContain('security delete-keychain "$keychain" || true');
    expect(workflow).toContain('rm -f "$certificate" "$notary_key"');
    expect(workflow).toContain('security delete-keychain "$keychain"\n');
    expect(workflow).toContain('security show-keychain-info "$keychain"');
    expect(workflow).toContain("trap - EXIT HUP INT TERM");
    expect(ga).toContain("--options runtime --timestamp");
    expect(ga).toContain("--test-requirement=");
    expect(ga).toContain("notarytool submit");
    expect(ga).toContain('result.status !== "Accepted"');
    expect(ga).toContain("stapler staple");
    expect(ga).toContain("stapler validate");
    expect(ga).toContain("spctl --assess --type open");
    expect(ga).toContain('mkdir "$lock_dir"');
    expect(ga).toContain('/usr/bin/ditto "$bundle_dir" "$candidate_bundle"');
    expect(ga).toContain('mv "$candidate_dmg" "$output_dmg"');
    expect(ga).toContain("trap on_signal HUP INT TERM");
  });

  it("grants OIDC only to minimal attestation jobs", () => {
    const workflow = read(".github/workflows/macos-release.yml");
    const headings = [...workflow.matchAll(/^  ([a-z][a-z-]+):$/gm)].map((match) => ({
      name: match[1],
      index: match.index,
    }));
    for (const buildJob of ["qualification", "beta", "ga"]) {
      const headingIndex = headings.findIndex((heading) => heading.name === buildJob);
      const start = headings[headingIndex].index;
      const section = workflow.slice(start, headings[headingIndex + 1]?.index);
      expect(section).not.toContain("id-token: write");
      expect(section).not.toContain("attestations: write");
    }
    expect(workflow.match(/id-token: write/g)).toHaveLength(3);
    expect(workflow.match(/attestations: write/g)).toHaveLength(3);
  });

  it("never weakens Gatekeeper in scripts or documentation", () => {
    const combined = [
      read("scripts/package-macos-core.sh"),
      read("scripts/sign-notarize-macos-ga.sh"),
      read("docs/macos-beta-install.md"),
      read("docs/macos-release.md"),
    ].join("\n");

    expect(combined).not.toContain("spctl --master-disable");
    expect(combined).not.toContain("xattr -dr");
    expect(combined).toContain("Open Anyway");
  });

  it("generates conformant deterministic SPDX checksums", () => {
    const temporary = fs.mkdtempSync(path.join(process.env.TMPDIR ?? "/tmp", "keyclasp-spdx-test-"));
    try {
      const artifact = path.join(temporary, "keyclasp-core");
      const output = path.join(temporary, "metadata");
      const bytes = Buffer.from("deterministic release artifact");
      fs.writeFileSync(artifact, bytes);

      const result = spawnSync(process.execPath, [
        path.join(root, "scripts/generate-macos-release-metadata.mjs"),
        artifact,
        output,
        "qualification",
        "v1.2.3-test.1",
        "0123456789abcdef0123456789abcdef01234567",
        "1700000000",
      ], { encoding: "utf8" });
      expect(result.status, result.stderr).toBe(0);

      const sbom = JSON.parse(fs.readFileSync(path.join(output, "sbom.spdx.json"), "utf8"));
      const sha1 = crypto.createHash("sha1").update(bytes).digest("hex");
      const sha256 = crypto.createHash("sha256").update(bytes).digest("hex");
      expect(sbom.files[0].checksums).toEqual([
        { algorithm: "SHA1", checksumValue: sha1 },
        { algorithm: "SHA256", checksumValue: sha256 },
      ]);
      expect(sbom.packages[0].packageVerificationCode.packageVerificationCodeValue).toBe(
        crypto.createHash("sha1").update(sha1).digest("hex"),
      );
      expect(sbom.creationInfo.created).toBe("2023-11-14T22:13:20.000Z");
      expect(sbom.documentNamespace).toContain(`/spdx-qualification-`);
      expect(sbom.documentNamespace).toContain(sha256);
    } finally {
      fs.rmSync(temporary, { recursive: true, force: true });
    }
  });
});
