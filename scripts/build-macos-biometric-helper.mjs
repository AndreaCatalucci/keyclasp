#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const repository = path.resolve(import.meta.dirname, "..");
const sourceDirectory = path.join(repository, "native", "macos-biometric");
const configPath = path.join(sourceDirectory, "build-config.json");
const outputPath = path.join(repository, "native", "Keyclasp.app");
const metadataPath = path.join(repository, "keyclasp-macos-helper-candidate.json");
const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
const args = new Set(process.argv.slice(2));
const check = args.has("--check");
const sourceCheck = args.has("--source-check");
const replace = args.has("--replace");

if ([check, sourceCheck, replace].filter(Boolean).length > 1 || [...args].some((arg) => !["--check", "--source-check", "--replace"].includes(arg))) {
  throw new Error("Usage: build-macos-biometric-helper.mjs [--check|--source-check|--replace]");
}
if (process.platform !== "darwin" || process.arch !== "arm64") {
  throw new Error("The Keyclasp Touch ID helper must be built on macOS arm64.");
}

const toolEnv = {
  PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
  LANG: "C",
  LC_ALL: "C",
  TMPDIR: "/tmp",
};

function execute(command, commandArgs, options = {}) {
  return spawnSync(command, commandArgs, {
    encoding: "utf8",
    env: toolEnv,
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
  });
}

function run(command, commandArgs) {
  const result = execute(command, commandArgs);
  if (result.status !== 0 || result.error) {
    throw new Error(`${command} failed: ${result.error?.message ?? result.stderr}`);
  }
  return `${result.stdout}${result.stderr}`.trim();
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function fileDescriptor(absolutePath, relativePath) {
  return {
    path: relativePath,
    sha256: sha256(fs.readFileSync(absolutePath)),
  };
}

function describeTree(root, prefix) {
  const files = [];
  const visit = (directory, relative = "") => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const entryRelative = path.posix.join(relative, entry.name);
      const entryPath = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(entryPath, entryRelative);
      else if (entry.isFile()) files.push({
        ...fileDescriptor(entryPath, path.posix.join(prefix, entryRelative)),
        mode: fs.statSync(entryPath).mode & 0o777,
      });
      else throw new Error(`Unsupported helper bundle entry: ${entryRelative}`);
    }
  };
  visit(root);
  return files.sort((left, right) => left.path.localeCompare(right.path));
}

function collectToolchain() {
  const developerDirectory = run("/usr/bin/xcode-select", ["-p"]);
  const xcodeResult = execute("/usr/bin/xcodebuild", ["-version"]);
  const clangVersion = run(config.compiler, ["--version"]).split("\n")[0];
  const linkerVersion = run("/usr/bin/ld", ["-v"]);
  const linkerProject = /PROJECT:(ld-[^\s]+)/.exec(linkerVersion)?.[1] ?? null;
  const sdkPath = run("/usr/bin/xcrun", ["--sdk", config.sdk, "--show-sdk-path"]);
  const sdkVersion = run("/usr/bin/xcrun", ["--sdk", config.sdk, "--show-sdk-version"]);
  const sdkBuildVersion = run("/usr/bin/xcrun", ["--sdk", config.sdk, "--show-sdk-build-version"]);
  const codesignIdentity = run("/usr/bin/what", ["/usr/bin/codesign"]);
  const codesignProject = /PROJECT:(codesign-[^\s]+)/.exec(codesignIdentity)?.[1] ?? null;
  return {
    developerDirectory,
    xcodeVersion: xcodeResult.status === 0 ? xcodeResult.stdout.trim() : null,
    xcodeUnavailable: xcodeResult.status === 0
      ? null
      : "Full Xcode is unavailable; the active developer directory provides Command Line Tools only.",
    clangPath: config.compiler,
    clangVersion,
    linkerPath: "/usr/bin/ld",
    linkerProject,
    sdkPath,
    sdkVersion,
    sdkBuildVersion,
    codesignPath: "/usr/bin/codesign",
    codesignProject,
  };
}

function assertQualificationToolchain(toolchain) {
  const pins = config.qualificationToolchain;
  for (const key of [
    "developerDirectory",
    "xcodeVersion",
    "clangVersion",
    "linkerProject",
    "sdkVersion",
    "sdkBuildVersion",
    "codesignProject",
  ]) {
    if (toolchain[key] !== pins[key]) {
      throw new Error(`The helper qualification toolchain does not match ${key}: expected ${JSON.stringify(pins[key])}, received ${JSON.stringify(toolchain[key])}.`);
    }
  }
}

function assertRecordedSourceRevision(metadata) {
  if (!/^[a-f0-9]{40}$/.test(metadata.sourceRevision ?? "")) {
    throw new Error("The helper candidate metadata does not name a complete source revision.");
  }
  const ancestor = execute("/usr/bin/git", [
    "-C", repository, "merge-base", "--is-ancestor", metadata.sourceRevision, "HEAD",
  ]);
  if (ancestor.status !== 0 || ancestor.error) {
    throw new Error("The helper candidate source revision is not an ancestor of the current source.");
  }
}

function buildUnsignedBundle(root, sdkPath) {
  const bundle = path.join(root, "Keyclasp.app");
  const contents = path.join(bundle, "Contents");
  const executableDirectory = path.join(contents, "MacOS");
  const executable = path.join(executableDirectory, "keyclasp-biometric");
  fs.mkdirSync(executableDirectory, { recursive: true, mode: 0o755 });
  fs.copyFileSync(path.join(sourceDirectory, "Info.plist"), path.join(contents, "Info.plist"));
  fs.chmodSync(path.join(contents, "Info.plist"), 0o644);

  run(config.compiler, [
    "-arch", config.architecture,
    "-isysroot", sdkPath,
    `-mmacosx-version-min=${config.deploymentTarget}`,
    ...config.compileFlags,
    path.join(sourceDirectory, "main.m"),
    ...config.frameworks.flatMap((framework) => ["-framework", framework]),
    "-o", executable,
  ]);
  fs.chmodSync(executable, 0o755);
  return { bundle, executable };
}

function signAndVerify(bundle, executable) {
  run("/usr/bin/codesign", [
    "--force",
    "--sign", config.signing.identity,
    "--timestamp=none",
    "--options", "runtime",
    "--identifier", config.bundleIdentifier,
    bundle,
  ]);
  run("/usr/bin/codesign", ["--verify", "--strict", bundle]);
  if (run("/usr/bin/lipo", ["-archs", executable]) !== config.architecture) {
    throw new Error(`The Keyclasp Touch ID helper must contain only ${config.architecture} code.`);
  }
  const signature = run("/usr/bin/codesign", ["-d", "--verbose=4", "-r-", bundle]);
  if (!signature.includes("runtime")) {
    throw new Error("The Keyclasp Touch ID helper signature is missing the hardened-runtime option.");
  }
  const entitlements = execute("/usr/bin/codesign", ["-d", "--entitlements", "-", bundle]);
  if (entitlements.status !== 0 || entitlements.error || entitlements.stdout.trim().length !== 0) {
    throw new Error("The Keyclasp Touch ID helper has unexpected entitlements.");
  }
  return signature;
}

function createMetadata(bundle, signature, toolchain, unsignedSha256) {
  const designatedRequirement = /^# designated => (.+)$/m.exec(signature)?.[1];
  if (!designatedRequirement) throw new Error("Could not read the helper designated requirement.");
  const sourceFiles = ["Info.plist", "build-config.json", "main.m"].map((name) => fileDescriptor(
    path.join(sourceDirectory, name),
    `native/macos-biometric/${name}`,
  ));
  const sourceRevision = run("/usr/bin/git", ["-C", repository, "rev-parse", "HEAD"]);
  return {
    schemaVersion: 2,
    status: "local-source-candidate",
    qualified: false,
    sourceRevision,
    bundle: "Keyclasp.app",
    bundleIdentifier: config.bundleIdentifier,
    architecture: config.architecture,
    designatedRequirement,
    signature: {
      kind: "ad-hoc",
      hardenedRuntime: true,
      entitlements: [],
    },
    buildInputs: {
      sdk: config.sdk,
      deploymentTarget: config.deploymentTarget,
      compiler: config.compiler,
      compileFlags: config.compileFlags,
      frameworks: config.frameworks,
      signing: config.signing,
    },
    toolchain,
    reproducibility: {
      comparedBeforeSigning: true,
      byteIdentical: true,
      unsignedExecutableSha256: unsignedSha256,
    },
    sourceFiles,
    bundleFiles: describeTree(bundle, "native/Keyclasp.app"),
  };
}

const temporaryRoot = fs.mkdtempSync(path.join(repository, "native", ".keyclasp-biometric-build-"));
try {
  const toolchain = collectToolchain();
  if (!sourceCheck) assertQualificationToolchain(toolchain);
  const first = buildUnsignedBundle(path.join(temporaryRoot, "first"), toolchain.sdkPath);
  const second = buildUnsignedBundle(path.join(temporaryRoot, "second"), toolchain.sdkPath);
  const firstUnsigned = fs.readFileSync(first.executable);
  const secondUnsigned = fs.readFileSync(second.executable);
  if (!firstUnsigned.equals(secondUnsigned)) {
    throw new Error("Two clean unsigned helper builds with the declared inputs are not byte-identical.");
  }
  if (!fs.readFileSync(path.join(first.bundle, "Contents", "Info.plist")).equals(
    fs.readFileSync(path.join(second.bundle, "Contents", "Info.plist")),
  )) {
    throw new Error("Two clean helper bundles do not contain identical Info.plist files.");
  }
  const signature = signAndVerify(first.bundle, first.executable);
  const metadata = createMetadata(first.bundle, signature, toolchain, sha256(firstUnsigned));
  const metadataText = `${JSON.stringify(metadata, null, 2)}\n`;

  if (sourceCheck) {
    console.log("Compiled and hardened the Touch ID helper from explicit source inputs; exact candidate comparison remains release-only.");
  } else if (check) {
    const recordedMetadata = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
    assertRecordedSourceRevision(recordedMetadata);
    metadata.sourceRevision = recordedMetadata.sourceRevision;
    const checkedMetadataText = `${JSON.stringify(metadata, null, 2)}\n`;
    if (JSON.stringify(describeTree(first.bundle, "native/Keyclasp.app")) !== JSON.stringify(describeTree(outputPath, "native/Keyclasp.app"))) {
      throw new Error("The candidate Keyclasp.app differs from two clean builds using the declared qualification toolchain.");
    }
    if (fs.readFileSync(metadataPath, "utf8") !== checkedMetadataText) {
      throw new Error("keyclasp-macos-helper-candidate.json does not match the declared helper build inputs and output.");
    }
    console.log(`Verified two clean unsigned builds and the packaged candidate metadata for ${outputPath}`);
  } else if (!fs.existsSync(outputPath)) {
    fs.renameSync(first.bundle, outputPath);
    fs.writeFileSync(metadataPath, metadataText, { mode: 0o644 });
    console.log(`Built, hardened, and recorded ${outputPath}`);
  } else if (replace) {
    const previous = path.join(temporaryRoot, "previous-Keyclasp.app");
    fs.renameSync(outputPath, previous);
    try {
      fs.renameSync(first.bundle, outputPath);
      fs.writeFileSync(metadataPath, metadataText, { mode: 0o644 });
      fs.rmSync(previous, { recursive: true, force: true });
    } catch (error) {
      if (!fs.existsSync(outputPath) && fs.existsSync(previous)) fs.renameSync(previous, outputPath);
      throw error;
    }
    console.log(`Replaced the local helper with the hardened candidate and wrote ${metadataPath}`);
  } else {
    throw new Error("The reviewed Keyclasp.app already exists. Pass --check to verify it or --replace to install a reviewed local candidate.");
  }
} finally {
  fs.rmSync(temporaryRoot, { recursive: true, force: true });
}
