import { afterEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const temporary: string[] = [];
afterEach(() => { for (const root of temporary.splice(0)) fs.rmSync(root, { recursive: true, force: true }); });
function fixture(failTests = false) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-release-"));
  temporary.push(root);
  for (const folder of ["scripts", "bin", "docs/releases"]) fs.mkdirSync(path.join(root, folder), { recursive: true });
  fs.copyFileSync("scripts/prepare-software-beta.mjs", path.join(root, "scripts/prepare-software-beta.mjs"));
  fs.writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "keyclasp", version: "0.2.0-beta.37" }));
  for (const script of ["build-macos-biometric-helper.mjs", "release-package-manifest.mjs", "verify-packed-software-beta.mjs"]) {
    fs.writeFileSync(path.join(root, "scripts", script), "// External check succeeds in this orchestration fixture.\n");
  }
  fs.writeFileSync(path.join(root, "bin/npm"), `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
const args = process.argv.slice(2);
fs.appendFileSync('calls.log', args.join(' ') + '\\n');
if (args[0] === 'version') {
  const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  pkg.version = args[1];
  fs.writeFileSync('package.json', JSON.stringify(pkg));
}
if (args[0] === 'test' && ${failTests}) process.exit(1);
if (args[0] === 'pack') {
  const filename = 'keyclasp-' + JSON.parse(fs.readFileSync('package.json', 'utf8')).version + '.tgz';
  fs.writeFileSync(path.join(args.at(-1), filename), 'tested package');
  console.log(JSON.stringify([{filename}]));
}
`, { mode: 0o755 });
  return {
    root,
    run: (...args: string[]) => spawnSync(process.execPath, [path.join(root, "scripts/prepare-software-beta.mjs"), ...args], {
      cwd: root, encoding: "utf8", env: { ...process.env, PATH: `${root}/bin:${process.env.PATH}` },
    }),
  };
}
describe("beta release orchestration", () => {
  it("prepares arbitrary beta versions and rejects replacement of the verified tarball", () => {
    const { root, run } = fixture();
    expect(run().status).toBe(0);
    expect(run("--check").status).toBe(0);
    expect(fs.readFileSync(path.join(root, "calls.log"), "utf8")).toContain("test\nrun release:inventory:check\npack");
    fs.writeFileSync(path.join(root, "release-artifacts/keyclasp.tgz"), "different package");
    expect(run("--check").status).not.toBe(0);
  });
  it("invalidates an earlier success receipt and stops before packing when tests fail", () => {
    const { root, run } = fixture(true);
    fs.mkdirSync(path.join(root, "release-artifacts"));
    fs.writeFileSync(path.join(root, "release-artifacts/verified.json"), "{}");
    expect(run().status).not.toBe(0);
    expect(fs.existsSync(path.join(root, "release-artifacts/verified.json"))).toBe(false);
    expect(fs.readFileSync(path.join(root, "calls.log"), "utf8")).not.toContain("pack");
    expect(run("--check").status).not.toBe(0);
  });
  it("refuses a receipt for a different package version", () => {
    const { root, run } = fixture();
    expect(run().status).toBe(0);
    fs.writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "keyclasp", version: "0.2.0-beta.38" }));
    expect(run("--check").status).not.toBe(0);
  });
  it.each([false, true])("runs the configured release command without publishing (resume=%s)", resume => {
    const { root } = fixture();
    const config = JSON.parse(fs.readFileSync(".release-it.json", "utf8"));
    config.git = false;
    config.npm.publish = false;
    fs.writeFileSync(path.join(root, ".release-it.json"), JSON.stringify(config));
    const releaseArgs = JSON.parse(fs.readFileSync("package.json", "utf8")).scripts["release:beta"].split(" ").slice(1);
    const result = spawnSync(process.execPath, [path.resolve("node_modules/release-it/bin/release-it.js"), ...releaseArgs, ...(resume ? ["--no-increment"] : []), "--ci"], {
      cwd: root, encoding: "utf8", env: { ...process.env, PATH: `${root}/bin:${process.env.PATH}` },
    });
    expect(result.status, result.stdout + result.stderr).toBe(0);
    expect(JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8")).version).toBe(resume ? "0.2.0-beta.37" : "0.2.0-beta.38");
    expect(JSON.parse(fs.readFileSync(path.join(root, "release-artifacts/verified.json"), "utf8")).version).toBe(resume ? "0.2.0-beta.37" : "0.2.0-beta.38");
    expect(fs.readFileSync(path.join(root, "calls.log"), "utf8")).not.toContain("publish");
  });
  it.each([false, true])("gates release-it publication on successful preparation (failure=%s)", failTests => {
    const { root } = fixture(failTests);
    const config = JSON.parse(fs.readFileSync(".release-it.json", "utf8"));
    config.git = false;
    config.npm.skipChecks = true;
    fs.writeFileSync(path.join(root, ".release-it.json"), JSON.stringify(config));
    // PATH supplies the fixture npm executable: no registry or credentials are used.
    const result = spawnSync(process.execPath, [path.resolve("node_modules/release-it/bin/release-it.js"), "prerelease", "--preRelease=beta", "--ci"], {
      cwd: root, encoding: "utf8", env: { ...process.env, PATH: `${root}/bin:${process.env.PATH}` },
    });
    const calls = fs.readFileSync(path.join(root, "calls.log"), "utf8");
    if (failTests) {
      expect(result.status).not.toBe(0);
      expect(calls).not.toContain("publish");
    } else {
      expect(result.status, result.stdout + result.stderr).toBe(0);
      expect(calls).toContain("publish ./release-artifacts/keyclasp.tgz --tag beta --ignore-scripts");
    }
  });
  it("lets npm resolve the configured publish path as a local tarball", () => {
    const { root } = fixture();
    const config = JSON.parse(fs.readFileSync(".release-it.json", "utf8"));
    const directory = path.join(root, "release-artifacts");
    fs.mkdirSync(directory);
    const options = {
      cwd: root, encoding: "utf8" as const,
      env: { ...process.env, GIT_SSH_COMMAND: "false" },
    };
    const packed = spawnSync("npm", ["pack", "--ignore-scripts", "--offline", "--json", "--pack-destination", directory], options);
    expect(packed.status, packed.stderr).toBe(0);
    fs.copyFileSync(path.join(directory, JSON.parse(packed.stdout)[0].filename), path.join(directory, "keyclasp.tgz"));
    const published = spawnSync("npm", ["publish", config.npm.publishPath, "--tag", config.npm.tag, "--ignore-scripts", "--dry-run", "--offline"], options);
    expect(published.status, published.stdout + published.stderr).toBe(0);
    expect(published.stdout).toContain("keyclasp@0.2.0-beta.37");
  });
  it("publishes only the prepared tarball to beta with scripts disabled", () => {
    const config = JSON.parse(fs.readFileSync(".release-it.json", "utf8"));
    expect(config.git.addUntrackedFiles).toBe(false);
    expect(config.npm.publishPath).toBe("./release-artifacts/keyclasp.tgz");
    expect(config.npm.tag).toBe("beta");
    expect(config.npm.publishArgs).toContain("--ignore-scripts");
    expect(config.hooks["before:npm:release"]).toBe("node scripts/prepare-software-beta.mjs --check");
  });
});
