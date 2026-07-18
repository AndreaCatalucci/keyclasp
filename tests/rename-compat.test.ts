import { afterEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { readConfig, writeConfig } from "../src/config.js";
import { installHook } from "../src/hook.js";

const tempDirs: string[] = [];
const originalCwd = process.cwd();

afterEach(() => {
  process.chdir(originalCwd);
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe("Keyblind rename compatibility", () => {
  it("reads a legacy .keyblind project config and writes future changes to .keyclasp", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-config-"));
    tempDirs.push(dir);
    fs.writeFileSync(path.join(dir, ".keyblind"), JSON.stringify({ backend: "env" }));

    expect(readConfig(dir)).toEqual({ backend: "env" });
    writeConfig({ backend: "local" }, dir);
    expect(JSON.parse(fs.readFileSync(path.join(dir, ".keyclasp"), "utf8"))).toEqual({ backend: "local" });
  });

  it("replaces a legacy Keyblind pre-commit hook with the Keyclasp hook", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-hook-"));
    tempDirs.push(dir);
    const hooksDir = path.join(dir, ".git", "hooks");
    const hookPath = path.join(hooksDir, "pre-commit");
    fs.mkdirSync(hooksDir, { recursive: true });
    fs.writeFileSync(hookPath, "#!/usr/bin/env bash\nkeyblind check-secrets\n", { mode: 0o755 });
    process.chdir(dir);

    expect(installHook()).toBe(fs.realpathSync(hookPath));

    const hook = fs.readFileSync(hookPath, "utf8");
    expect(hook).toContain("# Installed by: keyclasp install-hook");
    expect(hook).toContain("keyclasp check-secrets");
    expect(hook).not.toMatch(/\bkeyblind\b/);
    expect(fs.statSync(hookPath).mode & 0o111).not.toBe(0);
  });
});
