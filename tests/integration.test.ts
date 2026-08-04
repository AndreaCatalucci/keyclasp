import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const cliPath = path.join(process.cwd(), "dist", "cli.js");
let vaultHome: string;

function run(args: string[], opts: { input?: string } = {}) {
  return spawnSync(process.execPath, [cliPath, ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, KEYCLASP_HOME: vaultHome },
    input: opts.input,
    stdio: ["pipe", "pipe", "pipe"],
  });
}

beforeAll(() => {
  execFileSync("npm", ["run", "build", "--silent"], {
    cwd: process.cwd(),
    stdio: ["ignore", "ignore", "pipe"],
  });
});

beforeEach(() => {
  vaultHome = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-cli-"));
});

describe("CLI end-to-end flow", () => {
  it("refuses set/get/list/delete/run before init", () => {
    for (const args of [["set", "X"], ["get", "X"], ["list"], ["delete", "X"], ["run", "--", "echo", "hi"]]) {
      const result = run(args, { input: "" });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("not initialized");
    }
  });

  it("initializes, stores, lists, resolves, and deletes a secret", () => {
    expect(run(["init"], { input: "test-passphrase\n" }).status).toBe(0);

    const set = run(["set", "API_KEY"], { input: "sk-test-value-123\n" });
    expect(set.status).toBe(0);
    expect(set.stdout).toContain('Stored "API_KEY"');

    const get = run(["get", "API_KEY"]);
    expect(get.status).toBe(0);
    expect(get.stdout.trim()).toBe("sk-test-value-123");

    const list = run(["list"]);
    expect(list.stdout).toContain("API_KEY");

    const del = run(["delete", "API_KEY"]);
    expect(del.status).toBe(0);
    expect(run(["get", "API_KEY"]).status).toBe(1);
  });

  it("passes the vault status check for a healthy vault", () => {
    run(["init"], { input: "\n" });
    run(["set", "STATUS_KEY"], { input: "value\n" });
    const status = run(["status"]);
    expect(status.status).toBe(0);
    expect(status.stdout).toContain("verified");
  });
});

describe("CLI run — secret injection stays out of the agent's view", () => {
  beforeEach(() => {
    run(["init"], { input: "\n" });
    run(["set", "INJECTED_SECRET"], { input: "sk-super-secret-value\n" });
  });

  it("injects the stored secret into the child process environment", () => {
    const result = run([
      "run",
      "--",
      process.execPath,
      "-e",
      "console.log(process.env.INJECTED_SECRET === 'sk-super-secret-value' ? 'ok' : 'missing')",
    ]);
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe("ok");
  });

  it("never prints the secret value to the parent's own stdout for the run command itself", () => {
    const result = run(["run", "--", "node", "-e", "0"]);
    expect(result.stdout).not.toContain("sk-super-secret-value");
    expect(result.stderr).not.toContain("sk-super-secret-value");
  });

  it("redacts and blocks a child command that leaks the secret to stdout", () => {
    const result = run([
      "run",
      "--",
      process.execPath,
      "-e",
      "console.log(process.env.INJECTED_SECRET)",
    ]);
    expect(result.status).toBe(2);
    expect(result.stdout).not.toContain("sk-super-secret-value");
    expect(result.stdout).toContain("[KEYCLASP_REDACTED]");
    expect(result.stderr).toContain("terminated");
  });

  it("blocks commands that would dump the whole environment", () => {
    const result = run(["run", "--", "env"]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("BLOCKED");
    expect(result.stdout).not.toContain("sk-super-secret-value");
  });

  it("supports explicit --env mapping to a differently named variable", () => {
    const result = run([
      "run",
      "--env",
      "INJECTED_SECRET:RENAMED",
      "--",
      process.execPath,
      "-e",
      "console.log(process.env.RENAMED === 'sk-super-secret-value' ? 'ok' : 'missing')",
    ]);
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe("ok");
  });
});
