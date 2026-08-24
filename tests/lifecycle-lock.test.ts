import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { acquireVaultLifecycleLock, lifecycleModeForCommand } from "../src/lifecycle-lock.js";
import { clearKey, closeDb } from "../src/vault.js";

describe("vault lifecycle serialization", () => {
  let root: string;
  let previousHome: string | undefined;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-lifecycle-"));
    previousHome = process.env.KEYCLASP_HOME;
    process.env.KEYCLASP_HOME = path.join(root, ".keyclasp");
    closeDb();
    clearKey();
  });

  afterEach(() => {
    closeDb();
    clearKey();
    if (previousHome === undefined) delete process.env.KEYCLASP_HOME;
    else process.env.KEYCLASP_HOME = previousHome;
    fs.rmSync(root, { recursive: true, force: true });
  });

  it("initializes a fresh lifecycle database safely in two simultaneous processes", async () => {
    const modulePath = path.join(process.cwd(), "dist", "lifecycle-lock.js");
    const releasePath = path.join(root, "release-fresh-schema");
    const environment = { ...process.env, KEYCLASP_HOME: process.env.KEYCLASP_HOME };
    const readyPaths = [0, 1].map((index) => path.join(root, `fresh-schema-${index}.ready`));
    const children = readyPaths.map((readyPath) => {
      const childSource = `
        import fs from "node:fs";
        import { acquireVaultLifecycleLock, setFreshLifecycleSchemaBarrierForTests } from ${JSON.stringify(`file://${modulePath}`)};
        setFreshLifecycleSchemaBarrierForTests(() => {
          fs.writeFileSync(${JSON.stringify(readyPath)}, "ready");
          const waitArray = new Int32Array(new SharedArrayBuffer(4));
          while (!fs.existsSync(${JSON.stringify(releasePath)})) Atomics.wait(waitArray, 0, 0, 10);
        });
        const lock = acquireVaultLifecycleLock("shared");
        process.stdout.write("acquired\\n");
        setTimeout(() => lock.release(), 100);
      `;
      return spawn(process.execPath, ["--input-type=module", "-e", childSource], {
        env: environment,
        stdio: ["ignore", "pipe", "pipe"],
      });
    });
    const results = children.map((child) => new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve, reject) => {
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (chunk) => { stdout += chunk; });
      child.stderr.on("data", (chunk) => { stderr += chunk; });
      child.once("error", reject);
      child.once("exit", (code) => resolve({ code, stdout, stderr }));
    }));
    await new Promise<void>((resolve, reject) => {
      const deadline = Date.now() + 5_000;
      const poll = () => {
        if (readyPaths.every((readyPath) => fs.existsSync(readyPath))) return resolve();
        if (Date.now() >= deadline) return reject(new Error("Both lifecycle openers did not reach the fresh-schema barrier."));
        setTimeout(poll, 10);
      };
      poll();
    });
    fs.writeFileSync(releasePath, "release");

    for (const result of await Promise.all(results)) {
      expect(result.code, result.stderr).toBe(0);
      expect(result.stdout).toBe("acquired\n");
    }
  });

  it("assigns every policy, recovery, and rename command an exclusive lifecycle lock", () => {
    for (const command of ["init", "lock", "unlock", "backup", "rename"]) {
      expect(lifecycleModeForCommand(command), command).toBe("exclusive");
    }
    for (const command of ["run", "get", "status", "list", "set", "delete", "use", "projects", "environments"]) {
      expect(lifecycleModeForCommand(command), command).toBe("shared");
    }
  });

  it("makes an exclusive restore-style operation wait for a live shared command", async () => {
    const modulePath = path.join(process.cwd(), "dist", "lifecycle-lock.js");
    const child = spawn(process.execPath, [
      "--input-type=module",
      "-e",
      `import { acquireVaultLifecycleLock } from ${JSON.stringify(`file://${modulePath}`)}; const lock = acquireVaultLifecycleLock("shared"); process.stdout.write("ready\\n"); setTimeout(() => { lock.release(); }, 250);`,
    ], {
      env: { ...process.env, KEYCLASP_HOME: process.env.KEYCLASP_HOME },
      stdio: ["ignore", "pipe", "pipe"],
    });
    await new Promise<void>((resolve, reject) => {
      child.stdout.once("data", () => resolve());
      child.once("error", reject);
      child.once("exit", (code) => { if (code && code !== 0) reject(new Error(`lock holder exited ${code}`)); });
    });
    const started = Date.now();
    const exclusive = acquireVaultLifecycleLock("exclusive");
    const elapsed = Date.now() - started;
    exclusive.release();
    expect(elapsed).toBeGreaterThanOrEqual(150);
  });

  it("does not time out behind a shared command that runs longer than five seconds", async () => {
    const modulePath = path.join(process.cwd(), "dist", "lifecycle-lock.js");
    const child = spawn(process.execPath, [
      "--input-type=module",
      "-e",
      `import { acquireVaultLifecycleLock } from ${JSON.stringify(`file://${modulePath}`)}; const lock = acquireVaultLifecycleLock("shared"); process.stdout.write("ready\\n"); setTimeout(() => { lock.release(); }, 5250);`,
    ], {
      env: { ...process.env, KEYCLASP_HOME: process.env.KEYCLASP_HOME },
      stdio: ["ignore", "pipe", "pipe"],
    });
    await new Promise<void>((resolve, reject) => {
      child.stdout.once("data", () => resolve());
      child.once("error", reject);
    });
    const started = Date.now();
    const exclusive = acquireVaultLifecycleLock("exclusive");
    const elapsed = Date.now() - started;
    exclusive.release();
    expect(elapsed).toBeGreaterThanOrEqual(5000);
    await new Promise<void>((resolve) => child.once("exit", () => resolve()));
  }, 10_000);

  it("allows a second ordinary CLI command while a named child holds a shared lock", async () => {
    const cliPath = path.join(process.cwd(), "dist", "cli.js");
    const environment = { ...process.env, KEYCLASP_HOME: process.env.KEYCLASP_HOME };
    expect(spawnSync(process.execPath, [cliPath, "init"], { encoding: "utf8", input: "\n", env: environment }).status).toBe(0);
    expect(spawnSync(process.execPath, [cliPath, "set", "API_KEY", "--project", "app", "--environment", "prod"], {
      encoding: "utf8",
      input: "value\n",
      env: environment,
    }).status).toBe(0);
    const holder = spawn(process.execPath, [
      cliPath,
      "run", "--project", "app", "--environment", "prod", "--env", "API_KEY", "--",
      process.execPath, "-e", "console.log('ready'); setTimeout(() => {}, 5500)",
    ], { env: environment, stdio: ["ignore", "pipe", "pipe"] });
    await new Promise<void>((resolve, reject) => {
      holder.stdout.once("data", () => resolve());
      holder.once("error", reject);
    });
    const started = Date.now();
    const list = spawnSync(process.execPath, [cliPath, "list", "--project", "app", "--environment", "prod"], {
      encoding: "utf8",
      env: environment,
    });
    const elapsed = Date.now() - started;
    await new Promise<void>((resolve) => holder.once("exit", () => resolve()));
    expect(list.status, list.stderr).toBe(0);
    expect(list.stdout).toContain("API_KEY");
    expect(elapsed).toBeLessThan(3000);
  }, 10_000);
});
