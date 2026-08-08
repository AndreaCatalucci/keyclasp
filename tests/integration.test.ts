import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { initializeVault, getKey, closeDb, clearKey, encrypt } from "../src/vault.js";

const cliPath = path.join(process.cwd(), "dist", "cli.js");
let vaultHome: string;

function run(args: string[], opts: { input?: string; env?: NodeJS.ProcessEnv } = {}) {
  return spawnSync(process.execPath, [cliPath, ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, KEYCLASP_HOME: vaultHome, ...opts.env },
    input: opts.input,
    stdio: ["pipe", "pipe", "pipe"],
  });
}

function runAsync(args: string[], env: NodeJS.ProcessEnv): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cliPath, ...args], {
      cwd: process.cwd(),
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (status) => resolve({ status, stdout, stderr }));
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

describe("CLI projects and environments scoping", () => {
  beforeEach(() => {
    run(["init"], { input: "\n" });
  });

  it("keeps unscoped usage working exactly as before, under default/default", () => {
    run(["set", "PLAIN_KEY"], { input: "plain-value\n" });
    const get = run(["get", "PLAIN_KEY"]);
    expect(get.stdout.trim()).toBe("plain-value");

    const scoped = run(["get", "PLAIN_KEY", "--project", "default", "--environment", "default"]);
    expect(scoped.stdout.trim()).toBe("plain-value");
  });

  it("round-trips a secret through explicit --project/--environment flags", () => {
    const set = run(["set", "DB_URL", "--project", "myapp", "--environment", "prod"], { input: "postgres://prod\n" });
    expect(set.status).toBe(0);
    expect(set.stdout).toContain("myapp/prod");

    const get = run(["get", "DB_URL", "--project", "myapp", "--environment", "prod"]);
    expect(get.status).toBe(0);
    expect(get.stdout.trim()).toBe("postgres://prod");

    // Same name, different scope, is a distinct secret.
    const missing = run(["get", "DB_URL", "--project", "myapp", "--environment", "staging"]);
    expect(missing.status).toBe(1);
    expect(missing.stderr).toContain('not found in project "myapp" environment "staging"');
  });

  it("supports -p/-E short flags and flags appearing after the name", () => {
    run(["set", "SHORT_FLAG_KEY", "-p", "shortapp", "-E", "prod"], { input: "value\n" });
    const get = run(["get", "SHORT_FLAG_KEY", "-p", "shortapp", "-E", "prod"]);
    expect(get.stdout.trim()).toBe("value");
  });

  it("prints a note the first time a project/environment combo is used, but not the second", () => {
    const first = run(["set", "FIRST", "--project", "newproj", "--environment", "newenv"], { input: "a\n" });
    expect(first.stdout).toContain('Note: "newproj/newenv" is a new project/environment combo.');

    const second = run(["set", "SECOND", "--project", "newproj", "--environment", "newenv"], { input: "b\n" });
    expect(second.stdout).not.toContain("new project/environment combo");
  });

  it("list filters independently by --project, --environment, both, or --all", () => {
    run(["set", "ONE", "--project", "app-a", "--environment", "prod"], { input: "1\n" });
    run(["set", "TWO", "--project", "app-a", "--environment", "staging"], { input: "2\n" });
    run(["set", "THREE", "--project", "app-b", "--environment", "prod"], { input: "3\n" });

    const byProject = run(["list", "--project", "app-a"]);
    expect(byProject.stdout).toContain("prod/ONE");
    expect(byProject.stdout).toContain("staging/TWO");
    expect(byProject.stdout).not.toContain("THREE");

    const byEnvironment = run(["list", "--environment", "prod"]);
    expect(byEnvironment.stdout).toContain("app-a/ONE");
    expect(byEnvironment.stdout).toContain("app-b/THREE");
    expect(byEnvironment.stdout).not.toContain("TWO");

    const exact = run(["list", "--project", "app-a", "--environment", "prod"]);
    expect(exact.stdout.trim()).toBe("- ONE");

    const all = run(["list", "--all"]);
    expect(all.stdout).toContain("app-a/prod/ONE");
    expect(all.stdout).toContain("app-a/staging/TWO");
    expect(all.stdout).toContain("app-b/prod/THREE");
  });

  it("lists distinct project and environment names", () => {
    run(["set", "A", "--project", "zeta", "--environment", "prod"], { input: "1\n" });
    run(["set", "B", "--project", "alpha", "--environment", "staging"], { input: "2\n" });

    const projects = run(["projects"]);
    expect(projects.stdout).toContain("alpha");
    expect(projects.stdout).toContain("zeta");

    const environments = run(["environments"]);
    expect(environments.stdout).toContain("prod");
    expect(environments.stdout).toContain("staging");
  });

  it("use persists a project/environment context that later commands pick up without flags", () => {
    run(["set", "CONTEXT_KEY", "--project", "ctxapp", "--environment", "ctxenv"], { input: "ctx-value\n" });

    const useResult = run(["use", "ctxapp", "ctxenv"]);
    expect(useResult.status).toBe(0);

    const get = run(["get", "CONTEXT_KEY"]);
    expect(get.stdout.trim()).toBe("ctx-value");

    const status = run(["status"]);
    expect(status.stdout).toContain("ctxapp/ctxenv");
    expect(status.stdout).toContain("context-file");

    const clear = run(["use", "--clear"]);
    expect(clear.status).toBe(0);
    const afterClear = run(["get", "CONTEXT_KEY"]);
    expect(afterClear.status).toBe(1);
  });

  it("an env var overrides the persisted context, and an explicit flag overrides both", () => {
    run(["set", "LAYER_KEY", "--project", "flagapp", "--environment", "flagenv"], { input: "flag-value\n" });
    run(["set", "LAYER_KEY", "--project", "envapp", "--environment", "envenv"], { input: "env-value\n" });
    run(["set", "LAYER_KEY", "--project", "fileapp", "--environment", "fileenv"], { input: "file-value\n" });
    run(["use", "fileapp", "fileenv"]);

    const viaContextFile = run(["get", "LAYER_KEY"]);
    expect(viaContextFile.stdout.trim()).toBe("file-value");

    const viaEnvVar = run(["get", "LAYER_KEY"], { env: { KEYCLASP_PROJECT: "envapp", KEYCLASP_ENVIRONMENT: "envenv" } });
    expect(viaEnvVar.stdout.trim()).toBe("env-value");

    const viaFlag = run(["get", "LAYER_KEY", "--project", "flagapp", "--environment", "flagenv"], {
      env: { KEYCLASP_PROJECT: "envapp", KEYCLASP_ENVIRONMENT: "envenv" },
    });
    expect(viaFlag.stdout.trim()).toBe("flag-value");
  });

  it("run injects only the resolved scope's secrets and ignores other scopes", () => {
    run(["set", "SCOPED_SECRET", "--project", "runapp", "--environment", "prod"], { input: "run-scoped-value\n" });
    run(["set", "SCOPED_SECRET", "--project", "runapp", "--environment", "staging"], { input: "other-scope-value\n" });

    const result = run([
      "run",
      "--project",
      "runapp",
      "--environment",
      "prod",
      "--",
      process.execPath,
      "-e",
      "console.log(process.env.SCOPED_SECRET === 'run-scoped-value' ? 'ok' : 'missing')",
    ]);
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe("ok");
  });

  it("run recognizes global flags interleaved with its own flags before '--', leaving child args untouched", () => {
    run(["set", "ORDER_SECRET", "--project", "orderapp", "--environment", "prod"], { input: "order-value\n" });

    const result = run([
      "run",
      "--allow-unsafe",
      "--project",
      "orderapp",
      "--environment",
      "prod",
      "--",
      process.execPath,
      "-e",
      "console.log(process.env.ORDER_SECRET === 'order-value' ? 'ok' : 'missing')",
    ]);
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe("ok");
  });

  it("run preserves scope-like child flags in the separator-free form", () => {
    const result = run([
      "run",
      process.execPath,
      "-e",
      "console.log(JSON.stringify(process.argv.slice(1)))",
      "child",
      "-p",
      "3000",
      "--environment",
      "child-value",
    ]);
    expect(result.status).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual(["child", "-p", "3000", "--environment", "child-value"]);
  });

  it("run prints an informational note and still runs when the resolved scope has no secrets", () => {
    const result = run([
      "run",
      "--project",
      "brandnew",
      "--environment",
      "brandnew",
      "--",
      process.execPath,
      "-e",
      "console.log('ran-anyway')",
    ]);
    expect(result.status).toBe(0);
    expect(result.stderr).toContain('no secrets stored yet for project "brandnew" environment "brandnew"');
    expect(result.stdout.trim()).toBe("ran-anyway");
  });
});

describe("CLI bulk delete", () => {
  beforeEach(() => {
    run(["init"], { input: "\n" });
    run(["set", "BULK_ONE", "--project", "bulkapp", "--environment", "prod"], { input: "1\n" });
    run(["set", "BULK_TWO", "--project", "bulkapp", "--environment", "prod"], { input: "2\n" });
  });

  it("refuses a non-interactive bulk delete and leaves the data untouched", () => {
    const result = run(["delete", "--bulk", "--project", "bulkapp", "--environment", "prod"], { input: "" });
    expect(result.status).toBe(1);
    expect(result.stderr.toLowerCase()).toContain("interactive");

    expect(run(["get", "BULK_ONE", "--project", "bulkapp", "--environment", "prod"]).stdout.trim()).toBe("1");
    expect(run(["get", "BULK_TWO", "--project", "bulkapp", "--environment", "prod"]).stdout.trim()).toBe("2");
  });

  it("rejects a --bulk delete combined with a secret name as a usage error", () => {
    const result = run(["delete", "--bulk", "BULK_ONE", "--project", "bulkapp"], { input: "" });
    expect(result.status).toBe(1);
    expect(run(["get", "BULK_ONE", "--project", "bulkapp", "--environment", "prod"]).stdout.trim()).toBe("1");
  });

  it("rejects an ambiguous --bulk --environment without --project or --all-projects", () => {
    const result = run(["delete", "--bulk", "--environment", "prod"], { input: "" });
    expect(result.status).toBe(1);
  });

  it("single-secret delete is unaffected — no confirmation required", () => {
    const result = run(["delete", "BULK_ONE", "--project", "bulkapp", "--environment", "prod"]);
    expect(result.status).toBe(0);
    expect(run(["get", "BULK_ONE", "--project", "bulkapp", "--environment", "prod"]).status).toBe(1);
  });
});

describe("CLI rename", () => {
  beforeEach(() => {
    run(["init"], { input: "\n" });
  });

  it("renames a whole project, moving every environment", () => {
    run(["set", "ONE", "--project", "old-app", "--environment", "prod"], { input: "1\n" });
    run(["set", "TWO", "--project", "old-app", "--environment", "staging"], { input: "2\n" });

    const result = run(["rename", "--project", "old-app", "--to-project", "new-app"]);
    expect(result.status).toBe(0);

    expect(run(["get", "ONE", "--project", "new-app", "--environment", "prod"]).stdout.trim()).toBe("1");
    expect(run(["get", "TWO", "--project", "new-app", "--environment", "staging"]).stdout.trim()).toBe("2");
    expect(run(["get", "ONE", "--project", "old-app", "--environment", "prod"]).status).toBe(1);
  });

  it("renames one environment within one project", () => {
    run(["set", "ONE", "--project", "app", "--environment", "stagng"], { input: "1\n" });

    const result = run(["rename", "--project", "app", "--environment", "stagng", "--to-environment", "staging"]);
    expect(result.status).toBe(0);
    expect(run(["get", "ONE", "--project", "app", "--environment", "staging"]).stdout.trim()).toBe("1");
  });

  it("renames one environment across every project with --all-projects", () => {
    run(["set", "ONE", "--project", "app-a", "--environment", "stagng"], { input: "1\n" });
    run(["set", "TWO", "--project", "app-b", "--environment", "stagng"], { input: "2\n" });

    const result = run(["rename", "--all-projects", "--environment", "stagng", "--to-environment", "staging"]);
    expect(result.status).toBe(0);
    expect(run(["get", "ONE", "--project", "app-a", "--environment", "staging"]).stdout.trim()).toBe("1");
    expect(run(["get", "TWO", "--project", "app-b", "--environment", "staging"]).stdout.trim()).toBe("2");
  });

  it("renames an exact project/environment pair to a different pair", () => {
    run(["set", "ONE", "--project", "app", "--environment", "stagng"], { input: "1\n" });

    const result = run([
      "rename", "--project", "app", "--environment", "stagng",
      "--to-project", "app2", "--to-environment", "staging",
    ]);
    expect(result.status).toBe(0);
    expect(run(["get", "ONE", "--project", "app2", "--environment", "staging"]).stdout.trim()).toBe("1");
  });

  it("aborts entirely on a name collision and leaves both scopes unchanged", () => {
    run(["set", "SAME_NAME", "--project", "old-app", "--environment", "prod"], { input: "old-value\n" });
    run(["set", "SAME_NAME", "--project", "new-app", "--environment", "prod"], { input: "existing-value\n" });

    const result = run(["rename", "--project", "old-app", "--to-project", "new-app"]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("already exist");
    expect(result.stderr).toContain("SAME_NAME");

    expect(run(["get", "SAME_NAME", "--project", "old-app", "--environment", "prod"]).stdout.trim()).toBe("old-value");
    expect(run(["get", "SAME_NAME", "--project", "new-app", "--environment", "prod"]).stdout.trim()).toBe("existing-value");
  });
});

describe("legacy vault migration race safety", () => {
  it("two concurrent processes opening the same legacy vault both succeed with no duplicated rows", async () => {
    const raceTmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-race-"));
    const raceHome = path.join(raceTmpDir, ".keyclasp");
    const previousHome = process.env.KEYCLASP_HOME;

    try {
      process.env.KEYCLASP_HOME = raceHome;
      closeDb();
      clearKey();
      initializeVault("race-passphrase");
      const key = getKey();
      closeDb();

      const dbPath = path.join(raceHome, "vault.db");
      const raw = new Database(dbPath);
      try {
        raw.exec("DROP TABLE IF EXISTS secrets");
        raw.exec(`
          CREATE TABLE secrets (
            name TEXT PRIMARY KEY,
            encrypted_value BLOB NOT NULL,
            iv BLOB NOT NULL,
            auth_tag BLOB NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
          )
        `);
        const insert = raw.prepare("INSERT INTO secrets (name, encrypted_value, iv, auth_tag) VALUES (?, ?, ?, ?)");
        for (const name of ["RACE_ONE", "RACE_TWO", "RACE_THREE"]) {
          const { encrypted, iv, authTag } = encrypt(`value-${name}`, key);
          insert.run(name, encrypted, iv, authTag);
        }
      } finally {
        raw.close();
      }
      closeDb();
      clearKey();

      const [first, second] = await Promise.all([
        runAsync(["list", "--all"], { KEYCLASP_HOME: raceHome }),
        runAsync(["list", "--all"], { KEYCLASP_HOME: raceHome }),
      ]);

      expect(first.status).toBe(0);
      expect(second.status).toBe(0);

      const verifyDb = new Database(dbPath, { readonly: true });
      try {
        const columns = (verifyDb.pragma("table_info(secrets)") as { name: string }[]).map((r) => r.name);
        expect(columns).toEqual(expect.arrayContaining(["project", "environment", "name"]));
        const rows = verifyDb.prepare("SELECT project, environment, name FROM secrets ORDER BY name").all() as
          { project: string; environment: string; name: string }[];
        expect(rows).toEqual([
          { project: "default", environment: "default", name: "RACE_ONE" },
          { project: "default", environment: "default", name: "RACE_THREE" },
          { project: "default", environment: "default", name: "RACE_TWO" },
        ]);
      } finally {
        verifyDb.close();
      }
    } finally {
      closeDb();
      clearKey();
      if (previousHome === undefined) delete process.env.KEYCLASP_HOME;
      else process.env.KEYCLASP_HOME = previousHome;
      fs.rmSync(raceTmpDir, { recursive: true, force: true });
    }
  });
});
