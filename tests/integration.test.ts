import { beforeEach, describe, expect, it } from "vitest";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { initializeVault, getKey, closeDb, clearKey, encrypt, resolveSecret, storeSecret, unlockVault, writeLegacyV3KeyFileForTests } from "../src/vault.js";
import { createManagedBackup } from "../src/recovery.js";

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

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

function runLinuxPty(args: string[], input: string) {
  const command = [process.execPath, cliPath, ...args].map(shellQuote).join(" ");
  return spawnSync("/usr/bin/script", [
    "--quiet",
    "--return",
    "--flush",
    "--echo",
    "never",
    "--command",
    command,
    "/dev/null",
  ], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, KEYCLASP_HOME: vaultHome },
    input,
    stdio: ["pipe", "pipe", "pipe"],
  });
}

function runSecretCheck(
  name: string,
  expectedValue: string,
  scopeArgs: string[] = [],
  opts: { env?: NodeJS.ProcessEnv } = {},
) {
  const script = `process.stdout.write(process.env[${JSON.stringify(name)}] === ${JSON.stringify(expectedValue)} ? "ok" : "wrong")`;
  return run([
    "run",
    ...scopeArgs,
    "--env",
    name,
    "--",
    process.execPath,
    "-e",
    script,
  ], opts);
}

function runMissingSecret(name: string, scopeArgs: string[] = [], opts: { env?: NodeJS.ProcessEnv } = {}) {
  return run([
    "run",
    ...scopeArgs,
    "--env",
    name,
    "--",
    process.execPath,
    "-e",
    "process.exit(0)",
  ], opts);
}

function runAsync(args: string[], env: NodeJS.ProcessEnv, input?: string): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cliPath, ...args], {
      cwd: process.cwd(),
      env: { ...process.env, ...env },
      stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    if (input !== undefined) child.stdin.end(input);
    child.on("error", reject);
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

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

  it("initializes, stores, lists, injects, and deletes a secret", () => {
    expect(run(["init"], { input: "\n" }).status).toBe(0);

    const set = run(["set", "API_KEY"], { input: "sk-test-value-123\n" });
    expect(set.status).toBe(0);
    expect(set.stdout).toContain('Stored "API_KEY"');

    const injected = runSecretCheck("API_KEY", "sk-test-value-123");
    expect(injected.status).toBe(0);
    expect(injected.stdout.trim()).toBe("ok");

    const list = run(["list"]);
    expect(list.stdout).toContain("API_KEY");

    const del = run(["delete", "API_KEY"]);
    expect(del.status).toBe(0);
    expect(runMissingSecret("API_KEY").status).toBe(1);
  });

  it.runIf(process.platform === "darwin")("exits after completing a secret prompt on a real TTY", () => {
    const script = [
      "set timeout 5",
      "spawn env KEYCLASP_HOME=$env(KEYCLASP_TEST_HOME) $env(KEYCLASP_NODE) $env(KEYCLASP_CLI) init",
      'expect -exact "Enter vault passphrase (or empty for machine-only key): "',
      'send -- "tty-passphrase\\r"',
      "expect eof",
      "set result [wait]",
      "exit [lindex $result 3]",
    ].join("; ");
    const result = spawnSync("/usr/bin/expect", ["-c", script], {
      encoding: "utf8",
      env: {
        ...process.env,
        KEYCLASP_TEST_HOME: vaultHome,
        KEYCLASP_NODE: process.execPath,
        KEYCLASP_CLI: cliPath,
      },
    });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("Keyclasp vault created");
  });

  it("passes the vault status check for a healthy vault", () => {
    run(["init"], { input: "\n" });
    run(["set", "STATUS_KEY"], { input: "value\n" });
    const status = run(["status"]);
    expect(status.status, status.stderr).toBe(0);
    expect(status.stdout).toContain("Values:     not inspected by status");
  });

  it.runIf(process.platform === "linux")("fails a machine-only get at the CLI authorization gate before decryption", () => {
    expect(run(["init"], { input: "\n" }).status).toBe(0);
    expect(run(["set", "LOCKED_GET"], { input: "secret-value\n" }).status).toBe(0);
    const db = new Database(path.join(vaultHome, "vault.db"));
    db.prepare("UPDATE secrets SET encrypted_value = ? WHERE name = ?").run(Buffer.from("corrupt"), "LOCKED_GET");
    db.close();

    const result = run(["get", "LOCKED_GET"]);
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/machine-only vaults fail closed/i);
    expect(result.stderr).not.toMatch(/decrypt|authentication tag/i);
    expect(result.stdout).not.toContain("secret-value");
  });

  it.runIf(process.platform === "linux")("dispatches authenticated emergency restore before parsing a damaged live key", () => {
    const previous = process.env.KEYCLASP_HOME;
    process.env.KEYCLASP_HOME = vaultHome;
    closeDb();
    clearKey();
    initializeVault("emergency-passphrase");
    unlockVault("emergency-passphrase");
    storeSecret("app", "prod", "API_KEY", "restored-value", "interactive");
    const backupRoot = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-backup-"));
    const backup = path.join(backupRoot, "emergency-backup");
    createManagedBackup(backup);
    closeDb();
    clearKey();
    fs.writeFileSync(path.join(vaultHome, ".keyclasp.key"), "corrupt", { mode: 0o600 });

    const restored = runLinuxPty(["backup", "restore", backup], "emergency-passphrase\n");
    expect(restored.status, restored.stderr).toBe(0);
    expect(restored.stdout).toMatch(/backup restored/i);
    clearKey();
    unlockVault("emergency-passphrase");
    expect(resolveSecret("app", "prod", "API_KEY")).toBe("restored-value");
    closeDb();
    clearKey();
    fs.unlinkSync(path.join(vaultHome, ".keyclasp.key"));
    const restoredWithoutLiveKey = runLinuxPty(["backup", "restore", backup], "emergency-passphrase\n");
    expect(restoredWithoutLiveKey.status, restoredWithoutLiveKey.stderr).toBe(0);
    expect(restoredWithoutLiveKey.stdout).toMatch(/backup restored/i);
    if (previous === undefined) delete process.env.KEYCLASP_HOME;
    else process.env.KEYCLASP_HOME = previous;
  });

  it("keeps one authenticated record identity across concurrent first writes", async () => {
    expect(run(["init"], { input: "\n" }).status).toBe(0);
    const [first, second] = await Promise.all([
      runAsync(["set", "RACE_KEY", "--project", "app", "--environment", "prod"], { KEYCLASP_HOME: vaultHome }, "first-value\n"),
      runAsync(["set", "RACE_KEY", "--project", "app", "--environment", "prod"], { KEYCLASP_HOME: vaultHome }, "second-value\n"),
    ]);
    expect(first.status).toBe(0);
    expect(second.status).toBe(0);

    const previous = process.env.KEYCLASP_HOME;
    process.env.KEYCLASP_HOME = vaultHome;
    closeDb();
    clearKey();
    const value = resolveSecret("app", "prod", "RACE_KEY");
    expect(["first-value", "second-value"]).toContain(value);
    closeDb();
    clearKey();
    if (previous === undefined) delete process.env.KEYCLASP_HOME;
    else process.env.KEYCLASP_HOME = previous;
  });

  it("serializes concurrent initialization so exactly one process creates the vault", async () => {
    const [first, second] = await Promise.all([
      runAsync(["init"], { KEYCLASP_HOME: vaultHome }, "\n"),
      runAsync(["init"], { KEYCLASP_HOME: vaultHome }, "\n"),
    ]);
    expect([first.status, second.status].sort()).toEqual([0, 1]);
    expect(`${first.stderr}${second.stderr}`).toMatch(/already initialized|already in progress/i);
    expect(run(["status"]).status).toBe(0);
  });

  it("blocks on the live initialization owner and recovers when its advisory lock is released", async () => {
    fs.mkdirSync(vaultHome, { recursive: true, mode: 0o700 });
    const lockPath = path.join(vaultHome, ".initialize.db");
    const owner = new Database(lockPath);
    fs.chmodSync(lockPath, 0o600);
    owner.exec("BEGIN EXCLUSIVE");
    try {
      const blocked = await runAsync(["init"], { KEYCLASP_HOME: vaultHome }, "\n");
      expect(blocked.status).toBe(1);
      expect(blocked.stderr).toMatch(/initialization is already in progress/i);
      expect(fs.existsSync(path.join(vaultHome, ".keyclasp.key"))).toBe(false);
    } finally {
      owner.close();
    }

    expect(run(["init"], { input: "\n" }).status).toBe(0);
    expect(run(["status"]).status).toBe(0);
  });
});

describe("CLI dual-key vault keeps machine-class records unattended across processes", () => {
  beforeEach(() => {
    expect(run(["init"], { input: "wrap-passphrase\n" }).status).toBe(0);
    const previous = process.env.KEYCLASP_HOME;
    process.env.KEYCLASP_HOME = vaultHome;
    closeDb();
    clearKey();
    unlockVault("wrap-passphrase");
    storeSecret("default", "default", "LOCKED_RUN_KEY", "seeded-value");
    storeSecret("default", "default", "INTERACTIVE_RUN_KEY", "interactive-value", "interactive");
    closeDb();
    clearKey();
    if (previous === undefined) delete process.env.KEYCLASP_HOME;
    else process.env.KEYCLASP_HOME = previous;
  });

  it("prints dual-key metadata without decrypting values", () => {
    const status = run(["status"]);
    expect(status.status).toBe(0);
    expect(status.stdout).toContain("software-dual-key");
    expect(status.stdout).toContain("Authorization: unlocked");
    expect(status.stdout).not.toContain("FAILED");
  });

  it("allows a piped machine-class set without unlocking the interactive key", () => {
    const set = run(["set", "API_KEY"], { input: "sk-must-not-be-stored\n" });
    expect(set.status, set.stderr).toBe(0);
    const list = run(["list"]);
    expect(list.status).toBe(0);
    expect(list.stdout).toContain("API_KEY");
  });

  it("refuses non-TTY run --env without spawning the child", () => {
    const sentinel = path.join(vaultHome, "ran");
    const result = run([
      "run",
      "--env",
      "INTERACTIVE_RUN_KEY",
      "--",
      process.execPath,
      "-e",
      `require("node:fs").writeFileSync(${JSON.stringify(sentinel)}, "ran")`,
    ]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Keyclasp vault is locked.");
    expect(result.stderr).not.toContain("not found");
    expect(fs.existsSync(sentinel)).toBe(false);
  });

  it("allows unattended named machine-class run even with the unsafe override", () => {
    const sentinel = path.join(vaultHome, "unsafe-ran");
    const result = run([
      "run",
      "--allow-unsafe",
      "--env",
      "LOCKED_RUN_KEY",
      "--",
      process.execPath,
      "-e",
      `require("node:fs").writeFileSync(${JSON.stringify(sentinel)}, "ran")`,
    ]);
    expect(result.status, result.stderr).toBe(0);
    expect(fs.existsSync(sentinel)).toBe(true);
  });
});

describe("CLI run: secret injection stays out of the agent's view", () => {
  beforeEach(() => {
    run(["init"], { input: "\n" });
    run(["set", "INJECTED_SECRET"], { input: "sk-super-secret-value\n" });
  });

  it("injects the stored secret into the child process environment", () => {
    const result = run([
      "run",
      "--env",
      "INJECTED_SECRET",
      "--",
      process.execPath,
      "-e",
      "console.log(process.env.INJECTED_SECRET === 'sk-super-secret-value' ? 'ok' : 'missing')",
    ]);
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe("ok");
  });

  it("never prints the secret value to the parent's own stdout for the run command itself", () => {
    const result = run(["run", "--env", "INJECTED_SECRET", "--", "node", "-e", "0"]);
    expect(result.stdout).not.toContain("sk-super-secret-value");
    expect(result.stderr).not.toContain("sk-super-secret-value");
  });

  it("redacts and blocks a child command that leaks the secret to stdout", () => {
    const result = run([
      "run",
      "--env",
      "INJECTED_SECRET",
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
    const result = run(["run", "--env", "INJECTED_SECRET", "--", "env"]);
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
    const injected = runSecretCheck("PLAIN_KEY", "plain-value");
    expect(injected.stdout.trim()).toBe("ok");

    const scoped = runSecretCheck("PLAIN_KEY", "plain-value", ["--project", "default", "--environment", "default"]);
    expect(scoped.stdout.trim()).toBe("ok");
  });

  it("round-trips a secret through explicit --project/--environment flags", () => {
    const set = run(["set", "DB_URL", "--project", "myapp", "--environment", "prod"], { input: "postgres://prod\n" });
    expect(set.status).toBe(0);
    expect(set.stdout).toContain("myapp/prod");

    const injected = runSecretCheck("DB_URL", "postgres://prod", ["--project", "myapp", "--environment", "prod"]);
    expect(injected.status).toBe(0);
    expect(injected.stdout.trim()).toBe("ok");

    // Same name, different scope, is a distinct secret.
    const missing = runMissingSecret("DB_URL", ["--project", "myapp", "--environment", "staging"]);
    expect(missing.status).toBe(1);
    expect(missing.stderr).toContain('Secret "DB_URL" not found');
  });

  it("supports -p/-E short flags and flags appearing after the name", () => {
    run(["set", "SHORT_FLAG_KEY", "-p", "shortapp", "-E", "prod"], { input: "value\n" });
    const injected = runSecretCheck("SHORT_FLAG_KEY", "value", ["-p", "shortapp", "-E", "prod"]);
    expect(injected.stdout.trim()).toBe("ok");
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

    const injected = runSecretCheck("CONTEXT_KEY", "ctx-value");
    expect(injected.stdout.trim()).toBe("ok");

    const status = run(["status"]);
    expect(status.stdout).toContain("ctxapp/ctxenv");
    expect(status.stdout).toContain("context-file");

    const clear = run(["use", "--clear"]);
    expect(clear.status).toBe(0);
    const afterClear = runMissingSecret("CONTEXT_KEY");
    expect(afterClear.status).toBe(1);
  });

  it("an env var overrides the persisted context, and an explicit flag overrides both", () => {
    run(["set", "LAYER_KEY", "--project", "flagapp", "--environment", "flagenv"], { input: "flag-value\n" });
    run(["set", "LAYER_KEY", "--project", "envapp", "--environment", "envenv"], { input: "env-value\n" });
    run(["set", "LAYER_KEY", "--project", "fileapp", "--environment", "fileenv"], { input: "file-value\n" });
    run(["use", "fileapp", "fileenv"]);

    const viaContextFile = runSecretCheck("LAYER_KEY", "file-value");
    expect(viaContextFile.stdout.trim()).toBe("ok");

    const viaEnvVar = runSecretCheck("LAYER_KEY", "env-value", [], { env: { KEYCLASP_PROJECT: "envapp", KEYCLASP_ENVIRONMENT: "envenv" } });
    expect(viaEnvVar.stdout.trim()).toBe("ok");

    const viaFlag = runSecretCheck("LAYER_KEY", "flag-value", ["--project", "flagapp", "--environment", "flagenv"], {
      env: { KEYCLASP_PROJECT: "envapp", KEYCLASP_ENVIRONMENT: "envenv" },
    });
    expect(viaFlag.stdout.trim()).toBe("ok");
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
      "--env",
      "SCOPED_SECRET",
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
      "--env",
      "ORDER_SECRET",
      "--",
      process.execPath,
      "-e",
      "console.log(process.env.ORDER_SECRET === 'order-value' ? 'ok' : 'missing')",
    ]);
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe("ok");
  });

  it("run preserves scope-like child flags in the separator-free form", () => {
    run(["set", "ORDER_SECRET", "--project", "orderapp", "--environment", "prod"], { input: "order-value\n" });
    const result = run([
      "run",
      "--project",
      "orderapp",
      "--environment",
      "prod",
      "--env",
      "ORDER_SECRET",
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

  it.skipIf(process.platform === "darwin")("fails closed for a non-interactive whole-scope request even when the scope is empty", () => {
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
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('no secrets stored yet for project "brandnew" environment "brandnew"');
    expect(result.stderr).toMatch(/passphrase|Touch ID|Biometric/i);
    expect(result.stdout.trim()).toBe("");
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

    expect(runSecretCheck("BULK_ONE", "1", ["--project", "bulkapp", "--environment", "prod"]).stdout.trim()).toBe("ok");
    expect(runSecretCheck("BULK_TWO", "2", ["--project", "bulkapp", "--environment", "prod"]).stdout.trim()).toBe("ok");
  });

  it("rejects a --bulk delete combined with a secret name as a usage error", () => {
    const result = run(["delete", "--bulk", "BULK_ONE", "--project", "bulkapp"], { input: "" });
    expect(result.status).toBe(1);
    expect(runSecretCheck("BULK_ONE", "1", ["--project", "bulkapp", "--environment", "prod"]).stdout.trim()).toBe("ok");
  });

  it("rejects an ambiguous --bulk --environment without --project or --all-projects", () => {
    const result = run(["delete", "--bulk", "--environment", "prod"], { input: "" });
    expect(result.status).toBe(1);
  });

  it("single-secret delete is unaffected, no confirmation required", () => {
    const result = run(["delete", "BULK_ONE", "--project", "bulkapp", "--environment", "prod"]);
    expect(result.status).toBe(0);
    expect(runMissingSecret("BULK_ONE", ["--project", "bulkapp", "--environment", "prod"]).status).toBe(1);
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

    expect(runSecretCheck("ONE", "1", ["--project", "new-app", "--environment", "prod"]).stdout.trim()).toBe("ok");
    expect(runSecretCheck("TWO", "2", ["--project", "new-app", "--environment", "staging"]).stdout.trim()).toBe("ok");
    expect(runMissingSecret("ONE", ["--project", "old-app", "--environment", "prod"]).status).toBe(1);
  });

  it("renames one environment within one project", () => {
    run(["set", "ONE", "--project", "app", "--environment", "stagng"], { input: "1\n" });

    const result = run(["rename", "--project", "app", "--environment", "stagng", "--to-environment", "staging"]);
    expect(result.status).toBe(0);
    expect(runSecretCheck("ONE", "1", ["--project", "app", "--environment", "staging"]).stdout.trim()).toBe("ok");
  });

  it("renames one environment across every project with --all-projects", () => {
    run(["set", "ONE", "--project", "app-a", "--environment", "stagng"], { input: "1\n" });
    run(["set", "TWO", "--project", "app-b", "--environment", "stagng"], { input: "2\n" });

    const result = run(["rename", "--all-projects", "--environment", "stagng", "--to-environment", "staging"]);
    expect(result.status).toBe(0);
    expect(runSecretCheck("ONE", "1", ["--project", "app-a", "--environment", "staging"]).stdout.trim()).toBe("ok");
    expect(runSecretCheck("TWO", "2", ["--project", "app-b", "--environment", "staging"]).stdout.trim()).toBe("ok");
  });

  it("renames an exact project/environment pair to a different pair", () => {
    run(["set", "ONE", "--project", "app", "--environment", "stagng"], { input: "1\n" });

    const result = run([
      "rename", "--project", "app", "--environment", "stagng",
      "--to-project", "app2", "--to-environment", "staging",
    ]);
    expect(result.status).toBe(0);
    expect(runSecretCheck("ONE", "1", ["--project", "app2", "--environment", "staging"]).stdout.trim()).toBe("ok");
  });

  it("aborts entirely on a name collision and leaves both scopes unchanged", () => {
    run(["set", "SAME_NAME", "--project", "old-app", "--environment", "prod"], { input: "old-value\n" });
    run(["set", "SAME_NAME", "--project", "new-app", "--environment", "prod"], { input: "existing-value\n" });

    const result = run(["rename", "--project", "old-app", "--to-project", "new-app"]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("already exist");
    expect(result.stderr).toContain("SAME_NAME");

    expect(runSecretCheck("SAME_NAME", "old-value", ["--project", "old-app", "--environment", "prod"]).stdout.trim()).toBe("ok");
    expect(runSecretCheck("SAME_NAME", "existing-value", ["--project", "new-app", "--environment", "prod"]).stdout.trim()).toBe("ok");
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
      initializeVault("");
      const key = getKey();
      writeLegacyV3KeyFileForTests(key, "");
      closeDb();

      const dbPath = path.join(raceHome, "vault.db");
      const raw = new Database(dbPath);
      try {
        raw.exec("DROP TABLE IF EXISTS secrets");
        raw.exec("DROP TABLE IF EXISTS vault_metadata");
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
        runAsync(["run", "--env", "RACE_ONE", "--", process.execPath, "-e", "process.exit(0)"], { KEYCLASP_HOME: raceHome }),
        runAsync(["run", "--env", "RACE_TWO", "--", process.execPath, "-e", "process.exit(0)"], { KEYCLASP_HOME: raceHome }),
      ]);

      expect(first.status, first.stderr).toBe(0);
      expect(second.status, second.stderr).toBe(0);

      const verifyDb = new Database(dbPath, { readonly: true });
      try {
        const columns = (verifyDb.pragma("table_info(secrets)") as { name: string }[]).map((r) => r.name);
        expect(columns).toEqual(expect.arrayContaining(["project", "environment", "name", "record_id", "record_kind"]));
        expect(verifyDb.prepare("SELECT format_version FROM vault_metadata WHERE singleton = 1").pluck().get()).toBe(3);
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
