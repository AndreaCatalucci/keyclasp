import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { readAuthorizationState, setAuthorizationRule } from "../src/policy.js";
import { clearKey, closeDb } from "../src/vault.js";

describe("lock CLI contract", () => {
  let root: string;
  let home: string;

  function run(args: string[], input = "") {
    return spawnSync(process.execPath, [path.join(process.cwd(), "dist", "cli.js"), ...args], {
      encoding: "utf8",
      input,
      env: { ...process.env, KEYCLASP_HOME: home },
    });
  }

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-strict-cli-"));
    home = path.join(root, ".keyclasp");
    const initialized = run(["init"], "\n");
    expect(initialized.status, initialized.stderr).toBe(0);
  });

  afterEach(() => {
    closeDb();
    clearKey();
    fs.rmSync(root, { recursive: true, force: true });
  });

  function lockSecret(project: string, environment: string, secret: string): void {
    const previous = process.env.KEYCLASP_HOME;
    process.env.KEYCLASP_HOME = home;
    closeDb();
    clearKey();
    setAuthorizationRule({ project, environment, secret }, true);
    closeDb();
    clearKey();
    if (previous === undefined) delete process.env.KEYCLASP_HOME;
    else process.env.KEYCLASP_HOME = previous;
  }

  it("reports effective software mode and authorization state", () => {
    const result = run(["status", "--project", "app", "--environment", "prod"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Mode:       software-machine");
    expect(result.stdout).toContain("Authorization: unlocked (0 locked, 0 unlocked; future unlocked)");
  });

  it("reports metadata without unlocking or decrypting secret values", () => {
    expect(run(["set", "API_KEY", "--project", "app", "--environment", "prod"], "secret-value\n").status).toBe(0);
    lockSecret("app", "prod", "API_KEY");
    const db = new Database(path.join(home, "vault.db"));
    db.prepare("UPDATE secrets SET encrypted_value = ? WHERE project = ? AND environment = ? AND name = ?")
      .run(Buffer.from("corrupt"), "app", "prod", "API_KEY");
    db.close();

    const result = run(["status", "--project", "app", "--environment", "prod"]);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("Authorization: locked");
    expect(result.stdout).toContain("Values:     not inspected by status");
    expect(result.stdout).not.toContain("FAILED");
  });

  it("reports mixed effective state without revealing values", () => {
    expect(run(["set", "LOCKED_KEY", "--project", "app", "--environment", "prod"], "locked-value\n").status).toBe(0);
    expect(run(["set", "OPEN_KEY", "--project", "app", "--environment", "prod"], "open-value\n").status).toBe(0);
    const previous = process.env.KEYCLASP_HOME;
    process.env.KEYCLASP_HOME = home;
    closeDb();
    clearKey();
    setAuthorizationRule({ project: "app" }, true);
    setAuthorizationRule({ project: "app", environment: "prod", secret: "OPEN_KEY" }, false);
    closeDb();
    clearKey();
    if (previous === undefined) delete process.env.KEYCLASP_HOME;
    else process.env.KEYCLASP_HOME = previous;

    const result = run(["status", "--project", "app", "--environment", "prod"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Authorization: mixed (1 locked, 1 unlocked; future locked)");
    expect(result.stdout).not.toContain("locked-value");
    expect(result.stdout).not.toContain("open-value");
  });

  it("reports unlocked when every stored secret overrides a locked scope default", () => {
    expect(run(["set", "OPEN_KEY", "--project", "app", "--environment", "prod"], "open-value\n").status).toBe(0);
    const previous = process.env.KEYCLASP_HOME;
    process.env.KEYCLASP_HOME = home;
    closeDb();
    clearKey();
    setAuthorizationRule({ project: "app" }, true);
    setAuthorizationRule({ project: "app", environment: "prod", secret: "OPEN_KEY" }, false);
    closeDb();
    clearKey();
    if (previous === undefined) delete process.env.KEYCLASP_HOME;
    else process.env.KEYCLASP_HOME = previous;

    const result = run(["status", "--project", "app", "--environment", "prod"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Authorization: unlocked (0 locked, 1 unlocked; future locked)");
  });

  it("does not accept environment variables or persisted context instead of explicit lock scope flags", () => {
    expect(run(["use", "ambient", "prod"]).status).toBe(0);
    const result = spawnSync(process.execPath, [path.join(process.cwd(), "dist", "cli.js"), "lock"], {
      encoding: "utf8",
      env: {
        ...process.env,
        KEYCLASP_HOME: home,
        KEYCLASP_PROJECT: "environment-project",
        KEYCLASP_ENVIRONMENT: "environment-name",
      },
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Usage: keyclasp lock [--project NAME] [--environment NAME] [SECRET]");
    expect(fs.existsSync(path.join(home, "strict-policy.v1.json"))).toBe(false);
  });

  it("rejects a secret-specific rule unless both scope flags are explicit", () => {
    for (const args of [
      ["lock", "--project", "app", "API_KEY"],
      ["unlock", "--environment", "prod", "API_KEY"],
    ]) {
      const result = run(args);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain(`Usage: keyclasp ${args[0]} [--project NAME] [--environment NAME] [SECRET]`);
    }
  });

  it("removes the obsolete public strict command", () => {
    const result = run(["strict", "enable", "--project", "app", "--environment", "prod"]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Unknown command: strict");
  });

  it.each([
    {
      label: "project",
      sourceProject: "app",
      sourceEnvironment: "prod",
      args: ["rename", "--project", "app", "--to-project", "renamed"],
    },
    {
      label: "one environment",
      sourceProject: "app",
      sourceEnvironment: "prod",
      args: ["rename", "--project", "app", "--environment", "prod", "--to-environment", "renamed"],
    },
    {
      label: "environment across projects",
      sourceProject: "app",
      sourceEnvironment: "prod",
      args: ["rename", "--all-projects", "--environment", "prod", "--to-environment", "renamed"],
    },
    {
      label: "exact scope",
      sourceProject: "app",
      sourceEnvironment: "prod",
      args: ["rename", "--project", "app", "--environment", "prod", "--to-project", "renamed", "--to-environment", "renamed"],
    },
  ])("blocks $label rename when it would weaken a locked secret", ({ sourceProject, sourceEnvironment, args }) => {
    expect(run(["set", "API_KEY", "--project", sourceProject, "--environment", sourceEnvironment], "value\n").status).toBe(0);
    lockSecret(sourceProject, sourceEnvironment, "API_KEY");
    const result = run(args);
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/change the effective authorization state/i);
    expect(run(["list", "--project", sourceProject, "--environment", sourceEnvironment]).stdout).toContain("API_KEY");
    const previous = process.env.KEYCLASP_HOME;
    process.env.KEYCLASP_HOME = home;
    expect(readAuthorizationState(sourceProject, sourceEnvironment, "API_KEY")).toBe("locked");
    closeDb();
    clearKey();
    if (previous === undefined) delete process.env.KEYCLASP_HOME;
    else process.env.KEYCLASP_HOME = previous;
  });

  it("allows rename after a more-specific unlock overrides a broader lock", () => {
    expect(run(["set", "API_KEY", "--project", "app", "--environment", "prod"], "value\n").status).toBe(0);
    const previous = process.env.KEYCLASP_HOME;
    process.env.KEYCLASP_HOME = home;
    closeDb();
    clearKey();
    setAuthorizationRule({ project: "app" }, true);
    setAuthorizationRule({ project: "app", environment: "prod", secret: "API_KEY" }, false);
    closeDb();
    clearKey();
    if (previous === undefined) delete process.env.KEYCLASP_HOME;
    else process.env.KEYCLASP_HOME = previous;

    const result = run(["rename", "--project", "app", "--environment", "prod", "--to-project", "renamed", "--to-environment", "prod"]);
    expect(result.status, result.stderr).toBe(0);
    expect(run(["list", "--project", "renamed", "--environment", "prod"]).stdout).toContain("API_KEY");
  });

  it("allows a locked rename only when the destination remains locked", () => {
    expect(run(["set", "API_KEY", "--project", "app", "--environment", "prod"], "value\n").status).toBe(0);
    const previous = process.env.KEYCLASP_HOME;
    process.env.KEYCLASP_HOME = home;
    closeDb();
    clearKey();
    setAuthorizationRule({ project: "app" }, true);
    setAuthorizationRule({ project: "renamed" }, true);
    closeDb();
    clearKey();
    if (previous === undefined) delete process.env.KEYCLASP_HOME;
    else process.env.KEYCLASP_HOME = previous;

    const result = run(["rename", "--project", "app", "--to-project", "renamed"]);
    expect(result.status, result.stderr).toBe(0);
    process.env.KEYCLASP_HOME = home;
    closeDb();
    clearKey();
    expect(readAuthorizationState("renamed", "prod", "API_KEY")).toBe("locked");
    closeDb();
    clearKey();
    if (previous === undefined) delete process.env.KEYCLASP_HOME;
    else process.env.KEYCLASP_HOME = previous;
  });
});
