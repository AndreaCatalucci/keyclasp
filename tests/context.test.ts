import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  extractGlobalFlags,
  resolveContext,
  readContext,
  writeContext,
  clearContext,
} from "../src/context.js";
import { closeDb, clearKey } from "../src/vault.js";

describe("extractGlobalFlags", () => {
  it("scan-all: pulls --project/--environment from anywhere in the array", () => {
    expect(extractGlobalFlags(["NAME", "--project", "myapp", "--environment", "prod"])).toEqual({
      project: "myapp",
      environment: "prod",
      rest: ["NAME"],
    });
  });

  it("scan-all: works when flags appear before the positional", () => {
    expect(extractGlobalFlags(["--project", "myapp", "NAME"])).toEqual({
      project: "myapp",
      environment: undefined,
      rest: ["NAME"],
    });
  });

  it("scan-all: supports -p/-E short flags and --flag=value form", () => {
    expect(extractGlobalFlags(["-p", "myapp", "-E", "prod", "NAME"])).toEqual({
      project: "myapp",
      environment: "prod",
      rest: ["NAME"],
    });
    expect(extractGlobalFlags(["--project=myapp", "--environment=prod", "NAME"])).toEqual({
      project: "myapp",
      environment: "prod",
      rest: ["NAME"],
    });
  });

  it("scan-all: throws on a flag with no value", () => {
    expect(() => extractGlobalFlags(["--project"])).toThrow(/Missing value for --project/);
    expect(() => extractGlobalFlags(["--environment"])).toThrow(/Missing value for --environment/);
  });

  it("scan-until-terminator: stops recognizing flags at the first '--'", () => {
    const result = extractGlobalFlags(
      ["--project", "myapp", "--allow-unsafe", "--", "node", "-e", "1"],
      "scan-until-terminator",
    );
    expect(result.project).toBe("myapp");
    expect(result.rest).toEqual(["--allow-unsafe", "--", "node", "-e", "1"]);
  });

  it("scan-until-terminator: a token identical to a global flag after '--' is left untouched", () => {
    const result = extractGlobalFlags(
      ["--project", "myapp", "--", "node", "-e", "console.log(1)", "--project", "not-a-flag-here"],
      "scan-until-terminator",
    );
    expect(result.project).toBe("myapp");
    expect(result.rest).toEqual(["--", "node", "-e", "console.log(1)", "--project", "not-a-flag-here"]);
  });

  it("scan-until-terminator: recognizes global flags interleaved with run's own flags before '--'", () => {
    const result = extractGlobalFlags(
      ["--allow-unsafe", "--environment", "prod", "--env", "FOO:BAR", "--project", "myapp", "--", "npm", "test"],
      "scan-until-terminator",
    );
    expect(result.project).toBe("myapp");
    expect(result.environment).toBe("prod");
    expect(result.rest).toEqual(["--allow-unsafe", "--env", "FOO:BAR", "--", "npm", "test"]);
  });

  it("scan-until-terminator: with no '--' present, scans the whole array", () => {
    const result = extractGlobalFlags(["--project", "myapp", "node"], "scan-until-terminator");
    expect(result.project).toBe("myapp");
    expect(result.rest).toEqual(["node"]);
  });
});

describe("resolveContext precedence", () => {
  const previousProject = process.env.KEYCLASP_PROJECT;
  const previousEnvironment = process.env.KEYCLASP_ENVIRONMENT;
  const previousHome = process.env.KEYCLASP_HOME;
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-context-"));
    process.env.KEYCLASP_HOME = path.join(tmpDir, ".keyclasp");
    delete process.env.KEYCLASP_PROJECT;
    delete process.env.KEYCLASP_ENVIRONMENT;
    closeDb();
    clearKey();
  });

  afterEach(() => {
    closeDb();
    clearKey();
    if (previousProject === undefined) delete process.env.KEYCLASP_PROJECT;
    else process.env.KEYCLASP_PROJECT = previousProject;
    if (previousEnvironment === undefined) delete process.env.KEYCLASP_ENVIRONMENT;
    else process.env.KEYCLASP_ENVIRONMENT = previousEnvironment;
    if (previousHome === undefined) delete process.env.KEYCLASP_HOME;
    else process.env.KEYCLASP_HOME = previousHome;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("defaults to 'default'/'default' with nothing set", () => {
    expect(resolveContext()).toEqual({
      project: "default",
      projectSource: "default",
      environment: "default",
      environmentSource: "default",
    });
  });

  it("prefers an explicit flag over everything else", () => {
    process.env.KEYCLASP_PROJECT = "env-project";
    writeContext("file-project", "file-env");
    const resolved = resolveContext("flag-project", undefined);
    expect(resolved.project).toBe("flag-project");
    expect(resolved.projectSource).toBe("flag");
  });

  it("falls back to the env var when no flag is given", () => {
    process.env.KEYCLASP_ENVIRONMENT = "env-env";
    const resolved = resolveContext();
    expect(resolved.environment).toBe("env-env");
    expect(resolved.environmentSource).toBe("env");
  });

  it("falls back to context.json when no flag or env var is given", () => {
    writeContext("file-project", "file-env");
    const resolved = resolveContext();
    expect(resolved.project).toBe("file-project");
    expect(resolved.projectSource).toBe("context-file");
    expect(resolved.environment).toBe("file-env");
    expect(resolved.environmentSource).toBe("context-file");
  });

  it("resolves project and environment independently through the precedence ladder", () => {
    process.env.KEYCLASP_ENVIRONMENT = "env-env";
    writeContext("file-project", "file-env");
    const resolved = resolveContext("flag-project", undefined);
    expect(resolved).toEqual({
      project: "flag-project",
      projectSource: "flag",
      environment: "env-env",
      environmentSource: "env",
    });
  });
});

describe("readContext / writeContext / clearContext", () => {
  const previousHome = process.env.KEYCLASP_HOME;
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-context-file-"));
    process.env.KEYCLASP_HOME = path.join(tmpDir, ".keyclasp");
    closeDb();
    clearKey();
  });

  afterEach(() => {
    closeDb();
    clearKey();
    if (previousHome === undefined) delete process.env.KEYCLASP_HOME;
    else process.env.KEYCLASP_HOME = previousHome;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("returns null when no context file exists", () => {
    expect(readContext()).toBeNull();
  });

  it("round-trips a written context", () => {
    writeContext("myapp", "prod");
    expect(readContext()).toEqual({ project: "myapp", environment: "prod" });
  });

  it("clearContext removes the file and is safe to call when nothing exists", () => {
    writeContext("myapp", "prod");
    clearContext();
    expect(readContext()).toBeNull();
    expect(() => clearContext()).not.toThrow();
  });

  it("rejects invalid names on write without touching disk", () => {
    expect(() => writeContext("", "prod")).toThrow(/Invalid project name/);
    expect(readContext()).toBeNull();
  });

  it("treats a malformed context file as absent rather than throwing", () => {
    writeContext("myapp", "prod");
    const contextPath = path.join(process.env.KEYCLASP_HOME!, "context.json");
    fs.writeFileSync(contextPath, "{ not valid json");
    expect(readContext()).toBeNull();
  });

  it("treats a context file with non-string fields as absent", () => {
    const dir = process.env.KEYCLASP_HOME!;
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(dir, "context.json"), JSON.stringify({ project: 5, environment: null }));
    expect(readContext()).toBeNull();
  });
});
