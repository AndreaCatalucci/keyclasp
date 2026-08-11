import { beforeAll, describe, expect, it } from "vitest";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const cliPath = path.join(process.cwd(), "dist", "cli.js");
const packageVersion = (JSON.parse(fs.readFileSync(path.join(process.cwd(), "package.json"), "utf8")) as { version: string }).version;

function runCliProcess(args: string[]) {
  return spawnSync(process.execPath, [cliPath, ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, KEYCLASP_HOME: path.join(process.cwd(), ".not-used-by-version-test") },
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function runCli(args: string[]): string {
  const result = runCliProcess(args);
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(result.stderr);
  return result.stdout.trim();
}

function runCliFailure(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const result = runCliProcess(args);
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

describe("CLI version output", () => {
  beforeAll(() => {
    execFileSync("npm", ["run", "build", "--silent"], {
      cwd: process.cwd(),
      stdio: ["ignore", "ignore", "pipe"],
    });
  });

  it("prints version from the built CLI without requiring a vault", () => {
    expect(runCli(["version"])).toMatch(new RegExp(`^${packageVersion.replaceAll(".", "\\.")}(?:-dev\\+git\\.[0-9a-f]+(?:\\.dirty)?)?$`));
  });

  it("supports version flags without requiring vault access", () => {
    const version = runCli(["version"]);
    expect(runCli(["--version"])).toBe(version);
    expect(runCli(["-v"])).toBe(version);
  });
});

describe("removed CLI surface", () => {
  it.each(["start", "unlock", "sandbox", "totp", "share", "sync", "alias", "backend", "doctor"])(
    "rejects the removed %s command normally",
    (command) => {
      const result = runCliFailure([command]);

      expect(result.status).toBe(1);
      expect(result.stderr).toContain(`Unknown command: ${command}`);
      expect(result.stderr).not.toContain("deprecated");
    },
  );

  it("lists only the minimal command surface in help", () => {
    const help = runCli(["help"]);

    expect(help).toContain("keyclasp init");
    expect(help).toContain("keyclasp set");
    expect(help).toContain("keyclasp get");
    expect(help).toContain("keyclasp list");
    expect(help).toContain("keyclasp delete");
    expect(help).toContain("keyclasp run");
    expect(help).toContain("keyclasp status");
    expect(help).not.toContain("keyclasp sandbox");
    expect(help).not.toContain("keyclasp totp");
    expect(help).not.toContain("keyclasp share");
    expect(help).toContain("--project");
    expect(help).toContain("--environment");
  });
});
