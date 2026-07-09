import { beforeAll, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const cliPath = path.join(process.cwd(), "dist", "cli.js");
const packageVersion = (JSON.parse(fs.readFileSync(path.join(process.cwd(), "package.json"), "utf8")) as { version: string }).version;

function runCli(args: string[]): string {
  return execFileSync(process.execPath, [cliPath, ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, KEYBLIND_HOME: path.join(process.cwd(), ".not-used-by-version-test") },
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
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

  it("supports version flags and --project without requiring vault access", () => {
    const version = runCli(["version"]);
    expect(runCli(["--version"])).toBe(version);
    expect(runCli(["-v"])).toBe(version);
    expect(runCli(["--project", "isolated", "--version"])).toBe(version);
  });
});
