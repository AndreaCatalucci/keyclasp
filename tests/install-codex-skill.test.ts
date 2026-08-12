import { execFile, execFileSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

const installer = resolve("scripts/install-codex-skill.sh");

describe("Codex skill installer", () => {
  it("replaces an existing installation without leaving stale files", () => {
    const codexHome = mkdtempSync(join(tmpdir(), "keyclasp-codex-home-"));
    const installedSkill = join(codexHome, "skills", "keyclasp-agent");

    execFileSync(installer, { env: { ...process.env, CODEX_HOME: codexHome } });
    writeFileSync(join(installedSkill, "obsolete.md"), "stale");
    execFileSync(installer, { env: { ...process.env, CODEX_HOME: codexHome } });

    expect(() => readFileSync(join(installedSkill, "obsolete.md"))).toThrow();
    expect(readFileSync(join(installedSkill, "SKILL.md"), "utf8")).toBe(
      readFileSync(resolve("skills/keyclasp-agent/SKILL.md"), "utf8"),
    );
  });

  it("serializes concurrent installations", async () => {
    const codexHome = mkdtempSync(join(tmpdir(), "keyclasp-codex-home-"));
    const env = { ...process.env, CODEX_HOME: codexHome };

    await Promise.all(
      Array.from(
        { length: 8 },
        () =>
          new Promise<void>((resolvePromise, reject) => {
            execFile(installer, { env }, (error) =>
              error ? reject(error) : resolvePromise(),
            );
          }),
      ),
    );

    const installedSkill = join(codexHome, "skills", "keyclasp-agent");
    expect(existsSync(join(installedSkill, "next"))).toBe(false);
    expect(readFileSync(join(installedSkill, "SKILL.md"), "utf8")).toBe(
      readFileSync(resolve("skills/keyclasp-agent/SKILL.md"), "utf8"),
    );
  });

  it("releases the lock when staging fails", () => {
    const codexHome = mkdtempSync(join(tmpdir(), "keyclasp-codex-home-"));
    const fakeBin = mkdtempSync(join(tmpdir(), "keyclasp-fake-bin-"));
    const fakeMktemp = join(fakeBin, "mktemp");
    mkdirSync(join(codexHome, "skills"));
    writeFileSync(fakeMktemp, "#!/bin/sh\nexit 1\n");
    chmodSync(fakeMktemp, 0o755);

    expect(() =>
      execFileSync(installer, {
        env: {
          ...process.env,
          CODEX_HOME: codexHome,
          PATH: `${fakeBin}:${process.env.PATH}`,
        },
      }),
    ).toThrow();

    expect(
      existsSync(join(codexHome, "skills", ".keyclasp-agent.install.lock")),
    ).toBe(false);
    expect(() =>
      execFileSync(installer, { env: { ...process.env, CODEX_HOME: codexHome } }),
    ).not.toThrow();
  });
});
