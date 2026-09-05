import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const root = process.cwd();
const read = (relativePath: string) => fs.readFileSync(path.join(root, relativePath), "utf8");

describe("software workflow contracts", () => {
  it("runs source checks on pull requests without release qualification gates", () => {
    const source = read(".github/workflows/software-source.yml");

    expect(source).toContain("pull_request:");
    expect(source).toContain("workflow_call:");
    expect(source).not.toContain("pack-once:");
    expect(source).not.toContain("exact-tarball-tests:");
  });

  it("keeps package and native qualification in the manual release workflow", () => {
    const release = read(".github/workflows/software-beta.yml");

    expect(release).toContain("workflow_dispatch:");
    expect(release).not.toContain("pull_request:");
    expect(release).not.toContain("push:");
    expect(release).toContain("uses: ./.github/workflows/software-source.yml");
    expect(release).toContain("pack-once:");
    expect(release).toContain("exact-tarball-tests:");
    expect(release).toContain("musl-fails-closed:");
    expect(release).toContain("macos-x64-fails-closed:");
    expect(release).toContain("windows-fails-closed:");
  });
});
