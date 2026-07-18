import { describe, expect, it } from "vitest";
import { generateBash, generateFish, generateZsh } from "../src/completions.js";

describe("shell completions", () => {
  it.each([
    ["bash", generateBash],
    ["zsh", generateZsh],
    ["fish", generateFish],
  ])("omits removed commands and flags from %s output", (_shell, generate) => {
    const completions = generate();

    expect(completions).not.toMatch(/\bstart\b|\bunlock\b|--bio/);
    expect(completions).not.toContain("setup-");
    expect(completions).toContain("sandbox");
    expect(completions).toContain("run");
  });
});
