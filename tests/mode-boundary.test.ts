import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const sourceRoot = path.join(process.cwd(), "src");

function sourceFiles(directory: string): string[] {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const candidate = path.join(directory, entry.name);
    if (entry.isDirectory()) return sourceFiles(candidate);
    return entry.isFile() && entry.name.endsWith(".ts") ? [candidate] : [];
  });
}

function relativeImports(file: string): string[] {
  const source = fs.readFileSync(file, "utf8");
  return relativeModuleReferences(source, path.dirname(file));
}

function relativeModuleReferences(source: string, baseDirectory: string): string[] {
  return [...source.matchAll(/["'`]((?:\.\.?\/)[^"'`]+)["'`]/g)].map((match) =>
    path.resolve(baseDirectory, match[1].replace(/\.js$/, ".ts")),
  );
}

function hasDynamicModuleLoading(source: string): boolean {
  const call = /\b(?:import|require)(?:\s|\/\*[\s\S]*?\*\/|\/\/[^\n]*\n)*\(/;
  return call.test(source) || source.includes("createRequire");
}

function hasEncodedModuleReference(source: string): boolean {
  if (/%[0-9a-f]{2}/i.test(source) || /\\(?:[/.]|\r?\n|x[0-9a-f]{2}|u(?:\{[0-9a-f]+\}|[0-9a-f]{4})|[0-7]{1,3})/i.test(source)) {
    return true;
  }
  return [...source.matchAll(/\\([A-Za-z])/g)].some((match) =>
    !"bfnrtvux".includes(match[1].toLowerCase()),
  );
}

describe("mode import boundaries", () => {
  it("keeps the shared runtime contract independent of mode implementations", () => {
    expect(relativeImports(path.join(sourceRoot, "runtime.ts"))).toEqual([]);
  });

  it("keeps software and hardware implementations independent", () => {
    const softwareRoot = path.join(sourceRoot, "software");
    const hardwareRoot = path.join(sourceRoot, "hardware");

    for (const file of sourceFiles(softwareRoot)) {
      const source = fs.readFileSync(file, "utf8");
      expect(hasDynamicModuleLoading(source)).toBe(false);
      expect(hasEncodedModuleReference(source)).toBe(false);
      expect(relativeImports(file).some((candidate) => candidate.startsWith(hardwareRoot))).toBe(false);
    }

    const sharedRuntime = path.join(sourceRoot, "runtime.ts");
    const nativeStatusBinary = path.join(
      process.cwd(),
      "native/keyclasp-core/dist/keyclasp-core-spike",
    );
    for (const file of sourceFiles(hardwareRoot)) {
      const source = fs.readFileSync(file, "utf8");
      expect(hasDynamicModuleLoading(source)).toBe(false);
      expect(hasEncodedModuleReference(source)).toBe(false);
      for (const imported of relativeImports(file)) {
        expect(
          imported === sharedRuntime ||
            imported === nativeStatusBinary ||
            imported.startsWith(`${hardwareRoot}${path.sep}`),
        ).toBe(true);
      }
    }
  });

  it.each([
    'import("../vault.js")',
    'import(/* comment */ "../vault.js")',
    'import(`../vault.js`)',
    'import(pathToModule, { with: { type: "json" } })',
    'require("../vault.js")',
    'createRequire(import.meta.url)',
  ])("rejects dynamic hardware module loading: %s", (source) => {
    expect(hasDynamicModuleLoading(source)).toBe(true);
  });

  it("finds a side-effect import even when a comment replaces whitespace", () => {
    const hardwareRoot = path.join(sourceRoot, "hardware");
    expect(relativeModuleReferences(
      'import/* boundary bypass */"../vault.js";',
      hardwareRoot,
    )).toContain(path.join(sourceRoot, "vault.ts"));
  });

  it.each([
    'import "..\\x2fsoftware/runtime.js"',
    'import "..\\u002fsoftware/runtime.js"',
    'import "\\u{2e}./software/runtime.js"',
    'import "..\\/software/runtime.js"',
    'import "..\\\n/software/runtime.js"',
  ])("rejects encoded relative module paths: %s", (source) => {
    expect(hasEncodedModuleReference(source)).toBe(true);
  });

  it("rejects encoded and computed software imports", () => {
    expect(hasEncodedModuleReference('import "../h\\u0061rdware/status.js"')).toBe(true);
    expect(hasEncodedModuleReference('import "../hard\\ware/status.js"')).toBe(true);
    expect(hasEncodedModuleReference('import "../%68ardware/status.js"')).toBe(true);
    expect(hasDynamicModuleLoading('import("../" + "hardware/status.js")')).toBe(true);
  });
});
