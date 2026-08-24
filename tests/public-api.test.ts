import { describe, expect, it } from "vitest";
import * as keyclasp from "../src/index.js";

describe("public API", () => {
  it("matches the complete reviewed runtime allowlist", () => {
    expect(Object.keys(keyclasp).sort()).toEqual([
      "checkUnsafeCommand",
      "evaluateBiometricAuthentication",
      "extractGlobalFlags",
      "getVaultLocation",
      "parseRunArgs",
      "readContext",
      "resolveContext",
      "validateScopeName",
    ]);
  });

  it("exposes metadata and validation helpers", () => {
    expect(keyclasp).toHaveProperty("validateScopeName");
    expect(keyclasp).toHaveProperty("parseRunArgs");
    expect(keyclasp).toHaveProperty("checkUnsafeCommand");
  });

  it("exposes read-only context resolution helpers", () => {
    expect(keyclasp).toHaveProperty("extractGlobalFlags");
    expect(keyclasp).toHaveProperty("resolveContext");
    expect(keyclasp).toHaveProperty("readContext");
  });
});
