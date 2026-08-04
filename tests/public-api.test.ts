import { describe, expect, it } from "vitest";
import * as keyclasp from "../src/index.js";

describe("public API", () => {
  it("keeps the minimal vault + run surface", () => {
    expect(keyclasp).toHaveProperty("initializeVault");
    expect(keyclasp).toHaveProperty("storeSecret");
    expect(keyclasp).toHaveProperty("resolveSecret");
    expect(keyclasp).toHaveProperty("listSecrets");
    expect(keyclasp).toHaveProperty("deleteSecret");
    expect(keyclasp).toHaveProperty("runCommandWithSecrets");
  });

  it("omits exports for removed features", () => {
    expect(keyclasp).not.toHaveProperty("createAlias");
    expect(keyclasp).not.toHaveProperty("storeTOTP");
    expect(keyclasp).not.toHaveProperty("createShareLink");
    expect(keyclasp).not.toHaveProperty("sandboxEnvFile");
    expect(keyclasp).not.toHaveProperty("setBackend");
    expect(keyclasp).not.toHaveProperty("runDoctor");
    expect(keyclasp).not.toHaveProperty("setProjectName");
    expect(keyclasp).not.toHaveProperty("getAuditLog");
  });
});
