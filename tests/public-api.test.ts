import { describe, expect, it } from "vitest";
import * as keyclasp from "../src/index.js";

describe("public API", () => {
  it("keeps the minimal vault + run surface", () => {
    expect(keyclasp).toHaveProperty("initializeVault");
    expect(keyclasp).toHaveProperty("storeSecret");
    expect(keyclasp).toHaveProperty("resolveSecret");
    expect(keyclasp).toHaveProperty("unlockVault");
    expect(keyclasp).toHaveProperty("listSecrets");
    expect(keyclasp).toHaveProperty("deleteSecret");
    expect(keyclasp).toHaveProperty("runCommandWithSecrets");
  });

  it("exposes projects/environments scoping", () => {
    expect(keyclasp).toHaveProperty("validateScopeName");
    expect(keyclasp).toHaveProperty("isNewProjectEnvironment");
    expect(keyclasp).toHaveProperty("projects");
    expect(keyclasp).toHaveProperty("environments");
    expect(keyclasp).toHaveProperty("deleteProject");
    expect(keyclasp).toHaveProperty("deleteEnvironmentInProject");
    expect(keyclasp).toHaveProperty("deleteEnvironmentAcrossAllProjects");
    expect(keyclasp).toHaveProperty("renameProject");
    expect(keyclasp).toHaveProperty("renameEnvironmentInProject");
    expect(keyclasp).toHaveProperty("renameEnvironmentAcrossAllProjects");
    expect(keyclasp).toHaveProperty("renameScope");
  });

  it("exposes context resolution helpers", () => {
    expect(keyclasp).toHaveProperty("extractGlobalFlags");
    expect(keyclasp).toHaveProperty("resolveContext");
    expect(keyclasp).toHaveProperty("readContext");
    expect(keyclasp).toHaveProperty("writeContext");
    expect(keyclasp).toHaveProperty("clearContext");
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
