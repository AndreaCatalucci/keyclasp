import { describe, expect, it } from "vitest";
import * as keyblind from "../src/index.js";

describe("public API", () => {
  it("keeps the supported CLI-first library surface", () => {
    expect(keyblind).toHaveProperty("initializeVault");
    expect(keyblind).toHaveProperty("sandboxEnvFile");
    expect(keyblind).toHaveProperty("runDoctor");
    expect(keyblind).toHaveProperty("createShareLink");
  });

  it("omits removed server, setup, and authentication exports", () => {
    expect(keyblind).not.toHaveProperty("createServer");
    expect(keyblind).not.toHaveProperty("startServer");
    expect(keyblind).not.toHaveProperty("setupAll");
    expect(keyblind).not.toHaveProperty("setRequireSession");
    expect(keyblind).not.toHaveProperty("setClientInfo");
  });
});
