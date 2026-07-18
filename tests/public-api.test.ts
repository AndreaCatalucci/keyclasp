import { describe, expect, it } from "vitest";
import * as keyclasp from "../src/index.js";

describe("public API", () => {
  it("keeps the supported CLI-first library surface", () => {
    expect(keyclasp).toHaveProperty("initializeVault");
    expect(keyclasp).toHaveProperty("sandboxEnvFile");
    expect(keyclasp).toHaveProperty("runDoctor");
    expect(keyclasp).toHaveProperty("createShareLink");
  });

  it("omits removed server, setup, and authentication exports", () => {
    expect(keyclasp).not.toHaveProperty("createServer");
    expect(keyclasp).not.toHaveProperty("startServer");
    expect(keyclasp).not.toHaveProperty("setupAll");
    expect(keyclasp).not.toHaveProperty("setRequireSession");
    expect(keyclasp).not.toHaveProperty("setClientInfo");
  });
});
