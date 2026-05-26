import { describe, it, expect } from "vitest";
import { getBackend, setBackend, listAvailableBackends } from "../src/backends.js";

describe("backends", () => {
  it("returns local backend by default", () => {
    const backend = getBackend();
    expect(backend.name).toBe("local");
  });

  it("lists available backends", () => {
    const backends = listAvailableBackends();
    expect(backends.length).toBeGreaterThanOrEqual(4);
    const names = backends.map((b) => b.name);
    expect(names).toContain("local");
    expect(names).toContain("1password");
    expect(names).toContain("bitwarden");
    expect(names).toContain("env");
  });

  it("env backend is always available", () => {
    const backends = listAvailableBackends();
    const env = backends.find((b) => b.name === "env");
    expect(env?.available).toBe(true);
  });

  it("local backend has expected interface", () => {
    const backend = getBackend();
    expect(backend.name).toBe("local");
    expect(typeof backend.resolve).toBe("function");
    expect(typeof backend.list).toBe("function");
    expect(typeof backend.store).toBe("function");
    expect(typeof backend.isAvailable).toBe("function");
  });

  it("env backend resolves from process.env", () => {
    setBackend("env");
    const backend = getBackend();
    process.env.__KEYBLIND_TEST_VAR = "test-env-value";
    expect(backend.resolve("__KEYBLIND_TEST_VAR")).toBe("test-env-value");
    expect(backend.resolve("__NONEXISTENT_VAR_12345")).toBeNull();
    delete process.env.__KEYBLIND_TEST_VAR;
    // Reset to local
    setBackend("local");
  });

  it("setBackend throws for unknown backend", () => {
    expect(() => setBackend("nonexistent")).toThrow("Unknown backend");
  });
});
