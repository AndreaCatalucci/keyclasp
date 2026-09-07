import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Vault tests perform durable disk writes, key derivation, and child-process runs.
    // Limit competing workers and budget the whole flow, not one CLI invocation.
    maxWorkers: 2,
    testTimeout: 30_000,
    include: ["tests/**/*.test.ts"],
    exclude: ["node_modules/**", "dist/**", ".worktrees/**"],
    env: {
      KEYCLASP_DEV: "true",
    },
  },
});
