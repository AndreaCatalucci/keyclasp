import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    env: {
      KEYBLIND_DEV: "true",
    },
  },
});
