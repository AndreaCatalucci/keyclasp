import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    env: {
      KEYBLIND_DEV: "true",
      KEYBLIND_PUBLIC_KEY: "MCowBQYDK2VwAyEApW1Wgu2bKF4KN3pafAbYC2203SRyf9qdlITawyj9jJk=",
    },
  },
});
