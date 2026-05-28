import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    env: {
      KEYBLIND_DEV: "true",
      KEYBLIND_PUBLIC_KEY: "MCowBQYDK2VwAyEAaxu7ncsxw3rW0Sycd9iIVu4prMKbsjN9hZghJYI2LoY=",
    },
  },
});
