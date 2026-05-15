import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov"],
      include: ["src/**"],
      exclude: ["src/index.ts"],
      thresholds: {
        lines: 90,
        branches: 80,
        functions: 90,
        statements: 85,
      },
    },
  },
});
