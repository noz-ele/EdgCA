import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.node.test.ts"],
    // PKCS#12 integration tests intentionally exercise the production KDF
    // costs, and a few cases build two PFX files in one test.
    testTimeout: 15_000
  }
});
