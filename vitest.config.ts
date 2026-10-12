import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        // テストはローカル開発モード（Access 検証なし）で動かす。本番の fail-closed は access.test.ts で別途確認する
        bindings: { ENVIRONMENT: "development", PBKDF2_ITERATIONS: "1000", LAB_TTL_HOURS: "24" },
      },
    }),
  ],
  test: { include: ["test/**/*.test.ts"] },
});
