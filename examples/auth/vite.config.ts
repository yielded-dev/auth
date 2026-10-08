import { defineConfig } from "vite-plus";

export default defineConfig({
  build: {
    outDir: "dist",
    lib: { entry: "src/oauth-client.ts", formats: ["es"], fileName: "oauth-client" },
  },
  run: {
    tasks: {
      "example:oauth-proxy": {
        command: "bun src/oauth-proxy.ts",
        cache: false,
        dependsOn: ["build"],
      },
      "example:slack": {
        command: "bun src/slack-app.ts",
        cache: false,
        dependsOn: ["build"],
      },
      "example:github": {
        command: "bun src/github-app.ts",
        cache: false,
        dependsOn: ["build"],
      },
      "example:strava": {
        command: "bun src/strava-app.ts",
        cache: false,
        dependsOn: ["build"],
      },
      "example:strava-mcp": {
        command: "bun src/strava-mcp.ts",
        cache: false,
        dependsOn: ["build"],
      },
    },
  },
  test: {
    // Vitest v4 compatibility: preserve mock call history.
    // Remove after tests no longer rely on calls from setup or earlier tests.
    // https://viteplus.dev/guide/vitest-v5#remove-unneeded-compatibility-settings
    // https://vitest.dev/guide/migration/#clearmocks-is-enabled-by-default
    clearMocks: false,
    cache: false,
    silent: "passed-only",
    include: ["test/**/*.test.ts"],
  },
});
