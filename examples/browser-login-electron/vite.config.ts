import { defineConfig } from "vite-plus";

export default defineConfig({
  pack: {
    entry: ["src/main.ts", "src/preload.ts"],
    format: "cjs",
    platform: "node",
    target: "node24",
    outDir: "dist",
    dts: false,
    deps: {
      // tsdown <0.23 compatibility: resolve external dependency subpaths.
      // Remove to preserve subpath imports as written (the new default).
      // https://tsdown.dev/options/dependencies#deps-resolvedepsubpath
      resolveDepSubpath: true,
      alwaysBundle: [/^(?!electron$)/],
      neverBundle: ["electron"],
    },
  },
  base: "./",
  build: { outDir: "dist/renderer", target: "chrome152" },
});
