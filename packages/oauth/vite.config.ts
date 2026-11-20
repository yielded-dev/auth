import { defineConfig } from "vite-plus";

export default defineConfig({
  run: {
    tasks: {
      build: { command: "vp pack", cache: { untrackedEnv: ["TMPDIR"] } },
    },
  },
  pack: {
    tsconfig: "tsconfig.build.json",
    entry: [
      "src/index.ts",
      "src/Discovery.ts",
      "src/OAuth.ts",
      "src/OAuthError.ts",
      "src/Oidc.ts",
      "src/Pkce.ts",
    ],
    dts: true,
    unbundle: true,
    plugins: [
      {
        // Match core: retain actual ESM namespaces and avoid synthetic helper exports.
        name: "preserve-public-namespaces",
        resolveId: {
          order: "pre",
          handler(source, importer) {
            if (
              importer !== undefined &&
              /\/src\/index(?:\.d)?\.ts$/.test(importer) &&
              /^\.\/[A-Z]\w*(?:\.ts)?$/.test(source)
            ) {
              return { id: source.replace(/(?:\.ts)?$/, ".mjs"), external: true };
            }
          },
        },
      },
    ],
    sourcemap: true,
  },
  test: {
    cache: false,
    silent: "passed-only",
    include: ["test/**/*.test.ts"],
  },
});
