import { defineConfig } from "vite-plus";

export default defineConfig({
  pack: {
    tsconfig: "tsconfig.build.json",
    entry: [
      "src/index.ts",
      "src/Drizzle.ts",
      "src/DrizzleD1.ts",
      "src/DrizzleLibsql.ts",
      "src/DrizzleMysql2.ts",
      "src/DrizzlePglite.ts",
      "src/DrizzlePostgres.ts",
      "src/DrizzleSqliteBun.ts",
      "src/DrizzleSqliteDo.ts",
      "src/DrizzleSqliteNode.ts",
      "src/DrizzleSqliteWasm.ts",
    ],
    dts: true,
    unbundle: true,
    sourcemap: true,
  },
  test: { cache: false, silent: "passed-only", include: ["test/**/*.test.ts"] },
});
