import { defineConfig } from "vite-plus";

import { pureAnnotations } from "../../scripts/library-build";

export default defineConfig({
  pack: {
    tsconfig: "tsconfig.build.json",
    entry: [
      "src/index.ts",
      "src/D1.ts",
      "src/Libsql.ts",
      "src/Mysql2.ts",
      "src/Pglite.ts",
      "src/Postgres.ts",
      "src/SqliteBun.ts",
      "src/SqliteDo.ts",
      "src/SqliteNode.ts",
      "src/SqliteWasm.ts",
    ],
    dts: true,
    unbundle: true,
    outputOptions: { plugins: [pureAnnotations()] },
    sourcemap: true,
  },
  test: { cache: false, silent: "passed-only", include: ["test/**/*.test.ts"] },
});
