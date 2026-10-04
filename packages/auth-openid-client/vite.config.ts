import { defineConfig } from "vite-plus";

import { pureAnnotations } from "../../scripts/library-build";

export default defineConfig({
  pack: {
    tsconfig: "tsconfig.build.json",
    entry: ["src/index.ts", "src/Connected.ts", "src/GitHub.ts"],
    dts: true,
    unbundle: true,
    outputOptions: { plugins: [pureAnnotations()] },
    sourcemap: true,
  },
  test: { cache: false, silent: "passed-only", include: ["test/**/*.test.ts"] },
});
