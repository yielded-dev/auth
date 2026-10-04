import { defineConfig } from "vite-plus";

import { pureAnnotations } from "../../scripts/library-build";

export default defineConfig({
  pack: {
    tsconfig: "tsconfig.build.json",
    entry: ["src/index.ts", "src/BrowserLogin.ts"],
    dts: true,
    unbundle: true,
    sourcemap: true,
    outputOptions: { plugins: [pureAnnotations()] },
  },
});
