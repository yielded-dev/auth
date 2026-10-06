import { defineConfig } from "vite-plus";

export default defineConfig({
  run: {
    tasks: {
      "example:oauth-lifecycle": { command: "bun src/oauth-lifecycle.ts", cache: false },
      start: { command: "vp build && bun src/server.ts", cache: false },
      "start:pg": { command: "PERSISTENCE_DIALECT=pg vp run start", cache: false },
    },
  },
});
