import { defineConfig } from "vite-plus";

export default defineConfig({
  build: { rolldownOptions: { input: ["index.html", "oauth-settings.html"] } },
  run: {
    tasks: {
      "example:oauth-lifecycle": { command: "bun src/oauth-lifecycle.ts", cache: false },
      "start:oauth": { command: "vp build && bun src/oauth-settings-server.ts", cache: false },
      start: { command: "vp build && bun src/server.ts", cache: false },
      "start:pg": { command: "PERSISTENCE_DIALECT=pg vp run start", cache: false },
    },
  },
});
