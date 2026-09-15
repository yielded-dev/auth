import { defineConfig } from "vite-plus";

export default defineConfig({
  run: {
    tasks: {
      start: { command: "vp build && bun src/server.ts", cache: false },
    },
  },
});
