import starlight from "@astrojs/starlight";
import yieldedTheme from "@yielded/starlight-theme";
import { defineConfig } from "astro/config";
import starlightLinksValidator from "starlight-links-validator";

export default defineConfig({
  site: "https://yielded.dev",
  base: "/auth",
  integrations: [
    starlight({
      title: "Yielded Auth",
      description: "Composable authentication, sessions, and identity workflows for Effect.",
      favicon: "/favicon.svg",
      plugins: [yieldedTheme({ library: "auth" }), starlightLinksValidator()],
      sidebar: [
        {
          label: "Start",
          items: [
            { label: "Getting started", slug: "guide/getting-started" },
            { label: "How it fits together", slug: "guide/authentication" },
          ],
        },
        {
          label: "Authentication",
          items: [
            { label: "Sessions", slug: "guide/sessions" },
            { label: "Passwords", slug: "guide/passwords" },
            { label: "Email codes & magic links", slug: "guide/codes" },
            { label: "Phone codes", slug: "guide/phone" },
            { label: "Passkeys", slug: "guide/passkeys" },
            { label: "Two-factor authentication", slug: "guide/totp" },
          ],
        },
        {
          label: "OAuth providers",
          items: [
            { label: "GitHub", slug: "guide/github" },
            { label: "Google", slug: "guide/google" },
            { label: "Other OAuth / OIDC", link: "/guide/oauth/#other-providers" },
          ],
        },
        {
          label: "Integration",
          items: [
            { label: "OAuth setup", slug: "guide/oauth" },
            { label: "MCP authorization", link: "/guide/oauth/#authorize-mcp-clients" },
            { label: "HTTP & client state", slug: "guide/http-and-client" },
            { label: "Adapters & persistence", slug: "reference/adapters" },
            { label: "Examples", slug: "guide/examples" },
          ],
        },
        {
          label: "Reference",
          items: [
            { label: "Public modules", slug: "reference/modules" },
            { label: "OAuth", slug: "reference/oauth" },
          ],
        },
      ],
    }),
  ],
});
