import { defineConfig } from "vitepress";

import tokyoNightLight from "./theme/tokyo-night-light.json" with { type: "json" };

export default defineConfig({
  title: "Yielded Auth",
  description: "Composable authentication, sessions, and identity workflows for Effect.",
  lang: "en-US",
  base: "/auth/",
  cleanUrls: true,
  sitemap: { hostname: "https://yielded.dev/auth/" },
  head: [["link", { rel: "icon", type: "image/svg+xml", href: "/auth/favicon.svg" }]],
  srcExclude: ["TOOLCHAIN.md"],
  markdown: {
    theme: { light: { ...tokyoNightLight, type: "light" }, dark: "tokyo-night" },
  },
  themeConfig: {
    siteTitle: "Yielded Auth",
    nav: [
      { text: "Guide", link: "/guide/getting-started", activeMatch: "/guide/" },
      { text: "Reference", link: "/reference/modules", activeMatch: "/reference/" },
    ],
    sidebar: [
      {
        text: "Start",
        items: [
          { text: "Getting started", link: "/guide/getting-started" },
          { text: "How it fits together", link: "/guide/authentication" },
        ],
      },
      {
        text: "Authentication",
        items: [
          { text: "Sessions", link: "/guide/sessions" },
          { text: "Passwords", link: "/guide/passwords" },
          { text: "Email codes & magic links", link: "/guide/codes" },
          { text: "Phone codes", link: "/guide/phone" },
          { text: "Passkeys", link: "/guide/passkeys" },
          { text: "Two-factor authentication", link: "/guide/totp" },
        ],
      },
      {
        text: "OAuth providers",
        items: [
          { text: "GitHub", link: "/guide/github" },
          { text: "Google", link: "/guide/google" },
          { text: "Other OAuth / OIDC", link: "/guide/oauth#other-providers" },
        ],
      },
      {
        text: "Integration",
        items: [
          { text: "OAuth setup", link: "/guide/oauth" },
          { text: "MCP authorization", link: "/guide/oauth#authorize-mcp-clients" },
          { text: "HTTP & client state", link: "/guide/http-and-client" },
          { text: "Adapters & persistence", link: "/reference/adapters" },
          { text: "Examples", link: "/guide/examples" },
        ],
      },
      {
        text: "Reference",
        items: [
          { text: "Public modules", link: "/reference/modules" },
          { text: "OAuth", link: "/reference/oauth" },
          { text: "iOS passkeys", link: "/reference/passkey-react-native" },
        ],
      },
    ],
    socialLinks: [{ icon: "github", link: "https://github.com/yielded-dev/auth" }],
    search: { provider: "local" },
    outline: { level: [2, 3], label: "On this page" },
    docFooter: { prev: "Previous", next: "Continue" },
    externalLinkIcon: true,
    editLink: { pattern: "https://github.com/yielded-dev/auth/edit/main/docs/:path" },
  },
});
