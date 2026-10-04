interface BundleFixture {
  readonly name: string;
  readonly requires: ReadonlyArray<string>;
  readonly source?: string;
  readonly server?: boolean;
}

// Reuse the published-package consumers for core. Adapter probes select one
// public operation so reports expose unrelated factory retention.
export const bundleFixtures: ReadonlyArray<BundleFixture> = [
  { name: "identity", requires: ["@yielded/auth/Identity"] },
  { name: "identity-root", requires: ["@yielded/auth"] },
  {
    name: "contracts",
    requires: [
      "@yielded/auth/AuthContract",
      "@yielded/auth/PasskeyContract",
      "@yielded/auth/SessionContract",
      "@yielded/auth/TotpContract",
    ],
  },
  { name: "contracts-root", requires: ["@yielded/auth"] },
  { name: "atom", requires: ["@yielded/auth/Atom", "@yielded/auth/Client"] },
  { name: "atom-root", requires: ["@yielded/auth"] },
  {
    name: "server",
    requires: [
      "@yielded/auth/Auth",
      "@yielded/auth/AuthContract",
      "@yielded/auth/Http",
      "@yielded/auth/Password",
      "@yielded/auth/Sessions",
    ],
  },
  { name: "server-root", requires: ["@yielded/auth", "@yielded/auth/AuthContract"] },
  { name: "lazy", requires: ["@yielded/auth/AuthContract", "@yielded/auth/Client"] },
  { name: "lazy-root", requires: ["@yielded/auth"] },
  {
    name: "postgres-sessions",
    requires: ["@yielded/auth-persistence-drizzle/Postgres"],
    source:
      'export { makeStatefulSessionServices } from "@yielded/auth-persistence-drizzle/Postgres";',
    server: true,
  },
  {
    name: "postgres-connected",
    requires: ["@yielded/auth-persistence-drizzle/Postgres"],
    source:
      'export { makeOAuthConnectedServices } from "@yielded/auth-persistence-drizzle/Postgres";',
    server: true,
  },
  {
    name: "postgres-composed",
    requires: ["@yielded/auth-persistence-drizzle/Postgres"],
    source: 'export { AuthPersistence } from "@yielded/auth-persistence-drizzle/Postgres";',
    server: true,
  },
  {
    name: "d1-sessions",
    requires: ["@yielded/auth-persistence-drizzle/D1"],
    source: 'export { makeStatefulSessionServices } from "@yielded/auth-persistence-drizzle/D1";',
  },
  {
    name: "sqlite-sessions",
    requires: ["@yielded/auth-persistence-drizzle/SqliteNode"],
    source:
      'export { makeStatefulSessionServices } from "@yielded/auth-persistence-drizzle/SqliteNode";',
    server: true,
  },
  {
    name: "sql-composed",
    requires: ["@yielded/auth-persistence"],
    source: 'export { AuthPersistence } from "@yielded/auth-persistence";',
  },
  {
    name: "crypto-password",
    requires: ["@yielded/auth-crypto/Password"],
    source: 'export { layer } from "@yielded/auth-crypto/Password";',
  },
  {
    name: "crypto-totp",
    requires: ["@yielded/auth-crypto/Totp"],
    source: 'export { layer } from "@yielded/auth-crypto/Totp";',
  },
  {
    name: "crypto-oauth",
    requires: ["@yielded/auth-crypto/OAuth"],
    source: 'export { connectedTokenLayer } from "@yielded/auth-crypto/OAuth";',
  },
  {
    name: "openid",
    requires: ["@yielded/auth-openid-client"],
    source: 'export { layer } from "@yielded/auth-openid-client";',
  },
  {
    name: "openid-connected",
    requires: ["@yielded/auth-openid-client/Connected"],
    source: 'export { layer } from "@yielded/auth-openid-client/Connected";',
  },
  {
    name: "webauthn-browser",
    requires: ["@yielded/auth-simplewebauthn/Browser"],
    source: 'export { make } from "@yielded/auth-simplewebauthn/Browser";',
  },
  {
    name: "webauthn-server",
    requires: ["@yielded/auth-simplewebauthn/Server"],
    source: 'export { make } from "@yielded/auth-simplewebauthn/Server";',
    server: true,
  },
];
