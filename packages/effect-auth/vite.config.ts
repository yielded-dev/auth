import { defineConfig } from "vite-plus";

export default defineConfig({
  pack: {
    tsconfig: "tsconfig.build.json",
    entry: [
      "src/index.ts",
      "src/Contracts.ts",
      "src/Strategies.ts",
      "src/Auth.ts",
      "src/AuthContract.ts",
      "src/Client.ts",
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
      "src/Cloudflare.ts",
      "src/Http.ts",
      "src/HttpServer.ts",
      "src/OperationHttp.ts",
      "src/OperationHttpClient.ts",
      "src/OperationHttpServer.ts",
      "src/Atom.ts",
      "src/Hooks.ts",
      "src/Identity.ts",
      "src/OAuth.ts",
      "src/Operations.ts",
      "src/Rpc.ts",
      "src/Schema.ts",
      "src/Testing.ts",
      "src/WebCrypto.ts",
      "src/Sessions.ts",
      "src/SessionContract.ts",
      "src/Proofs.ts",
      "src/Password.ts",
      "src/Email.ts",
      "src/OpenIdClient.ts",
      "src/OpenIdClientConnected.ts",
      "src/Passkey.ts",
      "src/PasskeyPassword.ts",
      "src/PasskeySimpleWebAuthn.ts",
      "src/PasskeyBrowser.ts",
      "src/GitHub.ts",
      "src/AuthSession.ts",
      "src/Errors.ts",
      "src/Workflows.ts",
      "src/PasswordHasher.ts",
      "src/EmailOtp.ts",
      "src/AuthStore.ts",
      "src/PasswordAuth.ts",
      "src/Policy.ts",
      "src/EmailOtpSender.ts",
      "src/AuthTokenCodec.ts",
      "src/IdentityResolver.ts",
      "src/PasswordCredentialStore.ts",
      "src/PhoneOtp.ts",
      "src/Totp.ts",
      "src/PasskeyContract.ts",
      "src/TotpContract.ts",
    ],
    dts: true,
    // Preserve implementation boundaries so consumers can discard unused modules.
    unbundle: true,
    plugins: [
      {
        // Each target is also a pack entry. Keep native namespaces in JS and
        // declarations instead of materializing objects that retain every export.
        name: "preserve-public-namespaces",
        resolveId: {
          order: "pre",
          handler(source, importer) {
            if (
              importer !== undefined &&
              /\/src\/(?:index|Contracts|Strategies)(?:\.d)?\.ts$/.test(importer) &&
              /^\.\/[A-Z]\w*(?:\.ts)?$/.test(source)
            ) {
              return { id: source.replace(/(?:\.ts)?$/, ".mjs"), external: true };
            }
          },
        },
      },
    ],
    sourcemap: true,
  },
  test: { cache: false, silent: "passed-only", include: ["test/**/*.test.ts"] },
});
