import * as NodeCrypto from "@effect/platform-node/NodeCrypto";
import { it } from "@effect/vitest";
import { OAuth, OAuthProxy, OpenIdConnect } from "@yielded/auth";
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as FetchHttpClient from "effect/http/FetchHttpClient";
import * as Jwk from "effect/jose/Jwk";
import * as Jwt from "effect/jose/Jwt";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import * as TestClock from "effect/testing/TestClock";
import { expect } from "vite-plus/test";

// Regression at f1da141a: an admitted form_post provider could not complete its
// proxy callback. Live providers cannot supply controlled first-consent data.
// Exercise the HTTP workflow with real envelope protection and a replacement
// persistence service: reject mixed/duplicate input before the valid callback,
// forward user once, then reject replay without exchanging credentials again.
it.effect("completes a form_post callback through the proxy without repeating exchange", () =>
  Effect.gen(function* () {
    const origin = "https://proxy.example";
    const callbackUrl = `${origin}/oauth-proxy/apple/callback`;
    const state = "A".repeat(43);
    const user = JSON.stringify({ name: { firstName: "Ada", lastName: "Lovelace" } });
    let record: OAuthProxy.Record | undefined;
    let exchanges = 0;

    const crypto = NodeCrypto.layer;

    const persistence = Layer.succeed(OAuthProxy.Persistence, {
      get: () => Effect.succeed(record),
      insert: (_namespace, value) =>
        Effect.sync(() => {
          if (record !== undefined) return false;
          record = value;

          return true;
        }),
      compareAndSet: (_namespace, version, value) =>
        Effect.sync(() => {
          if (record?.version !== version) return false;
          record = value;

          return true;
        }),
    });

    const live = OAuthProxy.layer({
      origin,
      providers: {
        apple: {
          configure: (binding) =>
            Effect.succeed({
              prepareAuthorization: () =>
                Schema.decodeEffect(OAuth.OAuthProtocolPreparation)({
                  configuration: {
                    provider: binding.provider,
                    protocol: "oidc",
                    configurationGeneration: 1,
                    issuer: "https://appleid.apple.com",
                    responseIssuerMode: "unsupported",
                    callbackId: OAuth.OAuthCallbackId.make("apple"),
                    redirectUri: OAuth.OAuthRedirectUri.make(callbackUrl),
                  },
                  responseMode: "form_post",
                  authorizationUrl: "https://appleid.apple.com/auth/authorize",
                  secrets: {
                    namespace: "effect-auth/oauth-transaction-secrets/v1",
                    state,
                    oidcNonce: "B".repeat(43),
                  },
                }).pipe(Effect.orDie),
              exchangeVerifiedIdentity: Effect.fnUntraced(function* (input) {
                exchanges++;
                expect(input.response.user).toBe(user);

                return yield* Schema.decodeEffect(OAuth.OAuthVerifiedExternalIdentity)({
                  identity: {
                    provider: binding.provider,
                    issuer: "https://appleid.apple.com",
                    subject: "apple-subject",
                  },
                }).pipe(Effect.orDie);
              }),
            }),
        },
      },
      environments: [
        {
          id: "app",
          secret: Redacted.make("C".repeat(43)),
          callbacks: [
            {
              provider: OAuth.OAuthProviderKey.make("apple"),
              callbackId: OAuth.OAuthCallbackId.make("app"),
              redirectUri: "https://app.example/auth/apple/callback",
            },
          ],
        },
      ],
    }).pipe(
      Layer.provide(persistence),
      Layer.provide(
        OAuthProxy.protectorLayer({
          activeKeyId: "key",
          keys: [
            { id: "key", material: Redacted.make("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc") },
          ],
        }).pipe(Layer.provide(crypto)),
      ),
      Layer.provide(crypto),
    );

    yield* Effect.gen(function* () {
      const server = yield* OAuthProxy.Server;

      const prepared = yield* server.handle(
        new Request(`${origin}/oauth-proxy/prepare`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${"C".repeat(43)}`,
          },
          body: JSON.stringify({
            environment: "app",
            provider: "apple",
            callbackId: "app",
            redirectUri: "https://app.example/auth/apple/callback",
            flowId: "flow",
            verifierDigest: "D".repeat(43),
          }),
        }),
      );

      expect(prepared.status).toBe(200);

      const callback = (url: string, body: string) =>
        server.handle(
          new Request(url, {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body,
          }),
        );

      const form = new URLSearchParams({ state, code: "provider-code", user }).toString();

      expect((yield* server.handle(new Request(`${callbackUrl}?${form}`))).status).toBe(400);
      expect((yield* callback(`${callbackUrl}?state=${state}`, form)).status).toBe(400);
      expect((yield* callback(callbackUrl, `${form}&state=${state}`)).status).toBe(400);
      expect((yield* callback(callbackUrl, `${form}&id_token=header.payload.sig`)).status).toBe(
        400,
      );
      const completed = yield* callback(callbackUrl, form);

      expect(completed.status).toBe(303);
      expect(completed.headers.get("location")).toContain(
        "https://app.example/auth/apple/callback?",
      );
      expect((yield* callback(callbackUrl, form)).status).toBe(400);
      expect(exchanges).toBe(1);
    }).pipe(Effect.provide(live));
  }).pipe(Effect.scoped),
);

// Explicit human test request (2026-11-20): pending proxy callback records
// survive a cold-worker OIDC discovery outage untouched and complete after recovery.
it.effect(
  "keeps a pending proxy record untouched when cold OIDC discovery fails and completes after recovery",
  () =>
    Effect.gen(function* () {
      const seconds = 2_000_000_000;

      yield* TestClock.setTime(seconds * 1000);

      const pair = yield* Jwk.generateKeyPair({ algorithm: "ES256", kid: "proxy-key" }).pipe(
        Effect.provide(NodeCrypto.layer),
      );

      const signingKey = yield* Jwk.importPrivate(pair.privateKey, "ES256").pipe(
        Effect.provide(NodeCrypto.layer),
      );

      const issuer = "https://proxy-oidc.example";
      const origin = "https://proxy.example";
      let record: OAuthProxy.Record | undefined;
      let healthy = true;
      let discoveryCalls = 0;
      let tokenCalls = 0;
      let idToken = "";

      const persistence = Layer.succeed(OAuthProxy.Persistence, {
        get: () => Effect.succeed(record),
        insert: (_namespace, value) =>
          Effect.sync(() => {
            if (record !== undefined) return false;
            record = value;

            return true;
          }),
        compareAndSet: (_namespace, version, value) =>
          Effect.sync(() => {
            if (record?.version !== version) return false;
            record = value;

            return true;
          }),
      });

      const fetch: typeof globalThis.fetch = async (input, init) => {
        const url = input instanceof Request ? input.url : String(input);

        if (url === `${issuer}/.well-known/openid-configuration`) {
          discoveryCalls++;

          return healthy
            ? Response.json({
                issuer,
                authorization_endpoint: `${issuer}/authorize`,
                token_endpoint: `${issuer}/token`,
                jwks_uri: `${issuer}/jwks`,
                response_types_supported: ["code"],
                id_token_signing_alg_values_supported: ["ES256"],
                code_challenge_methods_supported: ["S256"],
                token_endpoint_auth_methods_supported: ["client_secret_basic"],
                authorization_response_iss_parameter_supported: true,
              })
            : new Response(null, { status: 503 });
        }
        if (url === `${issuer}/token` && init?.method === "POST") {
          tokenCalls++;

          return Response.json({
            access_token: "proxy-access",
            token_type: "bearer",
            id_token: idToken,
          });
        }
        if (url === `${issuer}/jwks`) return Response.json({ keys: [pair.publicKey] });
        throw new Error(`Unexpected endpoint ${url}`);
      };

      const services = Layer.mergeAll(
        NodeCrypto.layer,
        FetchHttpClient.layer,
        persistence,
        OAuthProxy.protectorLayer({
          activeKeyId: "key",
          keys: [
            { id: "key", material: Redacted.make("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc") },
          ],
        }).pipe(Layer.provide(NodeCrypto.layer)),
      );

      const makeServer = () =>
        Layer.build(
          OAuthProxy.layer({
            origin,
            providers: {
              example: OpenIdConnect.provider({
                protocol: "oidc",
                issuer,
                clientId: "client",
                clientSecret: Redacted.make("client-secret"),
                responseIssuerMode: "discovered",
                idTokenSignedResponseAlg: ["ES256"],
              }),
            },
            environments: [
              {
                id: "app",
                secret: Redacted.make("C".repeat(43)),
                callbacks: [
                  {
                    provider: OAuth.OAuthProviderKey.make("example"),
                    callbackId: OAuth.OAuthCallbackId.make("app"),
                    redirectUri: "https://app.example/callback",
                  },
                ],
              },
            ],
          }).pipe(
            Layer.provide(services),
            Layer.provide(Layer.succeed(FetchHttpClient.Fetch, fetch)),
          ),
        ).pipe(Effect.map(Context.get(OAuthProxy.Server)));

      const first = yield* makeServer();

      const prepared = yield* first.handle(
        new Request(`${origin}/oauth-proxy/prepare`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${"C".repeat(43)}`,
          },
          body: JSON.stringify({
            environment: "app",
            provider: "example",
            callbackId: "app",
            redirectUri: "https://app.example/callback",
            flowId: "flow",
            verifierDigest: "D".repeat(43),
          }),
        }),
      );

      expect(prepared.status).toBe(200);

      const body: { readonly authorizationUrl: string } = yield* Effect.promise(() =>
        prepared.json(),
      );

      const authUrl = new URL(body.authorizationUrl);
      const state = authUrl.searchParams.get("state") ?? "";
      const nonce = authUrl.searchParams.get("nonce") ?? "";

      idToken = Redacted.value(
        yield* Jwt.sign(
          Schema.Struct({
            iss: Schema.String,
            sub: Schema.String,
            aud: Schema.String,
            iat: Schema.Finite,
            exp: Schema.Finite,
            nonce: Schema.String,
          }),
          {
            iss: issuer,
            sub: "proxy-subject",
            aud: "client",
            iat: seconds,
            exp: seconds + 300,
            nonce,
          },
          signingKey,
          { kid: "proxy-key" },
        ).pipe(Effect.provide(NodeCrypto.layer)),
      );

      // Restart while discovery is down: callback fails 503 without advancing Pending -> Exchanging.
      healthy = false;
      const coldDown = yield* makeServer();

      const callbackUrl = `${origin}/oauth-proxy/example/callback?${new URLSearchParams({
        state,
        code: "provider-code",
        iss: issuer,
      })}`;

      expect((yield* coldDown.handle(new Request(callbackUrl))).status).toBe(503);
      expect(record?._tag).toBe("Pending");
      expect(tokenCalls).toBe(0);
      expect(discoveryCalls).toBe(2);

      // Recovery on a restarted worker completes the still-pending callback.
      healthy = true;
      const coldRecovered = yield* makeServer();
      const completed = yield* coldRecovered.handle(new Request(callbackUrl));

      expect(completed.status).toBe(303);
      expect(tokenCalls).toBe(1);
    }).pipe(Effect.scoped),
);
