// Public contracts adapted from panva/oauth4webapi v3.8.8 test/{client_auth,
// authorization_code,refresh_token,revocation,discovery}.test.ts and panva/openid-client
// v6.8.8 test/token-response.test.ts. Exact commits, selected case mappings and
// MIT notices in ../THIRD_PARTY_NOTICES.md.
// Cancellation seam adapted from the existing Auth adapter protocol.test.ts.
import { it } from "@effect/vitest";
import * as DateTime from "effect/DateTime";
import * as Deferred from "effect/Deferred";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as Fiber from "effect/Fiber";
import * as FetchHttpClient from "effect/http/FetchHttpClient";
import * as HttpClient from "effect/http/HttpClient";
import * as Redacted from "effect/Redacted";
import * as Scope from "effect/Scope";
import { expect } from "vite-plus/test";

import { Discovery, OAuth, OAuthError, Oidc, Pkce } from "../src/index";
import {
  codeInput,
  cryptoLayer,
  form,
  metadata,
  options,
  receipt,
  tokenBody,
  transport,
} from "./fixtures";

it.effect("uses RFC7636 S256 and fresh private 32-byte PKCE verifiers", () =>
  Effect.gen(function* () {
    expect(yield* Pkce.challenge(codeInput.pkceVerifier)).toBe(
      "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    );
    expect(yield* Pkce.challenge(Redacted.value(codeInput.pkceVerifier))).toBe(
      "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    );
    const first = yield* Pkce.generate;
    const second = yield* Pkce.generate;

    expect(Redacted.value(first.verifier)).toMatch(/^[\w-]{43}$/);
    expect(first.challenge).toBe(yield* Pkce.challenge(first.verifier));
    expect(Redacted.value(first.verifier)).not.toBe(Redacted.value(second.verifier));
    expect(JSON.stringify(first)).not.toContain(Redacted.value(first.verifier));
    const invalid = yield* Pkce.challenge(Redacted.make("short")).pipe(Effect.flip);

    expect(OAuthError.isOAuthError(invalid)).toBe(true);
    expect(OAuthError.isOAuthErrorReason(invalid.reason)).toBe(true);
    expect(invalid).toMatchObject({ _tag: "OAuthError", reason: { _tag: "InvalidArgument" } });
  }).pipe(Effect.provide(cryptoLayer)),
);

it.effect(
  "discovers the exact issuer including its trailing slash, supports RFC 8414 and local metadata, and rejects substituted metadata",
  () =>
    Effect.gen(function* () {
      const requests: string[] = [];
      let document: Discovery.Metadata = { ...metadata, custom_extension: { nested: true } };

      const client = transport((request) => {
        requests.push(request.url);

        return Response.json(document);
      });

      const local = yield* Discovery.makeLocal(document);

      expect(yield* local.resolve).toEqual(document);

      const oidcRemote = yield* Discovery.makeRemote({
        issuer: metadata.issuer,
        timeout: "1 second",
      }).pipe(Effect.provideService(HttpClient.HttpClient, client));

      expect(requests).toEqual([]);
      expect(yield* oidcRemote.resolve).toEqual(document);
      expect(yield* oidcRemote.resolve).toEqual(document);
      expect(requests).toEqual(["https://issuer.example/tenant/.well-known/openid-configuration"]);

      const rfc8414Remote = yield* Discovery.makeRemote({
        issuer: metadata.issuer,
        wellKnown: "oauth-authorization-server",
        timeout: "1 second",
      }).pipe(Effect.provideService(HttpClient.HttpClient, client));

      expect(yield* rfc8414Remote.resolve).toEqual(document);
      expect(requests[1]).toBe(
        "https://issuer.example/.well-known/oauth-authorization-server/tenant",
      );

      document = { ...metadata, issuer: metadata.issuer.slice(0, -1) };

      const mismatched = yield* Discovery.makeRemote({
        issuer: metadata.issuer,
        timeout: "1 second",
      }).pipe(Effect.provideService(HttpClient.HttpClient, client));

      expect(yield* mismatched.resolve.pipe(Effect.flip)).toMatchObject({
        _tag: "OAuthError",
        reason: { _tag: "DiscoveryFailed" },
      });
      expect(
        yield* Discovery.makeRemote({
          issuer: "http://issuer.example",
          timeout: "1 second",
        }).pipe(Effect.provideService(HttpClient.HttpClient, client), Effect.flip),
      ).toMatchObject({ _tag: "OAuthError", reason: { _tag: "InvalidArgument" } });
      expect(requests).toHaveLength(3);

      const loopback = {
        ...metadata,
        issuer: "http://127.0.0.1:8080",
        token_endpoint: "http://localhost:8080/token",
        jwks_uri: "https://issuer.example/jwks",
      };

      document = loopback;

      const loopbackRemote = yield* Discovery.makeRemote({
        issuer: loopback.issuer,
        timeout: "1 second",
      }).pipe(Effect.provideService(HttpClient.HttpClient, client));

      expect(yield* loopbackRemote.resolve).toEqual(loopback);
      expect(requests[3]).toBe("http://127.0.0.1:8080/.well-known/openid-configuration");
    }).pipe(Effect.scoped),
);

// Requested security seam: remote issuers cannot select HTTP loopback endpoints.
it.effect("binds HTTP loopback endpoints to an explicitly local issuer", () =>
  Effect.gen(function* () {
    const requests: string[] = [];

    const remote = {
      ...metadata,
      token_endpoint: "http://localhost:9901/token",
      userinfo_endpoint: "http://127.0.0.1:8500/user",
    };

    const http = transport((request) => {
      requests.push(request.url);

      return Response.json(remote);
    });

    const remoteDiscovery = yield* Discovery.makeRemote({
      issuer: metadata.issuer,
      timeout: "1 second",
    }).pipe(Effect.provideService(HttpClient.HttpClient, http));

    expect(yield* remoteDiscovery.resolve.pipe(Effect.flip)).toMatchObject({
      _tag: "OAuthError",
      reason: { _tag: "DiscoveryFailed" },
    });
    expect(
      yield* Discovery.makeRemote({
        issuer: metadata.issuer,
        timeout: "1 second",
        url: "http://localhost:8080/discovery",
      }).pipe(Effect.provideService(HttpClient.HttpClient, http), Effect.flip),
    ).toMatchObject({ _tag: "OAuthError", reason: { _tag: "InvalidArgument" } });
    expect(
      yield* OAuth.make({ ...options, metadata: remote }).pipe(
        Effect.provideService(HttpClient.HttpClient, http),
        Effect.flip,
      ),
    ).toMatchObject({ _tag: "OAuthError", reason: { _tag: "InvalidArgument" } });
    expect(requests).toEqual(["https://issuer.example/tenant/.well-known/openid-configuration"]);

    const local = yield* OAuth.make({
      ...options,
      metadata: { ...remote, issuer: "http://127.0.0.1:8080" },
    }).pipe(Effect.provideService(HttpClient.HttpClient, http));

    expect(local.metadata.token_endpoint).toBe(remote.token_endpoint);
  }).pipe(Effect.scoped),
);

// Requested security seam: discovery metadata rejects prototype-polluting keys.
it.effect("rejects __proto__ members in remote and local discovery metadata", () =>
  Effect.gen(function* () {
    const polluted = {
      userinfo_endpoint: "http://localhost:9999/pwned",
      jwks_uri: "http://localhost:9999/jwks",
      authorization_response_iss_parameter_supported: "not-a-boolean",
    };

    const hostileJson =
      '{"issuer":"https://issuer.example","token_endpoint":"https://issuer.example/token","__proto__":' +
      '{"userinfo_endpoint":"http://localhost:9999/pwned","jwks_uri":"http://localhost:9999/jwks","authorization_response_iss_parameter_supported":"not-a-boolean"}}';

    const http = transport(
      () =>
        new Response(hostileJson, {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );

    const remote = yield* Discovery.makeRemote({
      issuer: "https://issuer.example",
      timeout: "1 second",
    }).pipe(Effect.provideService(HttpClient.HttpClient, http));

    expect(yield* remote.resolve.pipe(Effect.flip)).toMatchObject({
      _tag: "OAuthError",
      reason: { _tag: "DiscoveryFailed" },
    });

    const hostileLocal = Object.defineProperty(
      {
        issuer: "https://issuer.example",
        token_endpoint: "https://issuer.example/token",
      },
      "__proto__",
      { value: polluted, enumerable: true, configurable: true, writable: true },
    ) as unknown as Discovery.Metadata;

    expect(yield* Discovery.makeLocal(hostileLocal).pipe(Effect.flip)).toMatchObject({
      _tag: "OAuthError",
      reason: { _tag: "InvalidArgument" },
    });
  }).pipe(Effect.scoped),
);

// Requested verifier seam: HTTP JWKS is a permanent configuration error.
it.effect("rejects HTTP JWKS before fetching a remote key set", () =>
  Effect.gen(function* () {
    const requests: string[] = [];

    const verifier = yield* Oidc.makeVerifierRemote({
      clientId: "client",
      jwks: { timeout: 1000 },
    }).pipe(
      Effect.provide(
        Discovery.layerLocal({
          ...metadata,
          issuer: "http://127.0.0.1:8080",
          jwks_uri: "http://[::1]:8080/jwks",
        }),
      ),
      Effect.provideService(
        HttpClient.HttpClient,
        transport((request) => {
          requests.push(request.url);

          return Response.json({ keys: [] });
        }),
      ),
    );

    const result = yield* verifier.verify("eyJhbGciOiJSUzI1NiJ9.e30.AQ").pipe(Effect.flip);

    expect(result).toMatchObject({ _tag: "OAuthError", reason: { _tag: "InvalidArgument" } });
    expect(requests).toEqual([]);
  }).pipe(Effect.scoped, Effect.provide(cryptoLayer)),
);

it.effect("authenticates Basic/Post/None once and preserves private raw provider receipts", () =>
  Effect.gen(function* () {
    for (const method of ["client_secret_basic", "client_secret_post", "none"] as const) {
      let count = 0;
      const clientId = "client %&+-_.!~*'()";

      const client = yield* OAuth.make({
        ...options,
        clientId,
        authentication:
          method === "none"
            ? { method, publicClient: true }
            : { method, secret: Redacted.make(clientId) },
      }).pipe(
        Effect.provideService(
          HttpClient.HttpClient,
          transport((request) => {
            count++;
            expect(request.url).toBe(metadata.token_endpoint);
            expect(request.method).toBe("POST");
            expect(request.headers.traceparent).toBeUndefined();
            const body = form(request);

            expect(body.get("grant_type")).toBe("authorization_code");
            expect(body.get("code")).toBe("single-use-code");
            expect(body.get("code_verifier")).toBe(Redacted.value(codeInput.pkceVerifier));
            expect(body.get("redirect_uri")).toBe(codeInput.redirectUri);
            expect(body.getAll("resource")).toEqual(["https://api.example/one", "urn:api:two"]);
            expect(body.get("extension")).toBe("value");
            if (method === "client_secret_basic") {
              expect(atob(request.headers.authorization.slice(6))).toBe(
                "client+%25%26%2B%2D%5F%2E%21%7E%2A%27%28%29:client+%25%26%2B%2D%5F%2E%21%7E%2A%27%28%29",
              );
              expect(body.has("client_id")).toBe(false);
              expect(body.has("client_secret")).toBe(false);
            } else {
              expect(request.headers.authorization).toBeUndefined();
              expect(body.get("client_id")).toBe(clientId);
              expect(body.get("client_secret")).toBe(method === "none" ? null : clientId);
            }

            return Response.json(tokenBody);
          }),
        ),
      );

      const raw = yield* client.codeGrant({
        ...codeInput,
        resources: ["https://api.example/one", "urn:api:two"],
        parameters: { extension: "value" },
      });

      expect(Redacted.value(raw.body)).toEqual(tokenBody);
      const grant = yield* OAuth.tokens(raw);

      expect(Redacted.value(grant.accessToken)).toBe("private-access");
      expect(grant.scope).toBe("read:user, repo");
      expect(grant.expiresIn).toBe(60);
      expect(JSON.stringify([raw, grant])).not.toContain("private-access");
      expect(count).toBe(1);
    }
  }).pipe(Effect.scoped),
);

it.effect(
  "distinguishes complete invalid_grant 400 from other endpoint or malformed receipts",
  () =>
    Effect.gen(function* () {
      const invalidGrant = yield* OAuth.tokens(
        receipt({ error: "invalid_grant", error_description: "private-provider-data" }, 400),
      ).pipe(Effect.flip);

      expect(invalidGrant).toMatchObject({
        _tag: "OAuthError",
        reason: { _tag: "EndpointError", endpoint: "token", code: "invalid_grant", status: 400 },
      });
      expect(JSON.stringify(invalidGrant)).not.toContain("private-");
      for (const [raw, expected] of [
        [receipt({ error: "invalid_grant" }, 200), { _tag: "InvalidResponse", endpoint: "token" }],
        [receipt({ error: "invalid_grant" }, 500), { _tag: "InvalidResponse", endpoint: "token" }],
        [
          receipt({ error: "invalid_client" }, 400),
          { _tag: "EndpointError", endpoint: "token", code: "invalid_client", status: 400 },
        ],
        [
          receipt({ error: "invalid_client" }, 401),
          { _tag: "EndpointError", endpoint: "token", code: "invalid_client", status: 401 },
        ],
        [
          receipt({ error: "invalid_grant", error_description: 12 }, 400),
          { _tag: "InvalidResponse", endpoint: "token" },
        ],
        [
          receipt({ error: "invalid_grant", access_token: "private-access" }, 400),
          { _tag: "InvalidResponse", endpoint: "token" },
        ],
        [
          receipt({ ...tokenBody, expires_in: "60junk" }),
          { _tag: "InvalidResponse", endpoint: "token" },
        ],
        [receipt({ ...tokenBody, expires_in: -1 }), { _tag: "InvalidResponse", endpoint: "token" }],
        [
          receipt({ ...tokenBody, token_type: "DPoP" }),
          { _tag: "InvalidResponse", endpoint: "token" },
        ],
        [
          { ...receipt(tokenBody), contentType: "text/plain" },
          { _tag: "InvalidResponse", endpoint: "token" },
        ],
      ] as const) {
        const failure = yield* OAuth.tokens(raw).pipe(Effect.flip);

        expect(failure).toMatchObject({ _tag: "OAuthError", reason: expected });
        expect(JSON.stringify(failure)).not.toContain("private-");
      }
      expect((yield* OAuth.tokens(receipt({ ...tokenBody, expires_in: 0 }))).expiresIn).toBe(0);
      const omitted = yield* OAuth.tokens(receipt({ ...tokenBody, refresh_token: null }));

      expect(omitted.refreshToken).toBeUndefined();
      expect(Redacted.value(omitted.accessToken)).toBe("private-access");
      const extension = receipt({ error: "bad_verification_code" });

      expect(Redacted.value(extension.body).error).toBe("bad_verification_code");
    }),
);

it.effect("binds authorization parameters and snapshots configuration before network effects", () =>
  Effect.gen(function* () {
    const mutable = { ...metadata };

    const client = yield* OAuth.make({ ...options, metadata: mutable }).pipe(
      Effect.provideService(
        HttpClient.HttpClient,
        transport(() => Response.json(tokenBody)),
      ),
    );

    mutable.authorization_endpoint = "https://attacker.example/authorize";

    const input: OAuth.AuthorizationInput = {
      redirectUri: "http://127.0.0.1:3000/callback",
      scopes: ["openid", "profile", "r".repeat(256)],
      state: Redacted.make("state"),
      nonce: Redacted.make("nonce"),
      codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      maxAgeSeconds: 0,
      resources: ["urn:one", "urn:two"],
      parameters: { prompt: "consent", resource: "urn:legacy", audience: "api" },
    };

    const url = new URL(Redacted.value(yield* client.authorizationUrl(input)));

    expect(url.origin).toBe("https://issuer.example");
    expect(url.searchParams.get("client_id")).toBe("client");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("max_age")).toBe("0");
    expect(url.searchParams.getAll("resource")).toEqual(["urn:legacy", "urn:one", "urn:two"]);
    expect(url.searchParams.get("audience")).toBe("api");
    expect(
      yield* client
        .authorizationUrl({ ...input, parameters: { CLIENT_ID: "attacker" } })
        .pipe(Effect.flip),
    ).toMatchObject({ _tag: "OAuthError", reason: { _tag: "InvalidArgument" } });
    expect(
      yield* client
        .codeGrant({ ...codeInput, parameters: { code: "replacement" } })
        .pipe(Effect.flip),
    ).toMatchObject({ _tag: "OAuthError", reason: { _tag: "InvalidArgument" } });
  }).pipe(Effect.scoped),
);

it.effect("keeps installed metadata arrays detached and immutable through revocation", () =>
  Effect.gen(function* () {
    const methods = ["client_secret_basic"];
    let calls = 0;

    const client = yield* OAuth.make({
      ...options,
      metadata: { ...metadata, revocation_endpoint_auth_methods_supported: methods },
    }).pipe(
      Effect.provideService(
        HttpClient.HttpClient,
        transport(() => {
          calls++;

          return new Response(null, { status: 200 });
        }),
      ),
    );

    methods[0] = "client_secret_post";
    const installed = client.metadata.revocation_endpoint_auth_methods_supported!;

    const input: OAuth.RevocationInput = {
      token: Redacted.make("private-refresh"),
      tokenTypeHint: "refresh_token",
    };

    expect(installed).toEqual(["client_secret_basic"]);
    expect(yield* client.revoke(input).pipe(Effect.flip)).toMatchObject({
      _tag: "OAuthError",
      reason: { _tag: "InvalidArgument" },
    });
    const changed = Reflect.set(installed, 0, "client_secret_post");
    const revoked = yield* client.revoke(input).pipe(Effect.exit);

    expect(Exit.isFailure(revoked)).toBe(true);
    expect(changed).toBe(false);
    expect(Object.isFrozen(installed)).toBe(true);
    expect(calls).toBe(0);
  }).pipe(Effect.scoped),
);

it.effect("refreshes and revokes with separately installed credentials", () =>
  Effect.gen(function* () {
    const requests: string[] = [];

    const client = yield* OAuth.make({
      ...options,
      revocationAuthentication: {
        method: "client_secret_basic",
        secret: Redacted.make("revocation-secret"),
      },
    }).pipe(
      Effect.provideService(
        HttpClient.HttpClient,
        transport((request) => {
          requests.push(request.url);
          const body = form(request);

          if (request.url === metadata.token_endpoint) {
            expect(body.get("grant_type")).toBe("refresh_token");
            expect(body.get("refresh_token")).toBe("private-refresh");
            expect(body.has("scope")).toBe(false);

            return Response.json(tokenBody);
          }
          expect(body.get("token_type_hint")).toBe("refresh_token");
          expect(body.get("token")).toBe("private-refresh");
          expect(atob(request.headers.authorization.slice(6))).toBe("client:revocation%2Dsecret");

          return new Response(null, { status: 200 });
        }),
      ),
    );

    yield* OAuth.tokens(
      yield* client.refreshGrant({ refreshToken: Redacted.make("private-refresh") }),
    );
    yield* client.revoke({
      token: Redacted.make("private-refresh"),
      tokenTypeHint: "refresh_token",
    });
    expect(requests).toEqual([metadata.token_endpoint, metadata.revocation_endpoint]);
  }).pipe(Effect.scoped),
);

it.effect(
  "rejects unsafe endpoints, reserved endpoint queries, and unsupported authentication before dispatch",
  () =>
    Effect.gen(function* () {
      let requests = 0;

      const http = transport(() => {
        requests++;

        return Response.json(tokenBody);
      });

      for (const configured of [
        { ...options, metadata: { ...metadata, token_endpoint: "http://issuer.example/token" } },
        { ...options, metadata: { ...metadata, token_endpoint: "https://issuer.example/token#" } },
        {
          ...options,
          metadata: { ...metadata, token_endpoint: "https://issuer.example/token?client_secret=x" },
        },
        { ...options, metadata: { ...metadata, token_endpoint_auth_methods_supported: ["none"] } },
        { ...options, timeoutMs: Infinity },
      ])
        expect(
          yield* OAuth.make(configured).pipe(
            Effect.provideService(HttpClient.HttpClient, http),
            Effect.flip,
          ),
        ).toMatchObject({ _tag: "OAuthError", reason: { _tag: "InvalidArgument" } });
      expect(requests).toBe(0);
    }).pipe(Effect.scoped),
);

it.effect(
  "bounds bodies, refuses redirects and unexpected URLs, and never repeats failed exchange/revocation",
  () =>
    Effect.gen(function* () {
      for (const [response, reasonTag] of [
        [
          new Response(null, { status: 302, headers: { location: "https://attacker.example" } }),
          "TransportFailed",
        ],
        [
          new Response("x".repeat(129), { headers: { "content-type": "application/json" } }),
          "TransportFailed",
        ],
        [new Response("{}", { headers: { "content-type": "text/plain" } }), "InvalidResponse"],
        [Response.json([]), "InvalidResponse"],
      ] as const) {
        let count = 0;

        const client = yield* OAuth.make({ ...options, maxResponseBytes: 128 }).pipe(
          Effect.provideService(
            HttpClient.HttpClient,
            transport(() => {
              count++;

              return response;
            }),
          ),
        );

        expect(yield* client.codeGrant(codeInput).pipe(Effect.flip)).toMatchObject({
          _tag: "OAuthError",
          reason: { _tag: reasonTag, endpoint: "token" },
        });
        expect(count).toBe(1);
      }
      const moved = Response.json(tokenBody);

      Object.defineProperty(moved, "url", { value: "https://attacker.example/token" });

      const client = yield* OAuth.make(options).pipe(
        Effect.provideService(
          HttpClient.HttpClient,
          transport(() => moved),
        ),
      );

      expect(yield* client.codeGrant(codeInput).pipe(Effect.flip)).toMatchObject({
        _tag: "OAuthError",
        reason: { _tag: "TransportFailed", endpoint: "token" },
      });
      let revocations = 0;

      const revoke = yield* OAuth.make(options).pipe(
        Effect.provideService(
          HttpClient.HttpClient,
          transport(() => {
            revocations++;

            return new Response(null, { status: 503 });
          }),
        ),
      );

      expect(
        yield* revoke
          .revoke({ token: Redacted.make("private-refresh"), tokenTypeHint: "refresh_token" })
          .pipe(Effect.flip),
      ).toMatchObject({
        _tag: "OAuthError",
        reason: { _tag: "InvalidResponse", endpoint: "revocation", status: 503 },
      });
      expect(revocations).toBe(1);
    }).pipe(Effect.scoped),
);

it.effect("rejects deeply nested provider JSON as unavailable without repeating the exchange", () =>
  Effect.gen(function* () {
    const body =
      '{"access_token":"private-access","token_type":"Bearer","extension":' +
      '{"x":'.repeat(20000) +
      "0" +
      "}".repeat(20000) +
      "}";

    let calls = 0;

    expect(new TextEncoder().encode(body).length).toBeLessThan(1048576);

    const client = yield* OAuth.make(options).pipe(
      Effect.provideService(
        HttpClient.HttpClient,
        transport(() => {
          calls++;

          return new Response(body, { headers: { "content-type": "application/json" } });
        }),
      ),
    );

    expect(yield* client.codeGrant(codeInput).pipe(Effect.flip)).toMatchObject({
      _tag: "OAuthError",
      reason: { _tag: "InvalidResponse", endpoint: "token" },
    });
    expect(calls).toBe(1);
  }).pipe(Effect.scoped),
);

for (const termination of ["interruption", "timeout"] as const) {
  it.live(`${termination} aborts a body read with Fetch injection and never repeats the code`, () =>
    Effect.gen(function* () {
      const reading = yield* Deferred.make<void>();
      let cancelled = false;
      let calls = 0;

      const fetch: typeof globalThis.fetch = async (_request, init) => {
        calls++;
        expect(init?.redirect).toBe("manual");
        expect(init?.credentials).toBe("omit");

        return new Response(
          new ReadableStream(
            {
              pull() {
                Deferred.doneUnsafe(reading, Effect.void);
              },
              cancel() {
                cancelled = true;
              },
            },
            { highWaterMark: 0 },
          ),
          { headers: { "content-type": "application/json" } },
        );
      };

      const client = yield* OAuth.make({ ...options, timeoutMs: 50 }).pipe(
        Effect.provide(FetchHttpClient.layer),
        Effect.provideService(FetchHttpClient.Fetch, fetch),
      );

      const fiber = yield* client.codeGrant(codeInput).pipe(Effect.forkChild);

      yield* Deferred.await(reading);
      if (termination === "interruption") yield* Fiber.interrupt(fiber);
      else
        expect(yield* Fiber.join(fiber).pipe(Effect.flip)).toMatchObject({
          _tag: "OAuthError",
          reason: { _tag: "TransportFailed", endpoint: "token" },
        });
      expect(cancelled).toBe(true);
      expect(calls).toBe(1);
    }).pipe(Effect.scoped),
  );
}

it.live("closing the owner scope cancels an active exchange before returning", () =>
  Effect.gen(function* () {
    const scope = yield* Effect.acquireRelease(Scope.make(), (scope) =>
      Scope.close(scope, Exit.void),
    );

    const reading = yield* Deferred.make<void>();
    let cancelled = false;
    let aborted = false;
    let calls = 0;

    const fetch: typeof globalThis.fetch = async (_request, init) => {
      calls++;
      init?.signal?.addEventListener("abort", () => {
        aborted = true;
      });

      return new Response(
        new ReadableStream(
          {
            pull() {
              Deferred.doneUnsafe(reading, Effect.void);
            },
            async cancel() {
              await Promise.resolve();
              cancelled = true;
            },
          },
          { highWaterMark: 0 },
        ),
        { headers: { "content-type": "application/json" } },
      );
    };

    const client = yield* OAuth.make({ ...options, timeoutMs: 60000 }).pipe(
      Effect.provideService(Scope.Scope, scope),
      Effect.provide(FetchHttpClient.layer),
      Effect.provideService(FetchHttpClient.Fetch, fetch),
    );

    const fiber = yield* client.codeGrant(codeInput).pipe(Effect.forkChild);

    yield* Deferred.await(reading);
    yield* Scope.close(scope, Exit.void);
    expect(cancelled).toBe(true);
    expect(aborted).toBe(true);
    expect(yield* Fiber.join(fiber).pipe(Effect.flip)).toMatchObject({
      _tag: "OAuthError",
      reason: { _tag: "TransportFailed", endpoint: "token" },
    });
    expect(yield* client.codeGrant(codeInput).pipe(Effect.flip)).toMatchObject({
      _tag: "OAuthError",
      reason: { _tag: "TransportFailed", endpoint: "token" },
    });
    expect(calls).toBe(1);
  }).pipe(Effect.scoped),
);

it.effect("invalidates clients when their owning scope closes", () =>
  Effect.gen(function* () {
    const scope = yield* Scope.make();
    let calls = 0;

    const client = yield* OAuth.make(options).pipe(
      Effect.provideService(Scope.Scope, scope),
      Effect.provideService(
        HttpClient.HttpClient,
        transport(() => {
          calls++;

          return Response.json(tokenBody);
        }),
      ),
    );

    yield* Scope.close(scope, Exit.void);
    expect(yield* client.codeGrant(codeInput).pipe(Effect.flip)).toMatchObject({
      _tag: "OAuthError",
      reason: { _tag: "TransportFailed", endpoint: "token" },
    });
    expect(calls).toBe(0);
    expect(DateTime.toEpochMillis(yield* DateTime.now)).toBeGreaterThanOrEqual(0);
  }),
);

it.effect("decodes whole decimal expiry strings while preserving the private raw receipt", () =>
  Effect.gen(function* () {
    const raw = receipt({ ...tokenBody, expires_in: "60.5" });

    expect((yield* OAuth.tokens(raw)).expiresIn).toBe(60.5);
    expect(Redacted.value(raw.body).expires_in).toBe("60.5");
    expect(
      yield* OAuth.tokens(receipt({ ...tokenBody, expires_in: " 60" })).pipe(Effect.flip),
    ).toMatchObject({ _tag: "OAuthError", reason: { _tag: "InvalidResponse", endpoint: "token" } });
    expect(
      yield* OAuth.tokens(receipt({ ...tokenBody, expires_in: "Infinity" })).pipe(Effect.flip),
    ).toMatchObject({ _tag: "OAuthError", reason: { _tag: "InvalidResponse", endpoint: "token" } });
  }),
);
