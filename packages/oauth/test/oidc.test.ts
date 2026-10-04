// Claim and auth_time contracts adapted from panva/oauth4webapi v3.8.8
// test/{authorization_code,auth_time,jwt_claims}.test.ts; this
// profile additionally verifies RS256 before definite claim classification.
// MIT, Copyright Filip Skokan. Exact commits and selected case mappings in
// ../THIRD_PARTY_NOTICES.md. Refresh continuity is an Auth-profile case.
import { createHash } from "node:crypto";

import { it } from "@effect/vitest";
import { DateTime, Deferred, Effect, Fiber, Redacted, Scope, Exit } from "effect";
import { HttpClient } from "effect/http";
import { TestClock } from "effect/testing";
import * as jose from "jose";
import { expect } from "vite-plus/test";

import { Oidc } from "../src/index";
import { cryptoLayer, metadata, transport } from "./fixtures";

const seconds = 2_000_000_000;

const hash = (value: string) =>
  createHash("sha256").update(value).digest().subarray(0, 16).toString("base64url");

const claims = {
  iss: metadata.issuer,
  sub: "provider-subject",
  aud: "client",
  azp: "client",
  iat: seconds,
  exp: seconds + 300,
  auth_time: seconds - 10,
  nonce: "nonce",
  email: "ada@example.com",
  email_verified: true,
  hd: "example.com",
  at_hash: hash("private-access"),
  c_hash: hash("single-use-code"),
};

const verification: Oidc.VerificationInput = {
  verificationStartedAt: DateTime.makeUnsafe(seconds * 1000 - 1000),
  nonce: Redacted.make("nonce"),
  maxAgeSeconds: 60,
  accessToken: Redacted.make("private-access"),
  code: Redacted.make("single-use-code"),
};

const generate = Effect.promise(() => jose.generateKeyPair("RS256", { extractable: true }));

const sign = (key: CryptoKey, data: jose.JWTPayload) =>
  Effect.promise(() =>
    new jose.SignJWT(data).setProtectedHeader({ alg: "RS256", kid: "key" }).sign(key),
  ).pipe(Effect.map(Redacted.make));

it.effect(
  "verifies signed OIDC claims/hashes, retains profile extensions and clamps authentication time to captured start",
  () =>
    Effect.gen(function* () {
      yield* TestClock.setTime(seconds * 1000);
      const keys = yield* generate;
      const jwk = yield* Effect.promise(() => jose.exportJWK(keys.publicKey));
      let calls = 0;

      const verifier = yield* Oidc.makeVerifier({
        metadata,
        clientId: "client",
        timeoutMs: 1000,
      }).pipe(
        Effect.provideService(
          HttpClient.HttpClient,
          transport((request) => {
            calls++;
            expect(request.url).toBe(metadata.jwks_uri);

            return Response.json({ keys: [{ ...jwk, kid: "key" }] });
          }),
        ),
      );

      const result = yield* verifier.verify(yield* sign(keys.privateKey, claims), verification);

      expect(result.subject).toBe("provider-subject");
      expect(result.authTime).toBe(seconds - 10);
      expect(Redacted.value(result.claims).hd).toBe("example.com");
      expect(DateTime.toEpochMillis(result.upstreamAuthenticatedAt!)).toBe((seconds - 10) * 1000);

      const recent = yield* verifier.verify(
        yield* sign(keys.privateKey, { ...claims, auth_time: seconds }),
        verification,
      );

      expect(DateTime.toEpochMillis(recent.upstreamAuthenticatedAt!)).toBe(seconds * 1000 - 1000);
      yield* verifier.verify(
        yield* sign(keys.privateKey, { ...claims, aud: ["client"] }),
        verification,
      );
      const longSubject = "s".repeat(1024);

      expect(
        (yield* verifier.verify(
          yield* sign(keys.privateKey, { ...claims, sub: longSubject }),
          verification,
        )).subject,
      ).toBe(longSubject);
      expect(calls).toBe(1);
      expect(JSON.stringify(result)).not.toContain("ada@example.com");
    }).pipe(Effect.scoped, Effect.provide(cryptoLayer)),
);

it.effect(
  "rejects authenticated wrong issuer/aud/azp/time/nonce/hash claims with no clock tolerance",
  () =>
    Effect.gen(function* () {
      yield* TestClock.setTime(seconds * 1000);
      const keys = yield* generate;
      const jwk = yield* Effect.promise(() => jose.exportJWK(keys.publicKey));

      const verifier = yield* Oidc.makeVerifier({
        metadata,
        clientId: "client",
        timeoutMs: 1000,
      }).pipe(
        Effect.provideService(
          HttpClient.HttpClient,
          transport(() => Response.json({ keys: [{ ...jwk, kid: "key" }] })),
        ),
      );

      // Existing Auth requires one audience even when an azp names this client.
      for (const override of [
        { iss: metadata.issuer.slice(0, -1) },
        { aud: "other" },
        { aud: ["client", "other"] },
        { azp: "other" },
        { exp: seconds },
        { iat: seconds + 1 },
        { nbf: seconds + 1 },
        { nonce: "other" },
        { nonce: undefined },
        { auth_time: seconds + 1 },
        { auth_time: seconds - 61 },
        { auth_time: undefined },
        { at_hash: hash("other") },
        { c_hash: hash("other") },
        { sub: "" },
      ]) {
        expect(
          (yield* verifier
            .verify(yield* sign(keys.privateKey, { ...claims, ...override }), verification)
            .pipe(Effect.flip))._tag,
        ).toBe("OAuthRejected");
      }
      expect(
        (yield* verifier
          .verify(yield* sign(keys.privateKey, claims), {
            ...verification,
            verificationStartedAt: DateTime.makeUnsafe(seconds * 1000 + 1),
          })
          .pipe(Effect.flip))._tag,
      ).toBe("OAuthRejected");
      expect(
        (yield* verifier
          .verify(yield* sign(keys.privateKey, claims), { ...verification, accessToken: undefined })
          .pipe(Effect.flip))._tag,
      ).toBe("OAuthRejected");
      expect(
        (yield* verifier
          .verify(yield* sign(keys.privateKey, claims), { ...verification, code: undefined })
          .pipe(Effect.flip))._tag,
      ).toBe("OAuthRejected");
    }).pipe(Effect.scoped, Effect.provide(cryptoLayer)),
);

it.effect(
  "verifies signatures before definite claim rejection and keeps key/signature faults ambiguous",
  () =>
    Effect.gen(function* () {
      yield* TestClock.setTime(seconds * 1000);
      const keys = yield* generate;
      const other = yield* generate;
      const jwk = yield* Effect.promise(() => jose.exportJWK(keys.publicKey));

      const verifier = yield* Oidc.makeVerifier({
        metadata,
        clientId: "client",
        timeoutMs: 1000,
      }).pipe(
        Effect.provideService(
          HttpClient.HttpClient,
          transport(() => Response.json({ keys: [{ ...jwk, kid: "key" }] })),
        ),
      );

      const invalid = yield* sign(other.privateKey, {
        ...claims,
        iss: "https://attacker.example",
        exp: 0,
      });

      expect((yield* verifier.verify(invalid, verification).pipe(Effect.flip))._tag).toBe(
        "OAuthUnavailable",
      );
      expect(
        (yield* verifier
          .verify(Redacted.make("malformed.jwt.signature"), verification)
          .pipe(Effect.flip))._tag,
      ).toBe("OAuthUnavailable");

      const unavailable = yield* Oidc.makeVerifier({
        metadata,
        clientId: "client",
        timeoutMs: 1000,
      }).pipe(
        Effect.provideService(
          HttpClient.HttpClient,
          transport(() => new Response(null, { status: 503 })),
        ),
      );

      expect(
        (yield* unavailable
          .verify(yield* sign(keys.privateKey, claims), verification)
          .pipe(Effect.flip))._tag,
      ).toBe("OAuthUnavailable");
    }).pipe(Effect.scoped, Effect.provide(cryptoLayer)),
);

it.effect(
  "refresh binds subject/optional nonce/auth_time without treating old max_age as a new login",
  () =>
    Effect.gen(function* () {
      yield* TestClock.setTime(seconds * 1000);
      const keys = yield* generate;
      const jwk = yield* Effect.promise(() => jose.exportJWK(keys.publicKey));

      const verifier = yield* Oidc.makeVerifier({
        metadata,
        clientId: "client",
        timeoutMs: 1000,
      }).pipe(
        Effect.provideService(
          HttpClient.HttpClient,
          transport(() => Response.json({ keys: [{ ...jwk, kid: "key" }] })),
        ),
      );

      const input = {
        ...verification,
        previous: { subject: "provider-subject", authTime: seconds - 7200 },
      };

      const refreshed = {
        ...claims,
        nonce: undefined,
        auth_time: seconds - 7200,
        c_hash: undefined,
      };

      expect((yield* verifier.verify(yield* sign(keys.privateKey, refreshed), input)).subject).toBe(
        "provider-subject",
      );
      for (const override of [
        { sub: "different" },
        { nonce: "different" },
        { auth_time: seconds - 7199 },
      ])
        expect(
          (yield* verifier
            .verify(yield* sign(keys.privateKey, { ...refreshed, ...override }), input)
            .pipe(Effect.flip))._tag,
        ).toBe("OAuthRejected");
    }).pipe(Effect.scoped, Effect.provide(cryptoLayer)),
);

it.effect("rejects unsupported OIDC metadata and closes the issuer's scoped JWKS resolver", () =>
  Effect.gen(function* () {
    const http = transport(() => Response.json({ keys: [] }));

    for (const override of [
      { jwks_uri: undefined },
      { code_challenge_methods_supported: ["plain"] },
      { id_token_signing_alg_values_supported: ["HS256"] },
      { response_types_supported: ["id_token"] },
    ]) {
      expect(
        (yield* Oidc.makeVerifier({
          metadata: { ...metadata, ...override },
          clientId: "client",
          timeoutMs: 1000,
        }).pipe(Effect.provideService(HttpClient.HttpClient, http), Effect.flip))._tag,
      ).toBe("OAuthConfigurationError");
    }
    const scope = yield* Scope.make();

    const verifier = yield* Oidc.makeVerifier({
      metadata,
      clientId: "client",
      timeoutMs: 1000,
    }).pipe(
      Effect.provideService(Scope.Scope, scope),
      Effect.provideService(HttpClient.HttpClient, http),
    );

    yield* Scope.close(scope, Exit.void);
    const keys = yield* generate;

    expect(
      (yield* verifier.verify(yield* sign(keys.privateKey, claims), verification).pipe(Effect.flip))
        ._tag,
    ).toBe("OAuthUnavailable");
  }).pipe(Effect.scoped, Effect.provide(cryptoLayer)),
);

it.effect("captures verification policy before JWKS I/O", () =>
  Effect.gen(function* () {
    yield* TestClock.setTime(seconds * 1000);
    const keys = yield* generate;
    const jwk = yield* Effect.promise(() => jose.exportJWK(keys.publicKey));
    const entered = yield* Deferred.make<void>();
    const release = yield* Deferred.make<void>();

    const http = HttpClient.transformResponse(
      transport(() => Response.json({ keys: [{ ...jwk, kid: "key" }] })),
      (effect) =>
        Effect.andThen(
          Deferred.succeed(entered, undefined),
          Effect.andThen(Deferred.await(release), effect),
        ),
    );

    const verifier = yield* Oidc.makeVerifier({
      metadata,
      clientId: "client",
      timeoutMs: 1000,
    }).pipe(Effect.provideService(HttpClient.HttpClient, http));

    const policy = { ...verification, nonce: Redacted.make("nonce") };
    const token = yield* sign(keys.privateKey, claims);
    const fiber = yield* verifier.verify(token, policy).pipe(Effect.forkChild);

    yield* Deferred.await(entered);
    policy.nonce = Redacted.make("substituted");
    yield* Deferred.succeed(release, undefined);
    expect((yield* Fiber.join(fiber)).subject).toBe("provider-subject");
  }).pipe(Effect.scoped, Effect.provide(cryptoLayer)),
);
