// Claim and auth_time contracts adapted from panva/oauth4webapi v3.8.8
// test/{authorization_code,auth_time,jwt_claims}.test.ts; this
// profile additionally verifies RS256 before definite claim classification.
// MIT, Copyright Filip Skokan. Exact commits and selected case mappings in
// ../THIRD_PARTY_NOTICES.md. Refresh continuity is an Auth-profile case.
import { createHash } from "node:crypto";

import { it } from "@effect/vitest";
import * as Cause from "effect/Cause";
import * as Signature from "effect/crypto/Signature";
import * as DateTime from "effect/DateTime";
import * as Deferred from "effect/Deferred";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as Fiber from "effect/Fiber";
import * as HttpClient from "effect/http/HttpClient";
import * as Redacted from "effect/Redacted";
import * as Scope from "effect/Scope";
import * as Struct from "effect/Struct";
import * as TestClock from "effect/testing/TestClock";
import * as jose from "jose";
import { expect } from "vite-plus/test";

import { Discovery, Oidc } from "../src/index";
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

const verification: Oidc.VerifyOptions = {
  requestedAt: DateTime.makeUnsafe(seconds * 1000 - 1000),
  nonce: Redacted.make("nonce"),
  maxAge: "60 seconds",
  accessToken: Redacted.make("private-access"),
  code: Redacted.make("single-use-code"),
};

const generate = Effect.promise(() => jose.generateKeyPair("RS256", { extractable: true }));

const sign = (
  key: CryptoKey,
  data: jose.JWTPayload,
  header: Partial<jose.JWTHeaderParameters> = {},
) =>
  Effect.promise(() =>
    new jose.SignJWT(data).setProtectedHeader({ alg: "RS256", kid: "key", ...header }).sign(key),
  ).pipe(Effect.map(Redacted.make));

const makeRemoteVerifier = (
  http: HttpClient.HttpClient,
  options: Partial<Oidc.VerifierOptions> = {},
  discoveryMetadata: Discovery.Metadata = metadata,
) =>
  Oidc.makeVerifierRemote({
    clientId: "client",
    jwks: { timeout: 1000 },
    ...options,
  }).pipe(
    Effect.provide(Discovery.layerLocal(discoveryMetadata)),
    Effect.provideService(HttpClient.HttpClient, http),
  );

it.effect(
  "verifies signed OIDC claims/hashes, retains profile extensions and clamps authentication time to verification clock",
  () =>
    Effect.gen(function* () {
      yield* TestClock.setTime(seconds * 1000);
      const keys = yield* generate;
      const jwk = yield* Effect.promise(() => jose.exportJWK(keys.publicKey));
      let calls = 0;

      const verifier = yield* makeRemoteVerifier(
        transport((request) => {
          calls++;
          expect(request.url).toBe(metadata.jwks_uri);

          return Response.json({ keys: [{ ...jwk, kid: "key" }] });
        }),
      );

      const result = yield* verifier.verify(yield* sign(keys.privateKey, claims), verification);

      expect(result.subject).toBe("provider-subject");
      expect(result.issuer).toBe(metadata.issuer);
      expect(result.audience).toEqual(["client"]);
      expect(result.protectedHeader.alg).toBe("RS256");
      expect(result.authTime).toBe(seconds - 10);
      expect(Redacted.value(result.claims).hd).toBe("example.com");
      expect(DateTime.toEpochMillis(result.authenticatedAt!)).toBe((seconds - 10) * 1000);

      // Fresh login occurring after requestedAt is not back-dated, while tolerable
      // future auth_time skew clamps to verification nowMillis.
      const fresh = yield* verifier.verify(
        yield* sign(keys.privateKey, { ...claims, auth_time: seconds }),
        verification,
      );

      expect(DateTime.toEpochMillis(fresh.authenticatedAt!)).toBe(seconds * 1000);

      const skewed = yield* verifier.verify(
        yield* sign(keys.privateKey, { ...claims, auth_time: seconds + 5 }),
        verification,
      );

      expect(DateTime.toEpochMillis(skewed.authenticatedAt!)).toBe(seconds * 1000);

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
  "rejects authenticated wrong typ/issuer/aud/azp/time/nonce/hash claims with zero clock tolerance",
  () =>
    Effect.gen(function* () {
      yield* TestClock.setTime(seconds * 1000);
      const keys = yield* generate;
      const jwk = yield* Effect.promise(() => jose.exportJWK(keys.publicKey));

      const verifier = yield* makeRemoteVerifier(
        transport(() => Response.json({ keys: [{ ...jwk, kid: "key" }] })),
        { clockTolerance: 0 },
      );

      // typ is rejected immediately after signature verification, before exp/claim checks.
      expect(
        yield* verifier
          .verify(
            yield* sign(keys.privateKey, { ...claims, exp: 0 }, { typ: "at+jwt" }),
            verification,
          )
          .pipe(Effect.flip),
      ).toMatchObject({
        _tag: "OAuthError",
        reason: { _tag: "TokenVerificationFailed", reason: "typ" },
      });

      const invalidCases: ReadonlyArray<readonly [Partial<jose.JWTPayload>, string]> = [
        [{ iss: metadata.issuer.slice(0, -1) }, "issuer"],
        [{ aud: "other" }, "audience"],
        [{ aud: ["client", "other"] }, "audience"],
        [{ azp: "other" }, "audience"],
        [{ exp: seconds }, "expired"],
        [{ iat: seconds + 1 }, "notYetValid"],
        [{ nbf: seconds + 1 }, "notYetValid"],
        [{ nonce: "other" }, "nonce"],
        [{ nonce: undefined }, "nonce"],
        [{ auth_time: seconds + 1 }, "notYetValid"],
        [{ auth_time: seconds - 62 }, "maxAge"],
        [{ auth_time: undefined }, "maxAge"],
        [{ at_hash: hash("other") }, "hash"],
        [{ c_hash: hash("other") }, "hash"],
        [{ sub: "" }, "claim"],
      ];

      for (const [override, expectedReason] of invalidCases) {
        expect(
          yield* verifier
            .verify(yield* sign(keys.privateKey, { ...claims, ...override }), verification)
            .pipe(Effect.flip),
        ).toMatchObject({
          _tag: "OAuthError",
          reason: { _tag: "TokenVerificationFailed", reason: expectedReason },
        });
      }
      expect(
        yield* verifier
          .verify(yield* sign(keys.privateKey, claims), {
            ...verification,
            requestedAt: DateTime.makeUnsafe(seconds * 1000 + 1),
          })
          .pipe(Effect.flip),
      ).toMatchObject({
        _tag: "OAuthError",
        reason: { _tag: "TokenVerificationFailed", reason: "maxAge" },
      });
      expect(
        yield* verifier
          .verify(yield* sign(keys.privateKey, claims), {
            ...Struct.omit(verification, ["code"]),
            requireCodeHash: true,
          })
          .pipe(Effect.flip),
      ).toMatchObject({
        _tag: "OAuthError",
        reason: { _tag: "TokenVerificationFailed", reason: "hash" },
      });

      // Exact future-tolerance boundary divides once ((nowMillis + toleranceMillis) / 1000)
      // so exact equality passes for iat, nbf, and auth_time.
      const boundaryNowMillis = Date.parse("2026-01-01T00:00:00.001Z");
      const exactFutureSeconds = (boundaryNowMillis + 100) / 1000;
      const pastFutureSeconds = (boundaryNowMillis + 101) / 1000;

      yield* TestClock.setTime(boundaryNowMillis);

      const tolerantVerifier = yield* makeRemoteVerifier(
        transport(() => Response.json({ keys: [{ ...jwk, kid: "key" }] })),
        { clockTolerance: "100 millis" },
      );

      const boundaryVerified = yield* tolerantVerifier.verify(
        yield* sign(keys.privateKey, {
          ...claims,
          iat: exactFutureSeconds,
          nbf: exactFutureSeconds,
          auth_time: exactFutureSeconds,
          exp: Math.floor(boundaryNowMillis / 1000) + 300,
        }),
        {
          ...verification,
          requestedAt: DateTime.makeUnsafe(boundaryNowMillis),
        },
      );

      expect(boundaryVerified.subject).toBe("provider-subject");
      expect(DateTime.toEpochMillis(boundaryVerified.authenticatedAt!)).toBe(boundaryNowMillis);

      for (const futureOverride of [
        { iat: pastFutureSeconds },
        { nbf: pastFutureSeconds },
        { auth_time: pastFutureSeconds },
      ]) {
        expect(
          yield* tolerantVerifier
            .verify(
              yield* sign(keys.privateKey, {
                ...claims,
                iat: Math.floor(boundaryNowMillis / 1000),
                exp: Math.floor(boundaryNowMillis / 1000) + 300,
                auth_time: Math.floor(boundaryNowMillis / 1000),
                ...futureOverride,
              }),
              {
                ...verification,
                requestedAt: DateTime.makeUnsafe(boundaryNowMillis),
              },
            )
            .pipe(Effect.flip),
        ).toMatchObject({
          _tag: "OAuthError",
          reason: { _tag: "TokenVerificationFailed", reason: "notYetValid" },
        });
      }
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

      const verifier = yield* makeRemoteVerifier(
        transport(() => Response.json({ keys: [{ ...jwk, kid: "key" }] })),
      );

      const invalid = yield* sign(other.privateKey, {
        ...claims,
        iss: "https://attacker.example",
        exp: 0,
      });

      expect(yield* verifier.verify(invalid, verification).pipe(Effect.flip)).toMatchObject({
        _tag: "OAuthError",
        reason: { _tag: "TokenVerificationFailed", reason: "signature" },
      });
      expect(
        yield* verifier
          .verify(Redacted.make("malformed.jwt.signature"), verification)
          .pipe(Effect.flip),
      ).toMatchObject({
        _tag: "OAuthError",
        reason: { _tag: "TokenVerificationFailed", reason: "malformed" },
      });

      const unavailable = yield* makeRemoteVerifier(
        transport(() => new Response(null, { status: 503 })),
      );

      expect(
        yield* unavailable
          .verify(yield* sign(keys.privateKey, claims), verification)
          .pipe(Effect.flip),
      ).toMatchObject({
        _tag: "OAuthError",
        reason: { _tag: "TransportFailed", endpoint: "jwks" },
      });
    }).pipe(Effect.scoped, Effect.provide(cryptoLayer)),
);

it.effect(
  "refresh binds issuer/subject/audience/optional nonce/auth_time without treating old max_age as a new login",
  () =>
    Effect.gen(function* () {
      yield* TestClock.setTime(seconds * 1000);
      const keys = yield* generate;
      const jwk = yield* Effect.promise(() => jose.exportJWK(keys.publicKey));

      const verifier = yield* makeRemoteVerifier(
        transport(() => Response.json({ keys: [{ ...jwk, kid: "key" }] })),
      );

      const input: Oidc.VerifyOptions = {
        ...verification,
        previous: {
          subject: "provider-subject",
          issuer: metadata.issuer,
          audience: "client",
          nonce: Redacted.make("nonce"),
          authTime: seconds - 7200,
        },
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
      for (const [override, expectedReason] of [
        [{ sub: "different" }, "continuity"],
        [{ nonce: "different" }, "nonce"],
        [{ auth_time: seconds - 7199 }, "continuity"],
      ] as const)
        expect(
          yield* verifier
            .verify(yield* sign(keys.privateKey, { ...refreshed, ...override }), input)
            .pipe(Effect.flip),
        ).toMatchObject({
          _tag: "OAuthError",
          reason: { _tag: "TokenVerificationFailed", reason: expectedReason },
        });
    }).pipe(Effect.scoped, Effect.provide(cryptoLayer)),
);

// Regression at c4752e3 (Effect-TS/effect#9884): max_age=0 checked auth_time + 0 < floor(now),
// rejecting fresh logins that took >= 1s after the authorization request began.
it.effect(
  "accepts max_age=0 when auth_time is at or after requestedAt despite >=1s login delay",
  () =>
    Effect.gen(function* () {
      yield* TestClock.setTime(seconds * 1000);
      const keys = yield* generate;
      const jwk = yield* Effect.promise(() => jose.exportJWK(keys.publicKey));

      const verifier = yield* makeRemoteVerifier(
        transport(() => Response.json({ keys: [{ ...jwk, kid: "key" }] })),
        { clockTolerance: 0 },
      );

      const requestedAt = DateTime.makeUnsafe((seconds - 5) * 1000);

      const verified = yield* verifier.verify(
        yield* sign(keys.privateKey, { ...claims, auth_time: seconds - 2 }),
        {
          ...verification,
          requestedAt,
          maxAge: 0,
        },
      );

      expect(verified.subject).toBe("provider-subject");
      expect(verified.authTime).toBe(seconds - 2);

      // Authentication before requestedAt is still rejected under max_age=0.
      expect(
        yield* verifier
          .verify(yield* sign(keys.privateKey, { ...claims, auth_time: seconds - 6 }), {
            ...verification,
            requestedAt,
            maxAge: 0,
          })
          .pipe(Effect.flip),
      ).toMatchObject({
        _tag: "OAuthError",
        reason: { _tag: "TokenVerificationFailed", reason: "maxAge" },
      });

      // Millisecond precision: fractional requestedAt neither admits an extra
      // second nor falsely rejects auth_time at the exact millisecond cutoff.
      const fractionalRequestedAt = DateTime.makeUnsafe((seconds - 5) * 1000 + 900);

      expect(
        yield* verifier
          .verify(yield* sign(keys.privateKey, { ...claims, auth_time: seconds - 10 + 0.2 }), {
            ...verification,
            requestedAt: fractionalRequestedAt,
            maxAge: "5 seconds",
          })
          .pipe(Effect.flip),
      ).toMatchObject({
        _tag: "OAuthError",
        reason: { _tag: "TokenVerificationFailed", reason: "maxAge" },
      });

      const exactCutoff = yield* verifier.verify(
        yield* sign(keys.privateKey, { ...claims, auth_time: seconds - 10 + 0.9 }),
        {
          ...verification,
          requestedAt: fractionalRequestedAt,
          maxAge: "5 seconds",
        },
      );

      expect(exactCutoff.subject).toBe("provider-subject");

      // Integer auth_time covers its whole second even when requestedAt has sub-second millis.
      const sameSecondInteger = yield* verifier.verify(
        yield* sign(keys.privateKey, { ...claims, auth_time: seconds - 5 }),
        {
          ...verification,
          requestedAt: DateTime.makeUnsafe((seconds - 5) * 1000 + 750),
          maxAge: 0,
        },
      );

      expect(sameSecondInteger.subject).toBe("provider-subject");

      // Exact fractional equality does not suffer from float multiplication rounding (2038-02-01T00:00:00.002Z).
      const y2038Millis = 2_148_595_200_002;
      const y2038Seconds = 2_148_595_200.002;

      yield* TestClock.setTime(y2038Millis);

      const exactY2038 = yield* verifier.verify(
        yield* sign(keys.privateKey, {
          ...claims,
          iat: 2_148_595_200,
          exp: 2_148_595_500,
          auth_time: y2038Seconds,
        }),
        {
          ...verification,
          requestedAt: DateTime.makeUnsafe(y2038Millis),
          maxAge: 0,
        },
      );

      expect(exactY2038.authTime).toBe(y2038Seconds);
      expect(DateTime.toEpochMillis(exactY2038.authenticatedAt!)).toBe(y2038Millis);
    }).pipe(Effect.scoped, Effect.provide(cryptoLayer)),
);

// Regression at c4752e3: refresh compared claims.auth_time !== previous.authTime even when
// previous.authTime was omitted, falsely rejecting refreshed tokens that include auth_time.
it.effect("accepts refresh ID token carrying auth_time when previous.authTime is omitted", () =>
  Effect.gen(function* () {
    yield* TestClock.setTime(seconds * 1000);
    const keys = yield* generate;
    const jwk = yield* Effect.promise(() => jose.exportJWK(keys.publicKey));

    const verifier = yield* makeRemoteVerifier(
      transport(() => Response.json({ keys: [{ ...jwk, kid: "key" }] })),
    );

    const verified = yield* verifier.verify(
      yield* sign(keys.privateKey, {
        ...claims,
        nonce: undefined,
        auth_time: seconds - 7200,
        c_hash: undefined,
      }),
      {
        ...verification,
        previous: {
          subject: "provider-subject",
          issuer: metadata.issuer,
          audience: "client",
          nonce: Redacted.make("nonce"),
        },
      },
    );

    expect(verified.subject).toBe("provider-subject");
    expect(verified.authTime).toBe(seconds - 7200);
  }).pipe(Effect.scoped, Effect.provide(cryptoLayer)),
);

it.effect("rejects missing jwks_uri, non-matching algorithms, and closed verifier scopes", () =>
  Effect.gen(function* () {
    yield* TestClock.setTime(seconds * 1000);
    const keys = yield* generate;
    const http = transport(() => Response.json({ keys: [] }));
    const token = yield* sign(keys.privateKey, claims);

    const { jwks_uri: _jwksUri, ...withoutJwks } = metadata;
    const missingJwks = yield* makeRemoteVerifier(http, {}, withoutJwks);

    expect(yield* missingJwks.verify(token, verification).pipe(Effect.flip)).toMatchObject({
      _tag: "OAuthError",
      reason: { _tag: "InvalidArgument" },
    });

    const hmacOnly = yield* makeRemoteVerifier(
      http,
      {},
      { ...metadata, id_token_signing_alg_values_supported: ["HS256"] },
    );

    expect(yield* hmacOnly.verify(token, verification).pipe(Effect.flip)).toMatchObject({
      _tag: "OAuthError",
      reason: { _tag: "TokenVerificationFailed", reason: "algorithm" },
    });

    const scope = yield* Scope.make();

    const verifier = yield* makeRemoteVerifier(http).pipe(
      Effect.provideService(Scope.Scope, scope),
    );

    yield* Scope.close(scope, Exit.void);

    expect(yield* verifier.verify(token, verification).pipe(Effect.flip)).toMatchObject({
      _tag: "OAuthError",
      reason: { _tag: "TransportFailed", endpoint: "jwks" },
    });
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

    const verifier = yield* makeRemoteVerifier(http);
    const policy = { ...verification, nonce: Redacted.make("nonce") };
    const token = yield* sign(keys.privateKey, claims);
    const fiber = yield* verifier.verify(token, policy).pipe(Effect.forkChild);

    yield* Deferred.await(entered);
    policy.nonce = Redacted.make("substituted");
    yield* Deferred.succeed(release, undefined);
    expect((yield* Fiber.join(fiber)).subject).toBe("provider-subject");
  }).pipe(Effect.scoped, Effect.provide(cryptoLayer)),
);

// Regression at 5199d99: owner closure left signature work running; gate cleanup to expose it.
for (const termination of ["owner closure", "caller interruption"] as const) {
  it.effect(`${termination} interrupts and joins active OIDC verification`, () =>
    Effect.gen(function* () {
      yield* TestClock.setTime(seconds * 1000);
      const keys = yield* generate;
      const jwk = yield* Effect.promise(() => jose.exportJWK(keys.publicKey));

      const owner = yield* Effect.acquireRelease(Scope.make(), (scope) =>
        Scope.close(scope, Exit.void),
      );

      const signatures = yield* Signature.Signature;
      const entered = yield* Deferred.make<void>();
      const cleanupStarted = yield* Deferred.make<void>();
      const allowCleanup = yield* Deferred.make<void>();
      let shouldGate = true;
      let cleanupFinished = false;
      let terminationFinished = false;

      yield* Effect.addFinalizer(() => Deferred.succeed(allowCleanup, undefined));

      const gated = Signature.Signature.of({
        ...signatures,
        verify: (key, signature, data) =>
          shouldGate
            ? signatures.verify(key, signature, data).pipe(
                Effect.tap(() => Deferred.succeed(entered, undefined)),
                Effect.andThen(Effect.never),
                Effect.ensuring(
                  Effect.gen(function* () {
                    yield* Deferred.succeed(cleanupStarted, undefined);
                    yield* Deferred.await(allowCleanup);
                    cleanupFinished = true;
                  }),
                ),
              )
            : signatures.verify(key, signature, data),
      });

      const verifier = yield* makeRemoteVerifier(
        transport(() => Response.json({ keys: [{ ...jwk, kid: "key" }] })),
      ).pipe(
        Effect.provideService(Scope.Scope, owner),
        Effect.provideService(Signature.Signature, gated),
      );

      const token = yield* sign(keys.privateKey, { ...claims, nonce: "wrong-nonce" });
      const active = yield* verifier.verify(token, verification).pipe(Effect.forkChild);

      yield* Deferred.await(entered);

      const terminating = yield* (
        termination === "owner closure" ? Scope.close(owner, Exit.void) : Fiber.interrupt(active)
      ).pipe(
        Effect.tap(() =>
          Effect.sync(() => {
            terminationFinished = true;
          }),
        ),
        Effect.forkChild,
      );

      expect(
        yield* Effect.raceFirst(
          Deferred.await(cleanupStarted).pipe(Effect.as("cleanup")),
          Fiber.join(terminating).pipe(Effect.as("terminated")),
        ),
      ).toBe("cleanup");
      expect(terminationFinished).toBe(false);
      yield* Deferred.succeed(allowCleanup, undefined);
      yield* Fiber.join(terminating);
      expect(cleanupFinished).toBe(true);

      if (termination === "owner closure") {
        expect(yield* Fiber.join(active).pipe(Effect.flip)).toMatchObject({
          _tag: "OAuthError",
          reason: { _tag: "TransportFailed", endpoint: "jwks" },
        });
      } else {
        const exit = yield* Fiber.await(active);

        expect(Exit.isFailure(exit) && Cause.hasInterruptsOnly(exit.cause)).toBe(true);
        shouldGate = false;
        expect(
          (yield* verifier.verify(yield* sign(keys.privateKey, claims), verification)).subject,
        ).toBe("provider-subject");
      }
    }).pipe(Effect.scoped, Effect.provide(cryptoLayer)),
  );
}
