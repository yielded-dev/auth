import * as Cause from "effect/Cause";
import * as Clock from "effect/Clock";
import * as Digest from "effect/crypto/Digest";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as Base64Url from "effect/encoding/Base64Url";
import type * as HttpClient from "effect/http/HttpClient";
import * as Jwk from "effect/jose/Jwk";
import * as Jwks from "effect/jose/Jwks";
import type * as Jws from "effect/jose/Jws";
import * as Jwt from "effect/jose/Jwt";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import type * as Scope from "effect/Scope";

import * as OidcJwks from "./internal/jwks.ts";
import * as Ownership from "./internal/ownership.ts";
import * as V from "./internal/validation.ts";
import { JsonObject, Metadata, type RequestOptions } from "./OAuth.ts";
import * as OAuthError from "./OAuthError.ts";

export const IdTokenAlgorithm = Schema.Literals(["RS256", "PS256", "ES256", "EdDSA", "HS256"]);
export type IdTokenAlgorithm = typeof IdTokenAlgorithm.Type;

export const defaultIdTokenAlgorithms: readonly IdTokenAlgorithm[] = [
  "RS256",
  "PS256",
  "ES256",
  "EdDSA",
];

const idTokenAlgorithms: readonly IdTokenAlgorithm[] = [
  "RS256",
  "PS256",
  "ES256",
  "EdDSA",
  "HS256",
];

export interface VerifierOptions extends RequestOptions {
  readonly metadata: Metadata;
  readonly clientId: string;
  /** Accepted ID-token audiences, for one relying party known by several client
   * IDs, such as an app per platform. A token's `aud` must contain one of them, and
   * a present `azp` must be one of them. Defaults to `[clientId]`. */
  readonly audiences?: ReadonlyArray<string>;
  /** Algorithms this verifier will accept. Discovery must advertise at least one.
   * Defaults to RS256, PS256, ES256 and EdDSA. HS256 is accepted only when
   * requested here and a client secret is supplied. */
  readonly algorithms?: ReadonlyArray<IdTokenAlgorithm>;
  /** Require advertised S256 PKCE. Defaults to true. Set false only for issuers
   * that cannot complete authorization-code + PKCE. */
  readonly pkceS256?: boolean;
  /** Channel or client secret used as the HS256 HMAC key. Required when the
   * advertised algorithm set is HS256. */
  readonly clientSecret?: Redacted.Redacted<string>;
}

export interface VerificationInput {
  readonly verificationStartedAt: DateTime.Utc;
  readonly nonce: Redacted.Redacted<string>;
  readonly maxAgeSeconds?: number;
  readonly accessToken?: Redacted.Redacted<string>;
  readonly code?: Redacted.Redacted<string>;
  /** Refresh continuation: same subject, optional nonce must match, auth_time cannot change.
   * A `{tenantid}` metadata issuer also requires the original token `iss`. */
  readonly previous?: {
    readonly subject: string;
    readonly authTime?: number;
    readonly issuer?: string;
  };
}

export interface Verified {
  readonly claims: Redacted.Redacted<JsonObject>;
  readonly subject: string;
  readonly authTime?: number;
  readonly upstreamAuthenticatedAt?: DateTime.Utc;
}

type VerificationRequirements = Jws.Requirements | Digest.Digest;

export interface Verifier {
  readonly verify: (
    token: Redacted.Redacted<string>,
    input: VerificationInput,
  ) => Effect.Effect<Verified, OAuthError.OAuthError, VerificationRequirements>;
}

const Configuration = Schema.Struct({
  metadata: Metadata,
  clientId: V.text(1024),
  audiences: Schema.optionalKey(
    Schema.Array(V.text(1024)).check(Schema.isMinLength(1), Schema.isMaxLength(64)),
  ),
  ...V.RequestOptions.fields,
  algorithms: Schema.optionalKey(
    Schema.Array(IdTokenAlgorithm).check(Schema.isMinLength(1), Schema.isMaxLength(5)),
  ),
  pkceS256: Schema.optionalKey(Schema.Boolean),
  clientSecret: Schema.optionalKey(V.secret(4096)),
});

const VerifyInput = Schema.Struct({
  verificationStartedAt: Schema.DateTimeUtc,
  nonce: V.secret(256),
  maxAgeSeconds: Schema.optional(V.integer(0, 86400)),
  accessToken: Schema.optional(V.secret(16384)),
  code: Schema.optional(V.secret(16384)),
  previous: Schema.optional(
    Schema.Struct({
      subject: V.text(1024),
      authTime: Schema.optional(V.NumericDate),
      /** Original token `iss`. Required when the metadata issuer is a `{tenantid}` template. */
      issuer: Schema.optional(V.text(2048)),
    }),
  ),
});

const IdClaims = Schema.Struct({
  iss: V.text(2048),
  sub: V.text(1024),
  aud: Schema.Union([
    V.text(1024),
    Schema.Array(V.text(1024)).check(Schema.isMinLength(1), Schema.isMaxLength(1)),
  ]),
  azp: Schema.optionalKey(V.text(1024)),
  exp: V.NumericDate,
  iat: V.NumericDate,
  nbf: Schema.optionalKey(V.NumericDate),
  auth_time: Schema.optionalKey(V.NumericDate),
  nonce: Schema.optionalKey(V.text(256)),
  // Leftmost half of the signing-algorithm hash, unpadded base64url: 22
  // characters for SHA-256 (RS256, PS256, ES256, HS256) and 43 for SHA-512 (Ed25519).
  at_hash: Schema.optionalKey(
    Schema.String.check(Schema.isPattern(/^[A-Za-z0-9_-]{22}(?:[A-Za-z0-9_-]{21})?$/u)),
  ),
  c_hash: Schema.optionalKey(
    Schema.String.check(Schema.isPattern(/^[A-Za-z0-9_-]{22}(?:[A-Za-z0-9_-]{21})?$/u)),
  ),
});

const tokenHash = (algorithm: string) =>
  algorithm === "EdDSA"
    ? { digest: Digest.sha512, octets: 32 }
    : algorithm === "RS256" ||
        algorithm === "PS256" ||
        algorithm === "ES256" ||
        algorithm === "HS256"
      ? { digest: Digest.sha256, octets: 16 }
      : undefined;

const tenantPlaceholder = "{tenantid}";

const TenantId = Schema.String.check(
  Schema.isPattern(
    /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/u,
  ),
);

const issuerOriginAndPath = (value: string) => {
  const match = /^(https:\/\/[^/?#]+)(\/[^?#]*)?$/u.exec(value);

  if (match === null) return undefined;

  const origin = match[1];

  return origin === undefined ? undefined : { origin, path: match[2] ?? "" };
};

/** True when `issuer` has exactly one `{tenantid}` path segment. The URL parser
 * percent-encodes braces, so matching stays on the raw identifier. */
export const isTenantIssuerTemplate = (issuer: string): boolean => {
  const parts = issuerOriginAndPath(issuer);

  return (
    parts !== undefined &&
    parts.path.split("/").filter((segment) => segment === tenantPlaceholder).length === 1
  );
};

export const substituteTenantIssuer = (template: string, tenantId: string): string | undefined => {
  if (!Schema.is(TenantId)(tenantId)) return undefined;

  const parts = issuerOriginAndPath(template);

  if (parts === undefined) return undefined;

  const segments = parts.path.split("/");
  const index = segments.indexOf(tenantPlaceholder);

  if (index < 0 || segments.filter((segment) => segment === tenantPlaceholder).length !== 1)
    return undefined;

  segments[index] = tenantId;

  return `${parts.origin}${segments.join("/")}`;
};

const tokenFailed = (
  reason: OAuthError.TokenVerificationFailed["reason"],
  cause?: unknown,
): OAuthError.OAuthError =>
  new OAuthError.OAuthError({
    reason: new OAuthError.TokenVerificationFailed({ reason, cause }),
  });

const mapJwtError = (error: Jwt.JwtError): OAuthError.OAuthError => {
  if (error._tag !== "JoseError") return tokenFailed("malformed", error);
  switch (error.reason._tag) {
    case "InvalidToken":
    case "InvalidArgument":
    case "DecryptionFailed":
      return tokenFailed("malformed", error);
    case "AlgorithmNotAllowed":
      return tokenFailed("algorithm", error);
    case "KeySetUnavailable":
      return new OAuthError.OAuthError({
        reason: new OAuthError.TransportFailed({
          endpoint: "jwks",
          description: error.message,
          cause: error,
        }),
      });
    case "KeyNotFound":
    case "AmbiguousKey":
    case "InvalidKey":
      return tokenFailed("key", error);
    case "SignatureVerificationFailed":
      return tokenFailed("signature");
    case "ClaimValidationFailed":
      if (error.reason.claim === "iss") return tokenFailed("issuer");
      if (error.reason.claim === "aud") return tokenFailed("audience");
      if (error.reason.claim === "typ") return tokenFailed("typ");
      if (error.reason.reason === "expired") return tokenFailed("expired");
      if (error.reason.reason === "notYetValid" || error.reason.reason === "future")
        return tokenFailed("notYetValid");

      return tokenFailed("claim");
  }
};

/** Signed ID tokens using advertised RS256, PS256, ES256, EdDSA, or explicit
 * HS256. Asymmetric verification requires an HTTPS JWKS URL; an HTTP URL
 * fails with `OAuthError` (`InvalidArgument`). Verification and the bounded
 * JWKS cache belong to the caller's Scope. HS256 uses the supplied client
 * secret as the HMAC key and does not install JWKS. Owner closure cancels and
 * joins active verification, failing with `TransportFailed`; caller
 * interruption joins its operation without closing the verifier. Unexpected
 * cleanup failures remain observable in the Cause. No process cache or
 * automatic exchange retry is created. */
export const makeVerifier = Effect.fnUntraced(function* (
  input: VerifierOptions,
): Effect.fn.Return<Verifier, OAuthError.OAuthError, HttpClient.HttpClient | Scope.Scope> {
  const options = yield* V.configuration(
    Configuration,
    input,
    "Invalid OIDC verifier configuration",
  );

  const metadata = V.freeze(options.metadata);
  const audiences = V.freeze([...(options.audiences ?? [options.clientId])]);

  const algorithms = idTokenAlgorithms.filter((algorithm) =>
    (options.algorithms ?? defaultIdTokenAlgorithms).includes(algorithm),
  );

  const advertised = algorithms.filter((algorithm) =>
    metadata.id_token_signing_alg_values_supported?.includes(algorithm),
  );

  const hmacOnly = advertised.length === 1 && advertised[0] === "HS256";

  if (
    advertised.length === 0 ||
    advertised.includes("HS256") !== hmacOnly ||
    !metadata.response_types_supported?.includes("code") ||
    ((options.pkceS256 ?? true) && !metadata.code_challenge_methods_supported?.includes("S256"))
  )
    return yield* V.invalidArgument("OIDC metadata does not support required verification policy");
  if (hmacOnly && options.clientSecret === undefined)
    return yield* V.invalidArgument("HS256 ID token verification requires a client secret");

  const jwksUri = metadata.jwks_uri;

  if (!hmacOnly && (jwksUri === undefined || new URL(jwksUri).protocol !== "https:"))
    return yield* V.invalidArgument("Asymmetric OIDC verification requires an HTTPS jwks_uri");

  const hmacKey =
    hmacOnly && options.clientSecret !== undefined
      ? yield* Jwk.importSecret(
          Redacted.make({
            kty: "oct" as const,
            alg: "HS256" as const,
            k: Base64Url.encode(
              new TextEncoder().encode(
                yield* V.reveal(
                  options.clientSecret,
                  () =>
                    new OAuthError.OAuthError({
                      reason: new OAuthError.ClientAuthFailed({
                        description: "Client secret is unavailable",
                      }),
                    }),
                ),
              ),
            ),
          }),
          "HS256",
        ).pipe(
          Effect.mapError((cause) =>
            V.invalidArgument("Client secret cannot be imported as an HS256 key", cause),
          ),
        )
      : undefined;

  const keys =
    hmacOnly || jwksUri === undefined
      ? undefined
      : yield* OidcJwks.makeRemote({
          url: jwksUri,
          timeoutMs: options.timeoutMs,
          maxResponseBytes: options.maxResponseBytes,
        }).pipe(
          Effect.mapError(
            (cause) =>
              new OAuthError.OAuthError({
                reason: new OAuthError.TransportFailed({
                  endpoint: "jwks",
                  description: "Could not initialize remote JWKS resolver",
                  cause,
                }),
              }),
          ),
        );

  const { use } = yield* Ownership.make("jwks");

  const verify = Effect.fnUntraced(function* (
    token: Redacted.Redacted<string>,
    input: VerificationInput,
  ): Effect.fn.Return<Verified, OAuthError.OAuthError, VerificationRequirements> {
    // Capture caller policy and secret values before key lookup or cryptography.
    const policy = yield* V.decode(VerifyInput, input, () =>
      V.invalidArgument("Invalid OIDC verification input"),
    );

    const credential = yield* V.decode(V.secret(65536), token, () => tokenFailed("malformed"));
    const start = DateTime.toEpochMillis(policy.verificationStartedAt);
    const expectedNonce = yield* V.reveal(policy.nonce);

    const accessToken =
      policy.accessToken === undefined ? undefined : yield* V.reveal(policy.accessToken);

    const code = policy.code === undefined ? undefined : yield* V.reveal(policy.code);

    // Jwt verifies the signature before any registered/application claim checks.
    // Unauthenticated malformed/key/signature failures must never burn a receipt.
    const tenantTemplate = isTenantIssuerTemplate(metadata.issuer);

    const jwtPolicy = {
      ...(tenantTemplate ? {} : { issuer: metadata.issuer }),
      audience: audiences,
      requiredClaims: ["iss", "sub", "aud", "exp", "iat"] as const,
      clockTolerance: 0,
    };

    const opened =
      hmacKey !== undefined
        ? {
            verified: yield* Jwt.verify(JsonObject, credential, hmacKey, jwtPolicy).pipe(
              Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, mapJwtError))),
            ),
            signingKey: undefined,
          }
        : keys === undefined
          ? yield* new OAuthError.OAuthError({
              reason: new OAuthError.TransportFailed({
                endpoint: "jwks",
                description: "No signing key source is configured",
              }),
            })
          : yield* Jwt.verifyWithKeySet(JsonObject, credential, {
              ...jwtPolicy,
              algorithms: advertised.filter((algorithm) => algorithm !== "HS256"),
            }).pipe(
              Effect.provideService(Jwks.Jwks, keys.service),
              Effect.map((verified) => ({ verified, signingKey: verified.key })),
              Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, mapJwtError))),
            );

    const verified = opened.verified;
    const signingKey = opened.signingKey;
    const keyIssuer = signingKey === undefined ? undefined : keys?.issuerOf(signingKey);

    const claims = yield* V.decode(IdClaims, verified.claims, () => tokenFailed("claim"));

    if (tenantTemplate) {
      const tenant = yield* Schema.decodeUnknownEffect(Schema.Struct({ tid: TenantId }))(
        verified.claims,
      ).pipe(Effect.mapError(() => tokenFailed("issuer")));

      const expected = substituteTenantIssuer(metadata.issuer, tenant.tid);

      if (expected === undefined || claims.iss !== expected) return yield* tokenFailed("issuer");
    }

    if (
      tenantTemplate ||
      metadata.signing_key_issuer_required === true ||
      keyIssuer !== undefined
    ) {
      if (verified.protectedHeader.alg === "HS256" || signingKey === undefined)
        return yield* tokenFailed("issuer");

      if (keyIssuer === undefined) return yield* tokenFailed("issuer");

      const allowed = isTenantIssuerTemplate(keyIssuer)
        ? substituteTenantIssuer(
            keyIssuer,
            (yield* Schema.decodeUnknownEffect(Schema.Struct({ tid: TenantId }))(
              verified.claims,
            ).pipe(Effect.mapError(() => tokenFailed("issuer")))).tid,
          )
        : keyIssuer;

      if (allowed !== claims.iss) return yield* tokenFailed("issuer");
    }

    const now = (yield* Clock.currentTimeMillis) / 1000;

    if (start < 0 || start > now * 1000) return yield* tokenFailed("claim");
    if (claims.azp !== undefined && !audiences.includes(claims.azp))
      return yield* tokenFailed("audience");
    if (claims.exp <= now) return yield* tokenFailed("expired");
    if (
      claims.iat > now ||
      (claims.nbf !== undefined && claims.nbf > now) ||
      (claims.auth_time !== undefined && claims.auth_time > now)
    )
      return yield* tokenFailed("notYetValid");
    if (policy.previous === undefined) {
      if (claims.nonce !== expectedNonce) return yield* tokenFailed("nonce");
      if (
        policy.maxAgeSeconds !== undefined &&
        (claims.auth_time === undefined ||
          claims.auth_time + policy.maxAgeSeconds < Math.floor(now))
      )
        return yield* tokenFailed("maxAge");
    } else {
      if (
        claims.sub !== policy.previous.subject ||
        (tenantTemplate
          ? claims.iss !== policy.previous.issuer
          : policy.previous.issuer !== undefined && claims.iss !== policy.previous.issuer)
      )
        return yield* tokenFailed("continuity");
      if (claims.nonce !== undefined && claims.nonce !== expectedNonce)
        return yield* tokenFailed("nonce");
      if (claims.auth_time !== undefined && claims.auth_time !== policy.previous.authTime)
        return yield* tokenFailed("continuity");
    }
    const hashProfile = tokenHash(verified.protectedHeader.alg);

    if (hashProfile === undefined) return yield* tokenFailed("algorithm");

    for (const [hash, secret] of [
      [claims.at_hash, accessToken],
      [claims.c_hash, code],
    ] as const) {
      if (hash === undefined) continue;
      if (secret === undefined) return yield* tokenFailed("hash");
      const digests = yield* Digest.Digest;

      const digest = yield* digests.digest(hashProfile.digest, new TextEncoder().encode(secret));

      if (digest.length !== hashProfile.octets * 2)
        return yield* V.invalidArgument("Digest returned an unexpected byte length");
      if (hash !== Base64Url.encode(digest.subarray(0, hashProfile.octets)))
        return yield* tokenFailed("hash");
    }
    // Re-read time after optional digest I/O so expired tokens cannot escape.
    const finished = (yield* Clock.currentTimeMillis) / 1000;

    if (claims.exp <= finished) return yield* tokenFailed("expired");
    if (
      policy.previous === undefined &&
      policy.maxAgeSeconds !== undefined &&
      claims.auth_time !== undefined &&
      claims.auth_time + policy.maxAgeSeconds < Math.floor(finished)
    )
      return yield* tokenFailed("maxAge");

    return {
      claims: Redacted.make(V.freeze(verified.claims)),
      subject: claims.sub,
      ...(claims.auth_time === undefined
        ? {}
        : {
            authTime: claims.auth_time,
            upstreamAuthenticatedAt: DateTime.makeUnsafe(Math.min(start, claims.auth_time * 1000)),
          }),
    };
  }, use);

  return { verify };
});
