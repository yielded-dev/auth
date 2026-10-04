import * as Jwks from "@yielded/jose/Jwks";
import type * as Jws from "@yielded/jose/Jws";
import * as Jwt from "@yielded/jose/Jwt";
import {
  Clock,
  Context,
  Crypto,
  DateTime,
  Effect,
  Layer,
  Redacted,
  Schema,
  type Scope,
} from "effect";
import { Base64Url } from "effect/encoding";
import { HttpClient, HttpClientRequest } from "effect/http";

import { ConfigurationError, Rejected, Unavailable } from "./Errors";
import * as Ownership from "./internal/ownership";
import * as Transport from "./internal/transport";
import * as V from "./internal/validation";
import { JsonObject, Metadata, type RequestOptions } from "./OAuth";

export interface VerifierOptions extends RequestOptions {
  readonly metadata: Metadata;
  readonly clientId: string;
}

export interface VerificationInput {
  readonly verificationStartedAt: DateTime.Utc;
  readonly nonce: Redacted.Redacted<string>;
  readonly maxAgeSeconds?: number;
  readonly accessToken?: Redacted.Redacted<string>;
  readonly code?: Redacted.Redacted<string>;
  /** Refresh continuation: same subject, optional nonce must match, auth_time cannot change. */
  readonly previous?: { readonly subject: string; readonly authTime?: number };
}

export interface Verified {
  readonly claims: Redacted.Redacted<JsonObject>;
  readonly subject: string;
  readonly authTime?: number;
  readonly upstreamAuthenticatedAt?: DateTime.Utc;
}

export interface Verifier {
  readonly verify: (
    token: Redacted.Redacted<string>,
    input: VerificationInput,
  ) => Effect.Effect<Verified, Rejected | Unavailable, Jws.Requirements | Crypto.Crypto>;
}

const Configuration = Schema.Struct({
  metadata: Metadata,
  clientId: V.text(1024),
  ...V.RequestOptions.fields,
});

const VerifyInput = Schema.Struct({
  verificationStartedAt: Schema.DateTimeUtc,
  nonce: V.secret(256),
  maxAgeSeconds: Schema.optional(V.integer(0, 86400)),
  accessToken: Schema.optional(V.secret(16384)),
  code: Schema.optional(V.secret(16384)),
  previous: Schema.optional(
    Schema.Struct({ subject: V.text(1024), authTime: Schema.optional(V.NumericDate) }),
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
  // The RS256 half digest is 128 bits (22 base64url characters).
  at_hash: Schema.optionalKey(Schema.String.check(Schema.isPattern(/^[A-Za-z0-9_-]{22}$/u))),
  c_hash: Schema.optionalKey(Schema.String.check(Schema.isPattern(/^[A-Za-z0-9_-]{22}$/u))),
});

/** OIDC discovery uses the trusted issuer identifier, retaining its exact
 * spelling for claim comparison even if its network URL normalizes. */
export const discover = Effect.fnUntraced(function* (
  input: string,
  inputOptions: RequestOptions,
): Effect.fn.Return<Metadata, ConfigurationError | Unavailable, HttpClient.HttpClient> {
  const issuer = yield* V.configuration(V.Issuer, input, "issuer");

  const options = yield* V.configuration(V.RequestOptions, inputOptions);

  const url = new URL(issuer);

  url.pathname = `${url.pathname.replace(/\/$/u, "")}/.well-known/openid-configuration`;
  const http = yield* Transport.capture;

  const response = yield* Transport.request(
    http,
    HttpClientRequest.get(url.href).pipe(HttpClientRequest.acceptJson),
    options,
  );

  if (response.status !== 200) return yield* Unavailable.make({});
  const document = yield* Transport.json(response);
  const metadata = yield* V.configuration(Metadata, yield* V.reveal(document.body), "metadata");

  if (metadata.issuer !== issuer) return yield* ConfigurationError.make({ reason: "issuer" });

  return V.freeze(metadata);
});

const claimFailure = () => Rejected.make({ reason: "claims" });

/** RS256-only signed ID tokens. Verification and the bounded JWKS cache belong
 * to the caller's Scope. Owner closure cancels and joins active verification,
 * returning Unavailable; caller interruption joins its operation without closing
 * the verifier. No process cache or automatic exchange retry is created. */
export const makeVerifier = Effect.fnUntraced(function* (
  input: VerifierOptions,
): Effect.fn.Return<
  Verifier,
  ConfigurationError | Unavailable,
  HttpClient.HttpClient | Scope.Scope
> {
  const options = yield* V.configuration(Configuration, input, "metadata");

  const metadata = V.freeze(options.metadata);

  if (
    metadata.jwks_uri === undefined ||
    !metadata.code_challenge_methods_supported?.includes("S256") ||
    !metadata.response_types_supported?.includes("code") ||
    !metadata.id_token_signing_alg_values_supported?.includes("RS256")
  )
    return yield* ConfigurationError.make({ reason: "metadata" });
  const http = yield* Transport.capture;

  const context = yield* Layer.build(
    Jwks.layerRemote({
      url: metadata.jwks_uri,
      timeoutMs: options.timeoutMs,
      maxResponseBytes: options.maxResponseBytes,
    }).pipe(Layer.provide(Layer.succeed(HttpClient.HttpClient, http))),
  ).pipe(Effect.mapError(() => Unavailable.make({})));

  const keys = Context.get(context, Jwks.Jwks);
  const { use } = yield* Ownership.make;

  const verify = Effect.fnUntraced(function* (
    token: Redacted.Redacted<string>,
    input: VerificationInput,
  ): Effect.fn.Return<Verified, Rejected | Unavailable, Jws.Requirements | Crypto.Crypto> {
    // Capture caller policy and secret values before key lookup or cryptography.
    const policy = yield* V.decode(VerifyInput, input);
    const start = DateTime.toEpochMillis(policy.verificationStartedAt);
    const expectedNonce = yield* V.reveal(policy.nonce);

    const accessToken =
      policy.accessToken === undefined ? undefined : yield* V.reveal(policy.accessToken);

    const code = policy.code === undefined ? undefined : yield* V.reveal(policy.code);

    // Jwt verifies the signature before any registered/application claim checks.
    // Unauthenticated malformed/key/signature failures must never burn a receipt.
    const verified = yield* Jwt.verifyWithKeySet(JsonObject, token, {
      algorithms: ["RS256"],
      issuer: metadata.issuer,
      audience: options.clientId,
      requiredClaims: ["iss", "sub", "aud", "exp", "iat"],
      clockTolerance: 0,
    }).pipe(
      Effect.provideService(Jwks.Jwks, keys),
      Effect.mapError((error) =>
        error._tag === "JoseClaimValidationFailed" ? claimFailure() : Unavailable.make({}),
      ),
    );

    const claims = yield* V.decode(IdClaims, verified.claims).pipe(Effect.mapError(claimFailure));

    const now = (yield* Clock.currentTimeMillis) / 1000;
    const audience = typeof claims.aud === "string" ? claims.aud : claims.aud[0];

    if (
      start < 0 ||
      start > now * 1000 ||
      claims.iss !== metadata.issuer ||
      audience !== options.clientId ||
      (claims.azp !== undefined && claims.azp !== options.clientId) ||
      claims.exp <= now ||
      claims.iat > now ||
      (claims.nbf !== undefined && claims.nbf > now) ||
      (claims.auth_time !== undefined && claims.auth_time > now)
    )
      return yield* claimFailure();
    if (policy.previous === undefined) {
      if (
        claims.nonce !== expectedNonce ||
        (policy.maxAgeSeconds !== undefined &&
          (claims.auth_time === undefined ||
            claims.auth_time + policy.maxAgeSeconds < Math.floor(now)))
      )
        return yield* claimFailure();
    } else if (
      claims.sub !== policy.previous.subject ||
      (claims.nonce !== undefined && claims.nonce !== expectedNonce) ||
      (claims.auth_time !== undefined && claims.auth_time !== policy.previous.authTime)
    )
      return yield* claimFailure();
    for (const [hash, secret] of [
      [claims.at_hash, accessToken],
      [claims.c_hash, code],
    ] as const) {
      if (hash === undefined) continue;
      if (secret === undefined) return yield* claimFailure();
      const crypto = yield* Crypto.Crypto;

      const digest = yield* crypto
        .digest("SHA-256", new TextEncoder().encode(secret))
        .pipe(Effect.mapError(() => Unavailable.make({})));

      if (digest.length !== 32) return yield* Unavailable.make({});
      if (hash !== Base64Url.encode(digest.subarray(0, 16))) return yield* claimFailure();
    }
    // Re-read time after optional digest I/O so expired tokens cannot escape.
    const finished = (yield* Clock.currentTimeMillis) / 1000;

    if (
      claims.exp <= finished ||
      (policy.previous === undefined &&
        policy.maxAgeSeconds !== undefined &&
        claims.auth_time !== undefined &&
        claims.auth_time + policy.maxAgeSeconds < Math.floor(finished))
    )
      return yield* claimFailure();

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
