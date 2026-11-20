/**
 * OpenID Connect ID-token verification and UserInfo retrieval.
 *
 * {@link verify} validates an ID token against a known verification key with
 * zero discovery or HTTP dependencies. {@link verifyWithKeySet} resolves an
 * asymmetric public key from `Jwks.Jwks`. {@link Verifier} binds verification
 * policy to `Discovery` and either an explicit `Jwks.Jwks` ({@link makeVerifier}
 * / {@link layerVerifier}) or a lazy, scoped remote key set
 * ({@link makeVerifierRemote} / {@link layerVerifierRemote}).
 * {@link fetchUserInfo} queries the discovered UserInfo endpoint and enforces
 * OIDC Core §5.3.2 subject matching.
 *
 * **Gotchas**
 *
 * `clockTolerance` defaults to `"30 seconds"`. `typ` header validation runs
 * immediately after signature verification and before `exp` or claim checks,
 * accepting omitted `typ` or `"JWT"` / `"application/jwt"` by default.
 * Asymmetric remote verification requires an HTTPS `jwks_uri`.
 *
 * @stability unstable
 * @since 4.1.4
 */
import * as Cause from "effect/Cause";
import * as Clock from "effect/Clock";
import * as Context from "effect/Context";
import * as Digest from "effect/crypto/Digest";
import * as Mac from "effect/crypto/Mac";
import * as Signature from "effect/crypto/Signature";
import * as DateTime from "effect/DateTime";
import * as Deferred from "effect/Deferred";
import type * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Base64Url from "effect/encoding/Base64Url";
import * as Exit from "effect/Exit";
import * as FetchHttpClient from "effect/http/FetchHttpClient";
import * as HttpClient from "effect/http/HttpClient";
import * as HttpClientRequest from "effect/http/HttpClientRequest";
import * as JoseError from "effect/jose/JoseError";
import * as Jwk from "effect/jose/Jwk";
import * as Jwks from "effect/jose/Jwks";
import * as Jws from "effect/jose/Jws";
import * as Layer from "effect/Layer";
import * as Predicate from "effect/Predicate";
import * as Redacted from "effect/Redacted";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import * as Scope from "effect/Scope";
import * as Tracer from "effect/Tracer";

import * as Discovery from "./Discovery.ts";
import * as Ownership from "./internal/ownership.ts";
import * as Transport from "./internal/transport.ts";
import * as V from "./internal/validation.ts";
import * as OAuthError from "./OAuthError.ts";

/**
 * Custom issuer verification policy invoked after signature and registered-claim
 * decoding. Use this for multi-tenant issuers such as Microsoft Entra `{tenantid}`
 * templates or per-key issuer authority checks.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export type IssuerPolicy = (input: {
  readonly configuredIssuer: string;
  readonly tokenIssuer: string;
  readonly claims: Readonly<Record<string, Schema.Json>>;
  readonly signingKey?: Jwk.PublicKey | undefined;
}) => Effect.Effect<void, OAuthError.OAuthError>;

/**
 * Relying-party ID-token verification policy shared across {@link verify},
 * {@link verifyWithKeySet}, and {@link Verifier}.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export interface PolicyOptions {
  /**
   * Primary relying-party client identifier.
   */
  readonly clientId: string;
  /**
   * Additional client identifiers belonging to this relying party (for example
   * multiple native app bundle IDs). A token's `aud` must contain at least one
   * relying-party client ID, and any present `azp` must be one of them.
   */
  readonly alternativeClientIds?: ReadonlyArray<string> | undefined;
  /**
   * Additional trusted co-audiences permitted alongside a relying-party client ID
   * in a multi-audience `aud` array.
   */
  readonly additionalTrustedAudiences?: ReadonlyArray<string> | undefined;
  /**
   * Require `azp` whenever `aud` contains more than one entry. Defaults to `true`.
   */
  readonly requireAzpForMultipleAudiences?: boolean | undefined;
  /**
   * Allowed clock skew for `exp`, `nbf`, `iat`, `auth_time`, and `requestedAt`.
   * Defaults to `"30 seconds"`.
   */
  readonly clockTolerance?: Duration.Input | undefined;
  /**
   * Permitted protected-header `typ` values (normalized case-insensitively with
   * RFC 7515 `application/` media-type defaulting). Defaults to `["JWT"]`.
   */
  readonly allowedTyp?: ReadonlyArray<string> | undefined;
  /**
   * Reject ID tokens that omit the protected-header `typ` parameter.
   * Defaults to `false`.
   */
  readonly requireTyp?: boolean | undefined;
  /**
   * Maximum compact ID-token length in characters. Defaults to `65536`.
   */
  readonly maxTokenLength?: number | undefined;
  /**
   * Custom issuer validation policy. Defaults to exact equality between
   * `tokenIssuer` and `configuredIssuer`.
   */
  readonly issuerPolicy?: IssuerPolicy | undefined;
}

/**
 * Per-verification inputs binding an ID token to an authorization ceremony,
 * refresh continuation, or companion tokens.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export interface VerifyOptions {
  /**
   * Expected `nonce` claim. When omitted on an initial flow, any present
   * `nonce` claim is rejected.
   */
  readonly nonce?: string | Redacted.Redacted<string> | undefined;
  /**
   * Requested `max_age` freshness bound. Must be a non-negative whole-second
   * duration. Skipped when `previous` is provided.
   */
  readonly maxAge?: Duration.Input | undefined;
  /**
   * Instant the authorization request was initiated, used to anchor `max_age`
   * checks so interactive login duration does not falsely trip `max_age=0`.
   */
  readonly requestedAt?: DateTime.Utc | undefined;
  /**
   * Access token returned alongside the ID token, verified against `at_hash`
   * when both are present.
   */
  readonly accessToken?: string | Redacted.Redacted<string> | undefined;
  /**
   * Authorization code associated with the ID token, verified against `c_hash`
   * when both are present.
   */
  readonly code?: string | Redacted.Redacted<string> | undefined;
  /**
   * Require both `code` and the token's `c_hash` claim (for Hybrid or front-channel
   * ID tokens). Defaults to `false`.
   */
  readonly requireCodeHash?: boolean | undefined;
  /**
   * Continuity expectations for an ID token returned by a refresh-token grant
   * (OIDC Core §12.2).
   */
  readonly previous?:
    | {
        readonly subject: string;
        readonly issuer: string;
        readonly audience: string | ReadonlyArray<string>;
        readonly nonce?: string | Redacted.Redacted<string> | undefined;
        readonly authTime?: number | undefined;
      }
    | undefined;
}

/**
 * Verified ID-token identity, registered claims, and authenticated header.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export interface VerifiedIdToken {
  readonly subject: string;
  readonly issuer: string;
  readonly audience: ReadonlyArray<string>;
  readonly claims: Redacted.Redacted<Readonly<Record<string, Schema.Json>>>;
  readonly protectedHeader: Jws.ProtectedHeader;
  readonly authTime?: number | undefined;
  readonly authenticatedAt?: DateTime.Utc | undefined;
}

/**
 * Options for {@link makeVerifier}, {@link layerVerifier},
 * {@link makeVerifierRemote}, and {@link layerVerifierRemote}.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export interface VerifierOptions extends PolicyOptions {
  /**
   * Permitted asymmetric JWS algorithms. Defaults to all asymmetric JWK
   * algorithms supported by `effect/jose`, intersected with
   * `id_token_signing_alg_values_supported` when advertised by discovery.
   */
  readonly algorithms?: ReadonlyArray<Jwk.AsymmetricAlgorithm> | undefined;
}

/**
 * Scoped OpenID Connect ID-token verifier bound to a `Discovery` service and
 * verification key source.
 *
 * @stability unstable
 * @category services
 * @since 4.1.4
 */
export class Verifier extends Context.Service<
  Verifier,
  {
    readonly verify: (
      idToken: string | Redacted.Redacted<string>,
      options?: VerifyOptions,
    ) => Effect.Effect<VerifiedIdToken, OAuthError.OAuthError>;
  }
>()("effect/oauth/Oidc/Verifier") {}

const defaultAsymmetricAlgorithms: ReadonlyArray<Jwk.AsymmetricAlgorithm> = [
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512",
  "EdDSA",
];

const isAsymmetricAlgorithm = Schema.is(Jwk.AsymmetricAlgorithm);
const utf8Encoder = new TextEncoder();

const IdClaims = Schema.Struct({
  iss: V.text(2048),
  sub: V.text(1024),
  aud: Schema.Union([
    V.text(1024),
    Schema.Array(V.text(1024)).check(Schema.isMinLength(1), Schema.isMaxLength(64)),
  ]),
  azp: Schema.optionalKey(V.text(1024)),
  exp: V.NumericDate,
  iat: V.NumericDate,
  nbf: Schema.optionalKey(V.NumericDate),
  auth_time: Schema.optionalKey(V.NumericDate),
  nonce: Schema.optionalKey(V.text(4096)),
  at_hash: Schema.optionalKey(V.text(128)),
  c_hash: Schema.optionalKey(V.text(128)),
});

interface ParsedPolicy {
  readonly rpClientIds: ReadonlySet<string>;
  readonly trustedAudiences: ReadonlySet<string>;
  readonly requireAzpForMultipleAudiences: boolean;
  readonly clockToleranceMillis: number;
  readonly allowedTyp: ReadonlySet<string>;
  readonly requireTyp: boolean;
  readonly maxTokenLength: number;
  readonly issuerPolicy: IssuerPolicy | undefined;
}

interface ParsedVerifyInput {
  readonly nonce: string | undefined;
  readonly maxAgeSeconds: number | undefined;
  readonly requestedAtMillis: number | undefined;
  readonly accessToken: string | undefined;
  readonly code: string | undefined;
  readonly requireCodeHash: boolean;
  readonly previous:
    | {
        readonly subject: string;
        readonly issuer: string;
        readonly audience: ReadonlyArray<string>;
        readonly nonce: string | undefined;
        readonly authTime: number | undefined;
      }
    | undefined;
}

const tokenFailed = (
  reason: OAuthError.TokenVerificationFailed["reason"],
  cause?: unknown,
): OAuthError.OAuthError =>
  new OAuthError.OAuthError({
    reason: new OAuthError.TokenVerificationFailed({
      reason,
      ...(cause === undefined ? {} : { cause }),
    }),
  });

const jwksTransportFailed = (description: string, cause?: unknown): OAuthError.OAuthError =>
  new OAuthError.OAuthError({
    reason: new OAuthError.TransportFailed({
      endpoint: "jwks",
      description,
      ...(cause === undefined ? {} : { cause }),
    }),
  });

const mediaTypeToken = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;

const normalizeMediaType = (value: string): string | undefined => {
  const lower = value.toLowerCase();
  const slash = lower.indexOf("/");

  if (slash === -1) {
    return mediaTypeToken.test(lower) ? `application/${lower}` : undefined;
  }

  const type = lower.slice(0, slash);
  const subtype = lower.slice(slash + 1);

  return mediaTypeToken.test(type) && mediaTypeToken.test(subtype)
    ? `${type}/${subtype}`
    : undefined;
};

const isWellFormedString = (value: string): boolean => {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);

    if (code >= 0xd800 && code <= 0xdbff) {
      if (index + 1 >= value.length) return false;
      const next = value.charCodeAt(index + 1);

      if (next < 0xdc00 || next > 0xdfff) return false;
      index++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }

  return true;
};

const isCanonicalBase64Url = (segment: string): boolean => {
  if (segment.length === 0 || /[^A-Za-z0-9_-]/u.test(segment)) return false;
  const remainder = segment.length % 4;
  const last = segment.charAt(segment.length - 1);

  return (
    remainder === 0 ||
    (remainder === 2 ? "AQgw".includes(last) : remainder === 3 && "AEIMQUYcgkosw048".includes(last))
  );
};

const decodeHashBytes = (value: string, expectedLength: number): Uint8Array | undefined => {
  if (!isCanonicalBase64Url(value)) return undefined;
  const decoded = Base64Url.decode(value);

  return Result.isSuccess(decoded) && decoded.success.length === expectedLength
    ? decoded.success
    : undefined;
};

const constantTimeEqual = (left: string, right: string): boolean =>
  isWellFormedString(left) &&
  isWellFormedString(right) &&
  Mac.timingSafeEqual(utf8Encoder.encode(left), utf8Encoder.encode(right));

const sameStringSet = (left: ReadonlyArray<string>, right: ReadonlyArray<string>): boolean => {
  const leftSet = new Set(left);
  const rightSet = new Set(right);

  if (leftSet.size !== rightSet.size) return false;
  for (const value of leftSet) {
    if (!rightSet.has(value)) return false;
  }

  return true;
};

const tokenHashProfile = (
  algorithm: Jwk.Algorithm,
): { readonly algorithm: Digest.Algorithm; readonly octets: number } => {
  switch (algorithm) {
    case "RS256":
    case "PS256":
    case "ES256":
    case "HS256":
      return { algorithm: Digest.sha256, octets: 16 };
    case "RS384":
    case "PS384":
    case "ES384":
    case "HS384":
      return { algorithm: Digest.sha384, octets: 24 };
    case "RS512":
    case "PS512":
    case "ES512":
    case "HS512":
    case "EdDSA":
      return { algorithm: Digest.sha512, octets: 32 };
  }
};

const revealString = (
  value: string | Redacted.Redacted<string>,
  onError: () => OAuthError.OAuthError,
): Effect.Effect<string, OAuthError.OAuthError> =>
  Redacted.isRedacted(value)
    ? V.reveal(value, onError).pipe(
        Effect.filterOrFail((text): text is string => typeof text === "string", onError),
      )
    : typeof value === "string"
      ? Effect.succeed(value)
      : Effect.fail(onError());

const decodeNonEmptySecret = (
  value: string | Redacted.Redacted<string>,
  maxLength: number,
  name: string,
): Effect.Effect<string, OAuthError.OAuthError> =>
  revealString(value, () => V.invalidArgument(`${name} is unavailable`)).pipe(
    Effect.filterOrFail(
      (text) => text.length > 0 && text.length <= maxLength,
      () => V.invalidArgument(`${name} must be a non-empty string`),
    ),
  );

const parseStringList = Effect.fnUntraced(function* (
  name: string,
  values: ReadonlyArray<string> | undefined,
  maxItems: number,
  maxLength: number,
  requireNonEmpty: boolean,
): Effect.fn.Return<ReadonlyArray<string>, OAuthError.OAuthError> {
  if (values === undefined) return [];
  if (!Array.isArray(values) || values.length > maxItems) {
    return yield* V.invalidArgument(`Invalid ${name}`);
  }
  if (requireNonEmpty && values.length === 0) {
    return yield* V.invalidArgument(`${name} must not be empty`);
  }

  const copy: Array<string> = [];

  for (const item of values) {
    if (typeof item !== "string" || item.length === 0 || item.length > maxLength) {
      return yield* V.invalidArgument(`Invalid entry in ${name}`);
    }
    copy.push(item);
  }

  return copy;
});

const parsePolicy = Effect.fnUntraced(function* (
  options: PolicyOptions,
): Effect.fn.Return<ParsedPolicy, OAuthError.OAuthError> {
  if (!Predicate.isObject(options)) {
    return yield* V.invalidArgument("Invalid OIDC verification options");
  }

  const clientId = yield* V.configuration(V.text(1024), options.clientId, "Invalid OIDC clientId");

  const alternativeClientIds = yield* parseStringList(
    "alternativeClientIds",
    options.alternativeClientIds,
    64,
    1024,
    false,
  );

  const additionalTrustedAudiences = yield* parseStringList(
    "additionalTrustedAudiences",
    options.additionalTrustedAudiences,
    64,
    1024,
    false,
  );

  if (
    options.requireAzpForMultipleAudiences !== undefined &&
    typeof options.requireAzpForMultipleAudiences !== "boolean"
  ) {
    return yield* V.invalidArgument("requireAzpForMultipleAudiences must be a boolean");
  }

  if (options.requireTyp !== undefined && typeof options.requireTyp !== "boolean") {
    return yield* V.invalidArgument("requireTyp must be a boolean");
  }

  const clockToleranceMillis = yield* V.finiteMillis(
    "clockTolerance",
    options.clockTolerance ?? "30 seconds",
  );

  const allowedTypList =
    options.allowedTyp === undefined
      ? ["JWT"]
      : yield* parseStringList("allowedTyp", options.allowedTyp, 64, 256, true);

  const allowedTyp = new Set<string>();

  for (const entry of allowedTypList) {
    const normalized = normalizeMediaType(entry);

    if (normalized === undefined) {
      return yield* V.invalidArgument("Invalid entry in allowedTyp");
    }
    allowedTyp.add(normalized);
  }

  const maxTokenLength = yield* V.positiveInteger(
    "maxTokenLength",
    options.maxTokenLength ?? 65536,
  );

  if (options.issuerPolicy !== undefined && !Predicate.isFunction(options.issuerPolicy)) {
    return yield* V.invalidArgument("issuerPolicy must be a function");
  }

  const rpClientIds = new Set<string>([clientId, ...alternativeClientIds]);
  const trustedAudiences = new Set<string>([...rpClientIds, ...additionalTrustedAudiences]);

  return {
    rpClientIds,
    trustedAudiences,
    requireAzpForMultipleAudiences: options.requireAzpForMultipleAudiences ?? true,
    clockToleranceMillis,
    allowedTyp,
    requireTyp: options.requireTyp ?? false,
    maxTokenLength,
    issuerPolicy: options.issuerPolicy,
  };
});

const parseAlgorithms = Effect.fnUntraced(function* (
  algorithms: ReadonlyArray<Jwk.AsymmetricAlgorithm> | undefined,
): Effect.fn.Return<ReadonlyArray<Jwk.AsymmetricAlgorithm>, OAuthError.OAuthError> {
  if (algorithms === undefined) return defaultAsymmetricAlgorithms;
  if (!Array.isArray(algorithms) || algorithms.length === 0 || algorithms.length > 16) {
    return yield* V.invalidArgument("algorithms must be a non-empty list of asymmetric algorithms");
  }

  const copy: Array<Jwk.AsymmetricAlgorithm> = [];

  for (const algorithm of algorithms) {
    if (!isAsymmetricAlgorithm(algorithm)) {
      return yield* V.invalidArgument("Unsupported asymmetric JWS algorithm");
    }
    if (!copy.includes(algorithm)) copy.push(algorithm);
  }

  return copy;
});

const parseVerifyOptions = Effect.fnUntraced(function* (
  options: VerifyOptions | undefined,
): Effect.fn.Return<ParsedVerifyInput, OAuthError.OAuthError> {
  if (options === undefined) {
    return {
      nonce: undefined,
      maxAgeSeconds: undefined,
      requestedAtMillis: undefined,
      accessToken: undefined,
      code: undefined,
      requireCodeHash: false,
      previous: undefined,
    };
  }
  const rawOptions: unknown = options;

  if (!Predicate.isObject(rawOptions)) {
    return yield* V.invalidArgument("Invalid OIDC verification input");
  }

  const nonce =
    options.nonce === undefined
      ? undefined
      : yield* decodeNonEmptySecret(options.nonce, 4096, "nonce").pipe(
          Effect.filterOrFail(isWellFormedString, () =>
            V.invalidArgument("nonce must be a well-formed Unicode string"),
          ),
        );

  const maxAgeSeconds =
    options.maxAge === undefined ? undefined : yield* V.wholeSeconds("maxAge", options.maxAge);

  let requestedAtMillis: number | undefined;

  if (options.requestedAt !== undefined) {
    if (!DateTime.isDateTime(options.requestedAt)) {
      return yield* V.invalidArgument("requestedAt must be a DateTime.Utc");
    }
    const millis = DateTime.toEpochMillis(options.requestedAt);

    if (!Number.isFinite(millis) || millis < 0) {
      return yield* V.invalidArgument("requestedAt must be a non-negative instant");
    }
    requestedAtMillis = millis;
  }

  const accessToken =
    options.accessToken === undefined
      ? undefined
      : yield* decodeNonEmptySecret(options.accessToken, 16384, "accessToken");

  const code =
    options.code === undefined
      ? undefined
      : yield* decodeNonEmptySecret(options.code, 16384, "code");

  if (options.requireCodeHash !== undefined && typeof options.requireCodeHash !== "boolean") {
    return yield* V.invalidArgument("requireCodeHash must be a boolean");
  }

  let previous: ParsedVerifyInput["previous"];

  if (options.previous !== undefined) {
    const rawPrevious: unknown = options.previous;

    if (!Predicate.isObject(rawPrevious)) {
      return yield* V.invalidArgument("Invalid previous ID-token continuity input");
    }

    const subject = yield* V.configuration(
      V.text(1024),
      options.previous.subject,
      "Invalid previous.subject",
    );

    const issuer = yield* V.configuration(
      V.text(2048),
      options.previous.issuer,
      "Invalid previous.issuer",
    );

    const audience =
      typeof options.previous.audience === "string"
        ? [
            yield* V.configuration(
              V.text(1024),
              options.previous.audience,
              "Invalid previous.audience",
            ),
          ]
        : yield* parseStringList("previous.audience", options.previous.audience, 64, 1024, true);

    const previousNonce =
      options.previous.nonce === undefined
        ? undefined
        : yield* decodeNonEmptySecret(options.previous.nonce, 4096, "previous.nonce").pipe(
            Effect.filterOrFail(isWellFormedString, () =>
              V.invalidArgument("previous.nonce must be a well-formed Unicode string"),
            ),
          );

    const authTime =
      options.previous.authTime === undefined
        ? undefined
        : yield* V.configuration(
            V.NumericDate,
            options.previous.authTime,
            "Invalid previous.authTime",
          );

    previous = {
      subject,
      issuer,
      audience,
      nonce: previousNonce,
      authTime,
    };
  }

  return {
    nonce,
    maxAgeSeconds,
    requestedAtMillis,
    accessToken,
    code,
    requireCodeHash: options.requireCodeHash ?? false,
    previous,
  };
});

const mapJwsError = (error: JoseError.JoseError): OAuthError.OAuthError => {
  switch (error.reason._tag) {
    case "InvalidToken":
    case "InvalidArgument":
    case "DecryptionFailed":
      return tokenFailed("malformed", error);
    case "AlgorithmNotAllowed":
      return tokenFailed("algorithm", error);
    case "KeySetUnavailable":
      return jwksTransportFailed(error.message, error);
    case "KeyNotFound":
    case "AmbiguousKey":
    case "InvalidKey":
    case "ClaimValidationFailed":
      return tokenFailed("key", error);
    case "SignatureVerificationFailed":
      return tokenFailed("signature");
  }
};

// Normalize unexpected JOSE error reasons from a custom `Jwks.Jwks` resolver
// at the key-resolution boundary so pre-signature faults can never masquerade
// as post-signature claim failures.
const guardKeySet = (jwks: Jwks.Jwks["Service"]): Jwks.Jwks["Service"] =>
  Jwks.Jwks.of({
    resolve: (selection) =>
      jwks.resolve(selection).pipe(
        Effect.catchCause((cause) =>
          Effect.failCause(
            Cause.map(cause, (error) => {
              switch (error.reason._tag) {
                case "KeyNotFound":
                case "AmbiguousKey":
                case "InvalidKey":
                case "KeySetUnavailable":
                  return error;
                case "InvalidToken":
                case "InvalidArgument":
                case "AlgorithmNotAllowed":
                case "SignatureVerificationFailed":
                case "DecryptionFailed":
                case "ClaimValidationFailed":
                  return new JoseError.JoseError({
                    reason: new JoseError.InvalidKey({
                      description: error.message,
                      cause: error,
                    }),
                  });
              }
            }),
          ),
        ),
      ),
  });

const isAuthTimeTooOld = (
  authTime: number,
  referenceMillis: number,
  maxAgeSeconds: number,
  clockToleranceMillis: number,
): boolean => {
  const cutoffMillis = referenceMillis - maxAgeSeconds * 1000 - clockToleranceMillis;

  return Number.isInteger(authTime)
    ? authTime < Math.floor(cutoffMillis / 1000)
    : authTime < cutoffMillis / 1000;
};

const authTimeMillis = (authTime: number): number => {
  const rounded = Math.round(authTime * 1000);

  return rounded / 1000 === authTime ? rounded : Math.trunc(authTime * 1000);
};

const verifyTokenPayload = Effect.fnUntraced(function* (
  verified: Jws.Verified,
  signingKey: Jwk.PublicKey | undefined,
  configuredIssuer: string,
  policy: ParsedPolicy,
  input: ParsedVerifyInput,
): Effect.fn.Return<VerifiedIdToken, OAuthError.OAuthError, Digest.Digest> {
  const protectedHeaderSnapshot = yield* V.snapshotPlainJson(verified.protectedHeader, () =>
    tokenFailed("malformed"),
  );

  const protectedHeader = V.freeze(
    yield* V.decode(Jws.ProtectedHeader, protectedHeaderSnapshot, () => tokenFailed("malformed")),
  );

  // 1. typ check immediately after signature verification, before JSON/exp/claim checks.
  const typ = protectedHeader.typ;

  if (typ === undefined) {
    if (policy.requireTyp) return yield* tokenFailed("typ");
  } else {
    const normalizedTyp = normalizeMediaType(typ);

    if (normalizedTyp === undefined || !policy.allowedTyp.has(normalizedTyp)) {
      return yield* tokenFailed("typ");
    }
  }

  // 2. JSON & registered claim schema decoding (descriptor-safe plain JSON snapshot).
  const payloadText = yield* Effect.try({
    try: () => new TextDecoder("utf-8", { fatal: true }).decode(verified.payload),
    catch: () => tokenFailed("claim"),
  });

  const parsedPayload = yield* Schema.decodeEffect(Schema.fromJsonString(Schema.Unknown))(
    payloadText,
    { reportInput: false },
  ).pipe(Effect.mapError(() => tokenFailed("claim")));

  const rawClaims = V.freeze(yield* V.snapshotPlainJson(parsedPayload, () => tokenFailed("claim")));

  const claims = yield* V.decode(IdClaims, rawClaims, () => tokenFailed("claim"));

  // 3. Issuer policy.
  if (policy.issuerPolicy !== undefined) {
    yield* policy.issuerPolicy({
      configuredIssuer,
      tokenIssuer: claims.iss,
      claims: rawClaims,
      ...(signingKey === undefined ? {} : { signingKey }),
    });
  } else if (claims.iss !== configuredIssuer) {
    return yield* tokenFailed("issuer");
  }

  // 4. Audience and azp checks (OIDC Core §3.1.3.7 Rules 3-5).
  const audiences: ReadonlyArray<string> =
    typeof claims.aud === "string" ? [claims.aud] : claims.aud;

  if (
    !audiences.some((audience) => policy.rpClientIds.has(audience)) ||
    !audiences.every((audience) => policy.trustedAudiences.has(audience))
  ) {
    return yield* tokenFailed("audience");
  }

  if (claims.azp !== undefined && !policy.rpClientIds.has(claims.azp)) {
    return yield* tokenFailed("audience");
  }

  if (policy.requireAzpForMultipleAudiences && audiences.length > 1 && claims.azp === undefined) {
    return yield* tokenFailed("audience");
  }

  // 5. Time claims: exp, nbf, iat, and future auth_time.
  const nowMillis = yield* Clock.currentTimeMillis;
  const minExp = (nowMillis - policy.clockToleranceMillis) / 1000;
  const maxIssuedAt = (nowMillis + policy.clockToleranceMillis) / 1000;

  if (claims.exp <= minExp) {
    return yield* tokenFailed("expired");
  }

  if (
    (claims.nbf !== undefined && claims.nbf > maxIssuedAt) ||
    claims.iat > maxIssuedAt ||
    (claims.auth_time !== undefined && claims.auth_time > maxIssuedAt)
  ) {
    return yield* tokenFailed("notYetValid");
  }

  // 6. Nonce and refresh continuity (OIDC Core §3.1.3.7 Rule 11 & §12.2).
  if (input.previous === undefined) {
    if (input.nonce !== undefined) {
      if (claims.nonce === undefined || !constantTimeEqual(claims.nonce, input.nonce)) {
        return yield* tokenFailed("nonce");
      }
    } else if (claims.nonce !== undefined) {
      return yield* tokenFailed("nonce");
    }

    // 7. max_age freshness (initial flow only).
    if (input.maxAgeSeconds !== undefined) {
      if (
        input.requestedAtMillis !== undefined &&
        input.requestedAtMillis > nowMillis + policy.clockToleranceMillis
      ) {
        return yield* tokenFailed("maxAge");
      }
      if (claims.auth_time === undefined) {
        return yield* tokenFailed("maxAge");
      }

      if (
        isAuthTimeTooOld(
          claims.auth_time,
          input.requestedAtMillis ?? nowMillis,
          input.maxAgeSeconds,
          policy.clockToleranceMillis,
        )
      ) {
        return yield* tokenFailed("maxAge");
      }
    }
  } else {
    if (
      claims.iss !== input.previous.issuer ||
      claims.sub !== input.previous.subject ||
      !sameStringSet(audiences, input.previous.audience)
    ) {
      return yield* tokenFailed("continuity");
    }

    if (claims.nonce !== undefined) {
      const expectedNonce = input.previous.nonce ?? input.nonce;

      if (expectedNonce === undefined || !constantTimeEqual(claims.nonce, expectedNonce)) {
        return yield* tokenFailed("nonce");
      }
    }

    if (
      input.previous.authTime !== undefined &&
      claims.auth_time !== undefined &&
      claims.auth_time !== input.previous.authTime
    ) {
      return yield* tokenFailed("continuity");
    }
  }

  // 8. at_hash and c_hash (OIDC Core §3.1.3.6, §3.1.3.8, §3.3.2.11).
  const hashProfile = tokenHashProfile(protectedHeader.alg);

  const checkHash = Effect.fnUntraced(function* (claimValue: string, secret: string) {
    const expectedBytes = decodeHashBytes(claimValue, hashProfile.octets);

    if (expectedBytes === undefined) {
      return yield* tokenFailed("hash");
    }
    const digests = yield* Digest.Digest;

    const digest = yield* digests
      .digest(hashProfile.algorithm, utf8Encoder.encode(secret))
      .pipe(Effect.mapError((cause) => tokenFailed("hash", cause)));

    if (digest.length !== hashProfile.octets * 2) {
      return yield* V.invalidArgument("Digest returned an unexpected byte length");
    }

    if (!Mac.timingSafeEqual(expectedBytes, digest.subarray(0, hashProfile.octets))) {
      return yield* tokenFailed("hash");
    }
  });

  if (input.accessToken !== undefined && claims.at_hash !== undefined) {
    yield* checkHash(claims.at_hash, input.accessToken);
  }

  if (input.requireCodeHash) {
    if (input.code === undefined || claims.c_hash === undefined) {
      return yield* tokenFailed("hash");
    }
    yield* checkHash(claims.c_hash, input.code);
  } else if (input.code !== undefined && claims.c_hash !== undefined) {
    yield* checkHash(claims.c_hash, input.code);
  }

  // Re-read time after optional digest I/O so expired tokens cannot escape.
  const finishedMillis = yield* Clock.currentTimeMillis;

  if (claims.exp <= (finishedMillis - policy.clockToleranceMillis) / 1000) {
    return yield* tokenFailed("expired");
  }
  if (
    input.previous === undefined &&
    input.maxAgeSeconds !== undefined &&
    input.requestedAtMillis === undefined &&
    claims.auth_time !== undefined &&
    isAuthTimeTooOld(
      claims.auth_time,
      finishedMillis,
      input.maxAgeSeconds,
      policy.clockToleranceMillis,
    )
  ) {
    return yield* tokenFailed("maxAge");
  }

  return {
    subject: claims.sub,
    issuer: claims.iss,
    audience: V.freeze([...audiences]),
    claims: Redacted.make(rawClaims),
    protectedHeader,
    ...(claims.auth_time === undefined
      ? {}
      : {
          authTime: claims.auth_time,
          authenticatedAt: DateTime.makeUnsafe(
            Math.min(nowMillis, authTimeMillis(claims.auth_time)),
          ),
        }),
  };
});

const decodeTokenString = (
  idToken: string | Redacted.Redacted<string>,
  maxTokenLength: number,
): Effect.Effect<string, OAuthError.OAuthError> =>
  revealString(idToken, () => tokenFailed("malformed")).pipe(
    Effect.filterOrFail(
      (token) => token.length > 0 && token.length <= maxTokenLength,
      () => tokenFailed("malformed"),
    ),
  );

// Enforces §3.10 token format and header checks before discovery or key-source
// I/O so malformed tokens fail locally and never mask `malformed` with discovery
// or missing-`jwks_uri` errors.
const checkCompactFormat = (
  rawToken: string,
): Effect.Effect<Jws.ProtectedHeader, OAuthError.OAuthError> => {
  const parts = rawToken.split(".");

  if (parts.length !== 3) return Effect.fail(tokenFailed("malformed"));
  const headerSegment = parts[0];
  const payloadSegment = parts[1];
  const signatureSegment = parts[2];

  if (
    headerSegment === undefined ||
    payloadSegment === undefined ||
    signatureSegment === undefined ||
    !isCanonicalBase64Url(headerSegment) ||
    !isCanonicalBase64Url(payloadSegment) ||
    !isCanonicalBase64Url(signatureSegment)
  ) {
    return Effect.fail(tokenFailed("malformed"));
  }
  const decodedHeader = Base64Url.decode(headerSegment);

  if (Result.isFailure(decodedHeader)) return Effect.fail(tokenFailed("malformed"));

  let headerText: string;

  try {
    headerText = new TextDecoder("utf-8", { fatal: true }).decode(decodedHeader.success);
  } catch {
    return Effect.fail(tokenFailed("malformed"));
  }

  return Schema.decodeEffect(Schema.fromJsonString(Schema.Unknown))(headerText, {
    reportInput: false,
  }).pipe(
    Effect.mapError(() => tokenFailed("malformed")),
    Effect.flatMap((parsed) => V.snapshotPlainJson(parsed, () => tokenFailed("malformed"))),
    Effect.filterOrFail(
      (snapshot) => !Object.hasOwn(snapshot, "crit") && !Object.hasOwn(snapshot, "b64"),
      () => tokenFailed("malformed"),
    ),
    Effect.flatMap((snapshot) =>
      V.decode(Jws.ProtectedHeader, snapshot, () => tokenFailed("malformed")),
    ),
  );
};

/**
 * Verifies a compact ID token with a known verification key (`Jwk.PublicKey`
 * or `Jwk.SecretKey<Jwk.HmacAlgorithm>`). Requires no `Discovery` or
 * `HttpClient` service.
 *
 * @see {@link verifyWithKeySet} for verifying against a `Jwks.Jwks` service
 *
 * @stability unstable
 * @category verification
 * @since 4.1.4
 */
export const verify: <K extends Jwk.VerificationKey>(
  idToken: string | Redacted.Redacted<string>,
  key: K,
  options: PolicyOptions & VerifyOptions & { readonly issuer: string },
) => Effect.Effect<VerifiedIdToken, OAuthError.OAuthError, Jws.KeyRequirements<K> | Digest.Digest> =
  Effect.fnUntraced(function* <K extends Jwk.VerificationKey>(
    idToken: string | Redacted.Redacted<string>,
    key: K,
    options: PolicyOptions & VerifyOptions & { readonly issuer: string },
  ): Effect.fn.Return<
    VerifiedIdToken,
    OAuthError.OAuthError,
    Jws.KeyRequirements<K> | Digest.Digest
  > {
    const rawKey: unknown = key;

    if (!Predicate.isObject(rawKey)) {
      return yield* V.invalidArgument("Invalid OIDC verification key");
    }
    const policy = yield* parsePolicy(options);

    const configuredIssuer = yield* V.configuration(
      V.Issuer,
      options.issuer,
      "Invalid OIDC issuer",
    );

    const input = yield* parseVerifyOptions(options);
    const rawToken = yield* decodeTokenString(idToken, policy.maxTokenLength);

    const verified = yield* Jws.verify(rawToken, key).pipe(
      Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, mapJwsError))),
    );

    const verificationKey: Jwk.VerificationKey = key;
    const signingKey = verificationKey._tag === "PublicKey" ? verificationKey : undefined;

    return yield* verifyTokenPayload(verified, signingKey, configuredIssuer, policy, input);
  });

const verifyWithKeySetInternal = Effect.fnUntraced(function* (
  rawToken: string,
  header: Jws.ProtectedHeader,
  configuredIssuer: string,
  policy: ParsedPolicy,
  algorithms: ReadonlyArray<Jwk.AsymmetricAlgorithm>,
  input: ParsedVerifyInput,
): Effect.fn.Return<
  VerifiedIdToken,
  OAuthError.OAuthError,
  Jwks.Jwks | Signature.Signature | Digest.Digest
> {
  if (
    algorithms.length === 0 ||
    !isAsymmetricAlgorithm(header.alg) ||
    !algorithms.includes(header.alg)
  ) {
    return yield* tokenFailed("algorithm");
  }

  const keySet = guardKeySet(yield* Jwks.Jwks);

  const verified = yield* Jws.verifyWithKeySet(rawToken, { algorithms }).pipe(
    Effect.provideService(Jwks.Jwks, keySet),
    Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, mapJwsError))),
  );

  return yield* verifyTokenPayload(verified, verified.key, configuredIssuer, policy, input);
});

/**
 * Verifies a compact ID token with an asymmetric public key resolved from
 * `Jwks.Jwks`. Requires no `Discovery` or `HttpClient` service.
 *
 * @see {@link verify} for verifying with a known key
 * @see {@link makeVerifier} for a `Discovery`-bound verifier service
 *
 * @stability unstable
 * @category verification
 * @since 4.1.4
 */
export const verifyWithKeySet: (
  idToken: string | Redacted.Redacted<string>,
  options: PolicyOptions &
    VerifyOptions & {
      readonly issuer: string;
      readonly algorithms?: ReadonlyArray<Jwk.AsymmetricAlgorithm> | undefined;
    },
) => Effect.Effect<
  VerifiedIdToken,
  OAuthError.OAuthError,
  Jwks.Jwks | Signature.Signature | Digest.Digest
> = Effect.fnUntraced(function* (
  idToken: string | Redacted.Redacted<string>,
  options: PolicyOptions &
    VerifyOptions & {
      readonly issuer: string;
      readonly algorithms?: ReadonlyArray<Jwk.AsymmetricAlgorithm> | undefined;
    },
): Effect.fn.Return<
  VerifiedIdToken,
  OAuthError.OAuthError,
  Jwks.Jwks | Signature.Signature | Digest.Digest
> {
  const policy = yield* parsePolicy(options);
  const configuredIssuer = yield* V.configuration(V.Issuer, options.issuer, "Invalid OIDC issuer");
  const algorithms = yield* parseAlgorithms(options.algorithms);
  const input = yield* parseVerifyOptions(options);
  const rawToken = yield* decodeTokenString(idToken, policy.maxTokenLength);
  const header = yield* checkCompactFormat(rawToken);

  return yield* verifyWithKeySetInternal(
    rawToken,
    header,
    configuredIssuer,
    policy,
    algorithms,
    input,
  );
});

const effectiveAlgorithmsFor = (
  configured: ReadonlyArray<Jwk.AsymmetricAlgorithm>,
  metadata: Discovery.Metadata,
): ReadonlyArray<Jwk.AsymmetricAlgorithm> => {
  const advertised = metadata.id_token_signing_alg_values_supported;

  return advertised === undefined
    ? configured
    : configured.filter((algorithm) => advertised.includes(algorithm));
};

/**
 * Builds a scoped {@link Verifier} service backed by `Discovery` and a
 * caller-supplied `Jwks.Jwks` service.
 *
 * Options are validated eagerly with zero network I/O during construction.
 * Closing the owning `Scope` interrupts and joins in-flight verifications and
 * rejects later calls with `TransportFailed` (`endpoint: "jwks"`).
 *
 * @stability unstable
 * @category constructors
 * @since 4.1.4
 */
export const makeVerifier: (
  options: VerifierOptions,
) => Effect.Effect<
  Verifier["Service"],
  OAuthError.OAuthError,
  Discovery.Discovery | Jwks.Jwks | Signature.Signature | Digest.Digest | Scope.Scope
> = Effect.fnUntraced(function* (
  options: VerifierOptions,
): Effect.fn.Return<
  Verifier["Service"],
  OAuthError.OAuthError,
  Discovery.Discovery | Jwks.Jwks | Signature.Signature | Digest.Digest | Scope.Scope
> {
  const policy = yield* parsePolicy(options);
  const algorithms = yield* parseAlgorithms(options.algorithms);
  const discovery = yield* Discovery.Discovery;
  const jwks = yield* Jwks.Jwks;
  const signature = yield* Signature.Signature;
  const digest = yield* Digest.Digest;
  const { available, use } = yield* Ownership.make("jwks");

  const verifyIdToken = Effect.fnUntraced(function* (
    idToken: string | Redacted.Redacted<string>,
    verifyOptions?: VerifyOptions,
  ): Effect.fn.Return<VerifiedIdToken, OAuthError.OAuthError> {
    // Capture caller policy, token bounds, and compact format before discovery or JWKS I/O.
    const input = yield* parseVerifyOptions(verifyOptions);

    yield* available;
    const rawToken = yield* decodeTokenString(idToken, policy.maxTokenLength);
    const header = yield* checkCompactFormat(rawToken);
    const metadata = yield* discovery.resolve;
    const effective = effectiveAlgorithmsFor(algorithms, metadata);

    return yield* verifyWithKeySetInternal(
      rawToken,
      header,
      metadata.issuer,
      policy,
      effective,
      input,
    ).pipe(
      Effect.provideService(Jwks.Jwks, jwks),
      Effect.provideService(Signature.Signature, signature),
      Effect.provideService(Digest.Digest, digest),
    );
  }, use);

  return Verifier.of({ verify: verifyIdToken });
});

/**
 * Layer that provides {@link Verifier} from `Discovery` and `Jwks.Jwks`.
 *
 * @stability unstable
 * @category layers
 * @since 4.1.4
 */
export const layerVerifier: (
  options: VerifierOptions,
) => Layer.Layer<
  Verifier,
  OAuthError.OAuthError,
  Discovery.Discovery | Jwks.Jwks | Signature.Signature | Digest.Digest
> = (options) => Layer.effect(Verifier, makeVerifier(options));

const validateRemoteJwksOptions = Effect.fnUntraced(function* (
  options: Omit<Jwks.RemoteOptions, "url"> | undefined,
): Effect.fn.Return<Omit<Jwks.RemoteOptions, "url">, OAuthError.OAuthError> {
  if (options === undefined) return {};
  if (!Predicate.isObject(options)) {
    return yield* V.invalidArgument("Invalid remote JWKS options");
  }
  if (options.timeToLive !== undefined) {
    yield* V.positiveFiniteMillis("jwks.timeToLive", options.timeToLive);
  }
  if (options.cooldown !== undefined) {
    yield* V.finiteMillis("jwks.cooldown", options.cooldown);
  }
  if (options.timeout !== undefined) {
    yield* V.positiveFiniteMillis("jwks.timeout", options.timeout);
  }
  if (options.maxResponseBytes !== undefined) {
    yield* V.positiveInteger("jwks.maxResponseBytes", options.maxResponseBytes);
  }
  if (options.maxKeys !== undefined) {
    yield* V.positiveInteger("jwks.maxKeys", options.maxKeys);
  }

  return {
    ...(options.timeToLive === undefined ? {} : { timeToLive: options.timeToLive }),
    ...(options.cooldown === undefined ? {} : { cooldown: options.cooldown }),
    ...(options.timeout === undefined ? {} : { timeout: options.timeout }),
    ...(options.maxResponseBytes === undefined
      ? {}
      : { maxResponseBytes: options.maxResponseBytes }),
    ...(options.maxKeys === undefined ? {} : { maxKeys: options.maxKeys }),
  };
});

interface CachedJwks {
  readonly uri: string;
  readonly service: Jwks.Jwks["Service"];
  readonly scope: Scope.Closeable;
  active: number;
  retired: boolean;
}

/**
 * Builds a scoped {@link Verifier} service that lazily initializes a remote
 * `Jwks.Jwks` resolver from the discovered `jwks_uri`.
 *
 * Options are validated eagerly with zero network I/O during construction. On
 * the first verification, `metadata.jwks_uri` must be an HTTPS URL; concurrent
 * initializations coalesce via a `Deferred`, and if discovery rotates
 * `jwks_uri`, the replacement key set is built in a fresh sequential child
 * scope while the previous child scope is torn down.
 *
 * @stability unstable
 * @category constructors
 * @since 4.1.4
 */
export const makeVerifierRemote: (
  options: VerifierOptions & { readonly jwks?: Omit<Jwks.RemoteOptions, "url"> | undefined },
) => Effect.Effect<
  Verifier["Service"],
  OAuthError.OAuthError,
  Discovery.Discovery | HttpClient.HttpClient | Signature.Signature | Digest.Digest | Scope.Scope
> = Effect.fnUntraced(function* (
  options: VerifierOptions & { readonly jwks?: Omit<Jwks.RemoteOptions, "url"> | undefined },
): Effect.fn.Return<
  Verifier["Service"],
  OAuthError.OAuthError,
  Discovery.Discovery | HttpClient.HttpClient | Signature.Signature | Digest.Digest | Scope.Scope
> {
  const policy = yield* parsePolicy(options);
  const algorithms = yield* parseAlgorithms(options.algorithms);
  const jwksOptions = yield* validateRemoteJwksOptions(options.jwks);
  const discovery = yield* Discovery.Discovery;
  const capturedHttp = yield* Transport.capture;

  const hardenedHttp = HttpClient.transformResponse(capturedHttp, (effect) =>
    effect.pipe(
      Effect.provideService(FetchHttpClient.RequestInit, {
        redirect: "manual",
        credentials: "omit",
        cache: "no-store",
      }),
      Effect.provideService(Tracer.DisablePropagation, true),
    ),
  );

  const signature = yield* Signature.Signature;
  const digest = yield* Digest.Digest;
  const layerScope = yield* Effect.scope;
  const { available, use } = yield* Ownership.make("jwks");

  let current: CachedJwks | undefined;

  let pending:
    | {
        readonly uri: string;
        readonly deferred: Deferred.Deferred<CachedJwks, OAuthError.OAuthError>;
      }
    | undefined;

  let closed = false;

  const closedExit = Exit.fail(jwksTransportFailed("The verifier scope is closed"));

  yield* Effect.addFinalizer(() =>
    Effect.sync(() => {
      closed = true;
      if (pending !== undefined) Deferred.doneUnsafe(pending.deferred, closedExit);
    }),
  );

  const releaseJwks = (cached: CachedJwks): Effect.Effect<void> =>
    Effect.suspend(() => {
      cached.active--;

      return cached.retired && cached.active === 0
        ? Scope.close(cached.scope, Exit.void).pipe(Effect.ignore)
        : Effect.void;
    });

  const withJwks = <A, E, R>(
    jwksUri: string | undefined,
    body: (service: Jwks.Jwks["Service"]) => Effect.Effect<A, E, R>,
  ): Effect.Effect<A, E | OAuthError.OAuthError, R> =>
    Effect.suspend(() => {
      if (jwksUri === undefined || !V.isHttpsUrl(jwksUri)) {
        return Effect.fail(
          V.invalidArgument("Asymmetric OIDC verification requires an HTTPS jwks_uri"),
        );
      }

      const normalizedUri = new URL(jwksUri).href;

      return Effect.uninterruptibleMask((restore) =>
        Effect.gen(function* () {
          while (true) {
            if (closed) return yield* closedExit;

            if (current !== undefined && current.uri === normalizedUri) {
              const cached = current;

              cached.active++;

              return yield* restore(body(cached.service)).pipe(
                Effect.ensuring(releaseJwks(cached)),
              );
            }

            if (pending !== undefined) {
              const activePending = pending;

              if (activePending.uri === normalizedUri) {
                const cached = yield* restore(Deferred.await(activePending.deferred));

                if (closed) return yield* closedExit;
                if (cached.retired) continue;
                cached.active++;

                return yield* restore(body(cached.service)).pipe(
                  Effect.ensuring(releaseJwks(cached)),
                );
              }

              yield* restore(Deferred.await(activePending.deferred)).pipe(
                Effect.catch(() => Effect.void),
              );
              continue;
            }

            const deferred = Deferred.makeUnsafe<CachedJwks, OAuthError.OAuthError>();

            pending = { uri: normalizedUri, deferred };

            const settle = (exit: Exit.Exit<CachedJwks, OAuthError.OAuthError>) => {
              if (pending?.deferred === deferred) pending = undefined;
              Deferred.doneUnsafe(
                deferred,
                Exit.isFailure(exit) && Cause.hasInterruptsOnly(exit.cause) ? closedExit : exit,
              );
            };

            const initialize = Effect.gen(function* () {
              const childScope = yield* Scope.fork(layerScope, "sequential");

              const service = yield* Jwks.makeRemote({
                ...jwksOptions,
                url: normalizedUri,
              }).pipe(
                Effect.provideService(HttpClient.HttpClient, hardenedHttp),
                Effect.provideService(Scope.Scope, childScope),
                Effect.catchCause((cause) =>
                  Scope.close(childScope, Exit.void).pipe(
                    Effect.ignore,
                    Effect.andThen(
                      Effect.failCause(
                        Cause.map(cause, (error) =>
                          error.reason._tag === "InvalidArgument"
                            ? V.invalidArgument(error.message, error)
                            : jwksTransportFailed(
                                "Could not initialize remote JWKS resolver",
                                error,
                              ),
                        ),
                      ),
                    ),
                  ),
                ),
              );

              if (closed) {
                yield* Scope.close(childScope, Exit.void).pipe(Effect.ignore);

                return yield* closedExit;
              }

              const next: CachedJwks = {
                uri: normalizedUri,
                service,
                scope: childScope,
                active: 0,
                retired: false,
              };

              const previous = current;

              current = next;
              pending = undefined;
              if (previous !== undefined) {
                previous.retired = true;
                if (previous.active === 0) {
                  yield* Scope.close(previous.scope, Exit.void).pipe(Effect.ignore);
                }
              }

              return next;
            }).pipe(Effect.onExit((exit) => Effect.sync(() => settle(exit))));

            const initFiber = yield* Effect.forkIn(initialize, layerScope, {
              uninterruptible: false,
            });

            // Settle `deferred` even if `layerScope` closes before `initFiber`
            // runs its first step (when `Effect.onExit` never fires).
            initFiber.addObserver(settle);

            const cached = yield* restore(Deferred.await(deferred));

            if (closed) return yield* closedExit;
            if (cached.retired) continue;
            cached.active++;

            return yield* restore(body(cached.service)).pipe(Effect.ensuring(releaseJwks(cached)));
          }
        }),
      );
    });

  const verifyIdToken = Effect.fnUntraced(function* (
    idToken: string | Redacted.Redacted<string>,
    verifyOptions?: VerifyOptions,
  ): Effect.fn.Return<VerifiedIdToken, OAuthError.OAuthError> {
    // Capture caller policy, token bounds, and compact format before discovery or JWKS I/O.
    const input = yield* parseVerifyOptions(verifyOptions);

    yield* available;
    const rawToken = yield* decodeTokenString(idToken, policy.maxTokenLength);
    const header = yield* checkCompactFormat(rawToken);
    const metadata = yield* discovery.resolve;
    const effective = effectiveAlgorithmsFor(algorithms, metadata);

    let keySourceError: OAuthError.OAuthError | undefined;

    const deferredJwks = Jwks.Jwks.of({
      resolve: (selection) =>
        withJwks(metadata.jwks_uri, (jwks) => jwks.resolve(selection)).pipe(
          Effect.catchCause((cause) =>
            Effect.failCause(
              Cause.map(cause, (error) => {
                if (OAuthError.isOAuthError(error)) {
                  keySourceError = error;

                  return new JoseError.JoseError({
                    reason: new JoseError.KeySetUnavailable({
                      description: error.message,
                      cause: error,
                    }),
                  });
                }

                return error;
              }),
            ),
          ),
        ),
    });

    return yield* verifyWithKeySetInternal(
      rawToken,
      header,
      metadata.issuer,
      policy,
      effective,
      input,
    ).pipe(
      Effect.provideService(Jwks.Jwks, deferredJwks),
      Effect.provideService(Signature.Signature, signature),
      Effect.provideService(Digest.Digest, digest),
      Effect.catchCause((cause) => {
        const captured = keySourceError;

        return captured === undefined
          ? Effect.failCause(cause)
          : Effect.failCause(Cause.map(cause, () => captured));
      }),
    );
  }, use);

  return Verifier.of({ verify: verifyIdToken });
});

/**
 * Layer that provides {@link Verifier} backed by lazy, scoped remote JWKS
 * resolution via {@link makeVerifierRemote}.
 *
 * @stability unstable
 * @category layers
 * @since 4.1.4
 */
export const layerVerifierRemote: (
  options: VerifierOptions & { readonly jwks?: Omit<Jwks.RemoteOptions, "url"> | undefined },
) => Layer.Layer<
  Verifier,
  OAuthError.OAuthError,
  Discovery.Discovery | HttpClient.HttpClient | Signature.Signature | Digest.Digest
> = (options) => Layer.effect(Verifier, makeVerifierRemote(options));

const isTokenChar = (code: number): boolean =>
  (code >= 0x30 && code <= 0x39) ||
  (code >= 0x41 && code <= 0x5a) ||
  (code >= 0x61 && code <= 0x7a) ||
  code === 0x21 ||
  code === 0x23 ||
  code === 0x24 ||
  code === 0x25 ||
  code === 0x26 ||
  code === 0x27 ||
  code === 0x2a ||
  code === 0x2b ||
  code === 0x2d ||
  code === 0x2e ||
  code === 0x5e ||
  code === 0x5f ||
  code === 0x60 ||
  code === 0x7c ||
  code === 0x7e;

const isQdTextChar = (code: number): boolean =>
  code === 0x09 ||
  code === 0x20 ||
  code === 0x21 ||
  (code >= 0x23 && code <= 0x5b) ||
  (code >= 0x5d && code <= 0x7e) ||
  (code >= 0x80 && code <= 0xff);

const isQuotedPairChar = (code: number): boolean =>
  code === 0x09 ||
  code === 0x20 ||
  (code >= 0x21 && code <= 0x7e) ||
  (code >= 0x80 && code <= 0xff);

const isToken68Char = (code: number): boolean =>
  (code >= 0x30 && code <= 0x39) ||
  (code >= 0x41 && code <= 0x5a) ||
  (code >= 0x61 && code <= 0x7a) ||
  code === 0x2d ||
  code === 0x2e ||
  code === 0x5f ||
  code === 0x7e ||
  code === 0x2b ||
  code === 0x2f;

const validBearerErrorCode = (value: string): boolean =>
  // oxlint-disable-next-line no-control-regex -- RFC 6750 §3 permits ASCII NQCHAR (0x20-0x21, 0x23-0x5B, 0x5D-0x7E) in quoted error values.
  value.length > 0 &&
  value.length <= 128 &&
  value.trim().length > 0 &&
  /^[\x20\x21\x23-\x5b\x5d-\x7e]+$/u.test(value);

// Strictly parses RFC 9110 §11.6.1 / RFC 6750 §3.1 WWW-Authenticate challenges
// for a single unambiguous Bearer `error` auth-param.
const parseBearerErrorCode = (header: string | null): string | undefined => {
  if (header === null || header.length === 0 || header.length > 4096) return undefined;

  let index = 0;
  const length = header.length;
  let bearerError: string | undefined;
  let sawBearerError = false;

  const isSpace = (code: number): boolean => code === 0x20 || code === 0x09;

  const skipSpaces = (): void => {
    while (index < length && isSpace(header.charCodeAt(index))) index++;
  };

  const readToken = (): string => {
    const start = index;

    while (index < length && isTokenChar(header.charCodeAt(index))) index++;

    return header.slice(start, index);
  };

  const readQuotedString = (): string | undefined => {
    if (header.charAt(index) !== '"') return undefined;
    index++;
    let result = "";

    while (index < length) {
      const code = header.charCodeAt(index);

      if (code === 0x5c) {
        index++;
        if (index >= length) return undefined;
        const escaped = header.charCodeAt(index);

        if (!isQuotedPairChar(escaped)) return undefined;
        result += header.charAt(index);
        index++;
        continue;
      }
      if (code === 0x22) {
        index++;

        return result;
      }
      if (!isQdTextChar(code)) return undefined;
      result += header.charAt(index);
      index++;
    }

    return undefined;
  };

  const readToken68 = (): boolean => {
    const start = index;

    while (index < length && isToken68Char(header.charCodeAt(index))) index++;
    if (index === start) return false;
    while (index < length && header.charAt(index) === "=") index++;

    return true;
  };

  const peekIsToken68 = (): boolean => {
    let cursor = index;

    while (cursor < length && isToken68Char(header.charCodeAt(cursor))) cursor++;
    if (cursor === index) return false;
    while (cursor < length && header.charAt(cursor) === "=") cursor++;
    while (cursor < length && isSpace(header.charCodeAt(cursor))) cursor++;

    return cursor >= length || header.charAt(cursor) === ",";
  };

  const peekIsAuthParam = (): boolean => {
    let cursor = index;

    while (cursor < length && isTokenChar(header.charCodeAt(cursor))) cursor++;
    if (cursor === index) return false;
    while (cursor < length && isSpace(header.charCodeAt(cursor))) cursor++;

    return cursor < length && header.charAt(cursor) === "=";
  };

  while (index < length) {
    skipSpaces();
    while (index < length && header.charAt(index) === ",") {
      index++;
      skipSpaces();
    }
    if (index >= length) break;

    const scheme = readToken();

    if (scheme.length === 0) return undefined;
    if (index >= length) break;

    const hadSpace = isSpace(header.charCodeAt(index));

    skipSpaces();
    if (index >= length) break;
    if (header.charAt(index) === ",") {
      index++;
      continue;
    }
    if (!hadSpace) return undefined;

    const isBearer = scheme.toLowerCase() === "bearer";

    if (peekIsToken68()) {
      if (isBearer || !readToken68()) return undefined;
      skipSpaces();
      if (index < length && header.charAt(index) !== ",") return undefined;
      if (index < length) index++;
      continue;
    }

    if (!peekIsAuthParam()) return undefined;

    while (index < length) {
      const name = readToken();

      if (name.length === 0) return undefined;
      skipSpaces();
      if (index >= length || header.charAt(index) !== "=") return undefined;
      index++;
      skipSpaces();
      if (index >= length) return undefined;

      const isQuoted = header.charAt(index) === '"';
      const value = isQuoted ? readQuotedString() : readToken();

      if (value === undefined || (!isQuoted && value.length === 0)) return undefined;
      if (isBearer && name.toLowerCase() === "error") {
        if (sawBearerError || !validBearerErrorCode(value)) return undefined;
        sawBearerError = true;
        bearerError = value;
      }

      skipSpaces();
      if (index >= length) break;
      if (header.charAt(index) !== ",") return undefined;
      index++;
      skipSpaces();
      while (index < length && header.charAt(index) === ",") {
        index++;
        skipSpaces();
      }
      if (index >= length || !peekIsAuthParam()) break;
    }
  }

  return bearerError;
};

/**
 * Fetches claims from the discovered OIDC UserInfo endpoint and verifies that
 * the returned `sub` matches `expectedSubject` (OIDC Core 1.0 §5.3.2).
 *
 * Requires an HTTP `200` `application/json` object response and does not
 * require `iss` or `aud` on JSON UserInfo responses. HTTP `401` or `403` with
 * a conformant `WWW-Authenticate: Bearer error="..."` challenge fails with
 * `EndpointError` (`endpoint: "userinfo"`); `5xx` and transport faults fail
 * with `TransportFailed` (`endpoint: "userinfo"`).
 *
 * @stability unstable
 * @category userinfo
 * @since 4.1.4
 */
export const fetchUserInfo: (options: {
  readonly accessToken: string | Redacted.Redacted<string>;
  readonly expectedSubject: string;
  readonly timeout?: Duration.Input | undefined;
  readonly maxResponseBytes?: number | undefined;
}) => Effect.Effect<
  Redacted.Redacted<Readonly<Record<string, Schema.Json>>>,
  OAuthError.OAuthError,
  Discovery.Discovery | HttpClient.HttpClient
> = Effect.fnUntraced(function* (options: {
  readonly accessToken: string | Redacted.Redacted<string>;
  readonly expectedSubject: string;
  readonly timeout?: Duration.Input | undefined;
  readonly maxResponseBytes?: number | undefined;
}): Effect.fn.Return<
  Redacted.Redacted<Readonly<Record<string, Schema.Json>>>,
  OAuthError.OAuthError,
  Discovery.Discovery | HttpClient.HttpClient
> {
  if (!Predicate.isObject(options)) {
    return yield* V.invalidArgument("Invalid UserInfo options");
  }

  const token = yield* revealString(options.accessToken, () =>
    V.invalidArgument("Invalid bearer access token"),
  ).pipe(
    Effect.flatMap((value) =>
      V.decode(V.Bearer, Redacted.make(value), () =>
        V.invalidArgument("Invalid bearer access token"),
      ),
    ),
    Effect.flatMap((redacted) =>
      V.reveal(redacted, () => V.invalidArgument("Invalid bearer access token")),
    ),
  );

  const expectedSubject = yield* V.configuration(
    V.text(1024),
    options.expectedSubject,
    "Invalid expectedSubject",
  );

  const timeoutMs = yield* V.positiveFiniteMillis("timeout", options.timeout ?? "5 seconds");

  const maxResponseBytes = yield* V.positiveInteger(
    "maxResponseBytes",
    options.maxResponseBytes ?? 131072,
  );

  const discovery = yield* Discovery.Discovery;
  const http = yield* Transport.capture;
  const metadata = yield* discovery.resolve;

  if (metadata.userinfo_endpoint === undefined) {
    return yield* V.invalidArgument("Discovery metadata does not include userinfo_endpoint");
  }

  const issuer = yield* V.decode(V.Issuer, metadata.issuer, () =>
    V.invalidArgument("Discovery metadata issuer is invalid"),
  );

  const userInfoEndpoint = yield* V.decode(V.Endpoint, metadata.userinfo_endpoint, () =>
    V.invalidArgument("Discovery metadata userinfo_endpoint is invalid"),
  );

  if (!V.endpointMatchesIssuer(issuer, userInfoEndpoint)) {
    return yield* V.invalidArgument(
      "Discovery metadata userinfo_endpoint scheme does not match issuer",
    );
  }

  const request = HttpClientRequest.get(new URL(userInfoEndpoint).href).pipe(
    HttpClientRequest.acceptJson,
    HttpClientRequest.setHeader("authorization", `Bearer ${token}`),
  );

  const response = yield* Transport.request(
    http,
    request,
    { timeoutMs, maxResponseBytes },
    "userinfo",
  );

  if (response.status >= 500) {
    return yield* new OAuthError.OAuthError({
      reason: new OAuthError.TransportFailed({
        endpoint: "userinfo",
        status: response.status,
        description: "UserInfo endpoint returned server error",
      }),
    });
  }

  if (response.status === 401 || response.status === 403) {
    const bearerError = parseBearerErrorCode(response.wwwAuthenticate);

    if (bearerError !== undefined) {
      return yield* new OAuthError.OAuthError({
        reason: new OAuthError.EndpointError({
          endpoint: "userinfo",
          status: response.status,
          ...V.normalizeOAuthErrorCode(bearerError),
        }),
      });
    }

    return yield* new OAuthError.OAuthError({
      reason: new OAuthError.InvalidResponse({
        endpoint: "userinfo",
        status: response.status,
        description: "UserInfo authorization error lacked a conformant Bearer error code",
      }),
    });
  }

  if (response.status !== 200) {
    return yield* new OAuthError.OAuthError({
      reason: new OAuthError.InvalidResponse({
        endpoint: "userinfo",
        status: response.status,
        description: "Unexpected UserInfo response status",
      }),
    });
  }

  const document = yield* Transport.json(response, "userinfo");

  const rawBody = yield* V.reveal(
    document.body,
    () =>
      new OAuthError.OAuthError({
        reason: new OAuthError.InvalidResponse({
          endpoint: "userinfo",
          status: response.status,
          description: "UserInfo response body is unavailable",
        }),
      }),
  );

  const body = yield* V.snapshotPlainJson(
    rawBody,
    () =>
      new OAuthError.OAuthError({
        reason: new OAuthError.InvalidResponse({
          endpoint: "userinfo",
          status: response.status,
          description: "UserInfo response body is not a safe JSON object",
        }),
      }),
  );

  const subject = yield* V.decode(
    Schema.Struct({ sub: V.text(1024) }),
    body,
    () =>
      new OAuthError.OAuthError({
        reason: new OAuthError.InvalidResponse({
          endpoint: "userinfo",
          status: response.status,
          description: "UserInfo response is missing a valid sub claim",
        }),
      }),
  );

  if (subject.sub !== expectedSubject) {
    return yield* tokenFailed("subjectMismatch");
  }

  return Redacted.make(V.freeze(body));
});
