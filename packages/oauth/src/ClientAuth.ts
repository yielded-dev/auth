/**
 * OAuth 2.1 / OpenID Connect client authentication methods.
 *
 * Built-in methods cover public clients ({@link none}), HTTP Basic
 * ({@link secretBasic}), form-body secrets ({@link secretPost}), and RFC 10070
 * JWT client assertions ({@link secretJwt} and {@link privateKeyJwt}).
 * External callers can define custom methods with {@link make} or defer method
 * creation behind a fixed registered method name with {@link unwrap}.
 *
 * **Gotchas**
 *
 * {@link secretJwt} and {@link privateKeyJwt} follow RFC 10070 §4 by default:
 * `aud` is the single issuer string `request.issuer` (never an array), `typ`
 * defaults to `"client-authentication+jwt"`, `jti` carries 128 random bits,
 * and `lifetime` defaults to `"60 seconds"`. Legacy servers that require the
 * token-endpoint URL as `aud` must configure `audience: (req) => req.endpoint`
 * explicitly.
 *
 * @stability unstable
 * @since 4.1.4
 */
import * as Cause from "effect/Cause";
import * as Clock from "effect/Clock";
import type * as Mac from "effect/crypto/Mac";
import * as SecureRandom from "effect/crypto/SecureRandom";
import type * as Signature from "effect/crypto/Signature";
import type * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Base64 from "effect/encoding/Base64";
import * as Base64Url from "effect/encoding/Base64Url";
import * as Jwk from "effect/jose/Jwk";
import type * as Jws from "effect/jose/Jws";
import * as Jwt from "effect/jose/Jwt";
import * as Predicate from "effect/Predicate";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";

import * as V from "./internal/validation.ts";
import * as OAuthError from "./OAuthError.ts";

const TypeId = "~effect/oauth/ClientAuth/Method" as const;

const jwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const defaultAssertionTyp = "client-authentication+jwt";
const utf8Encoder = new TextEncoder();

// Tracks per-request Redacted values allocated by built-in methods so
// `OAuth.Client` can wipe them after encoding without touching caller-owned
// `Redacted` values returned by custom `ClientAuth.make` implementations.
const ephemeralRedacted = new WeakSet<Redacted.Redacted<string>>();

const makeEphemeral = (value: string): Redacted.Redacted<string> => {
  const redacted = Redacted.make(value);

  ephemeralRedacted.add(redacted);

  return redacted;
};

/**
 * Context passed to a client authentication method when preparing a token or
 * revocation request.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export interface Request {
  readonly clientId: string;
  readonly endpoint: string;
  readonly issuer: string;
}

/**
 * Headers and form fields emitted by a client authentication method.
 *
 * Credential values stay wrapped in `Redacted<string>` until wire encoding.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export interface Applied {
  readonly headers: Readonly<Record<string, string | Redacted.Redacted<string>>>;
  readonly form: ReadonlyArray<readonly [string, string | Redacted.Redacted<string>]>;
}

/**
 * A client authentication method whose `name` matches the registered OAuth
 * authentication method identifier and whose `apply` effect prepares request
 * credentials requiring `R`.
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export interface Method<out R = never> {
  readonly [TypeId]: typeof TypeId;
  readonly name: string;
  readonly apply: (request: Request) => Effect.Effect<Applied, OAuthError.OAuthError, R>;
}

/**
 * Options for RFC 10070 JWT client assertions ({@link secretJwt} and
 * {@link privateKeyJwt}).
 *
 * @stability unstable
 * @category models
 * @since 4.1.4
 */
export interface JwtAssertionOptions<
  H extends object & { readonly [P in keyof H]: Schema.Json | undefined } = Jws.Header,
> {
  /** Single audience string. Defaults to `request.issuer` per RFC 10070 §4. */
  readonly audience?: string | ((request: Request) => string) | undefined;
  /** Assertion lifetime. Defaults to `"60 seconds"`. */
  readonly lifetime?: Duration.Input | undefined;
  /** Protected header parameters; `typ` defaults to `"client-authentication+jwt"`. */
  readonly header?: (Jws.Header & H) | undefined;
}

const AssertionClaims = Schema.Struct({
  iss: Schema.NonEmptyString,
  sub: Schema.NonEmptyString,
  aud: Schema.NonEmptyString,
  jti: Schema.NonEmptyString,
  iat: Schema.Finite,
  exp: Schema.Finite,
});

const clientAuthFailed = (description: string, cause?: unknown): OAuthError.OAuthError =>
  new OAuthError.OAuthError({
    reason: new OAuthError.ClientAuthFailed({
      description,
      ...(cause === undefined ? {} : { cause }),
    }),
  });

const isHmacAlgorithm = (value: unknown): value is Jwk.HmacAlgorithm =>
  value === "HS256" || value === "HS384" || value === "HS512";

// RFC 6749 Appendix B: encode client credentials before joining with the colon.
// Adapted from oauth4webapi 3.8.8 src/index.ts::formUrlEncode (MIT, Filip Skokan).
// Exact source commit and license: ../THIRD_PARTY_NOTICES.md.
const basicComponent = (value: string): string =>
  encodeURIComponent(value).replace(/[-_.!~*'()]|%20/gu, (part) =>
    part === "%20" ? "+" : `%${part.charCodeAt(0).toString(16).toUpperCase()}`,
  );

const validateRequest = Effect.fnUntraced(function* (
  request: Request,
): Effect.fn.Return<Request, OAuthError.OAuthError> {
  if (!Predicate.isObject(request)) {
    return yield* V.invalidArgument("Invalid client authentication request");
  }

  const clientId = yield* V.configuration(V.text(1024), request.clientId, "Invalid OAuth clientId");

  const issuer = yield* V.configuration(V.Issuer, request.issuer, "Invalid OAuth issuer");
  const endpoint = yield* V.configuration(V.Endpoint, request.endpoint, "Invalid OAuth endpoint");

  return { clientId, issuer, endpoint };
});

const revealClientSecret = (
  secret: string | Redacted.Redacted<string>,
  maxLength: number,
): Effect.Effect<string, OAuthError.OAuthError> =>
  V.revealString(
    secret,
    () => clientAuthFailed("Client secret is unavailable"),
    () => V.invalidArgument("Client secret must be a non-empty string"),
  ).pipe(
    Effect.filterOrFail(
      (value) => value.length > 0 && value.length <= maxLength,
      () => V.invalidArgument("Client secret must be a non-empty string"),
    ),
  );

const resolveAudience = Effect.fnUntraced(function* (
  audience: string | ((request: Request) => string) | undefined,
  request: Request,
): Effect.fn.Return<string, OAuthError.OAuthError> {
  if (audience === undefined) return request.issuer;

  const value = Predicate.isFunction(audience)
    ? yield* Effect.try({
        try: () => audience(request),
        catch: (cause) => clientAuthFailed("Could not resolve JWT assertion audience", cause),
      })
    : audience;

  if (typeof value !== "string" || value.length === 0 || value.length > 2048) {
    return yield* V.invalidArgument("JWT assertion audience must be a single non-empty string");
  }

  return value;
});

const resolveAssertionHeader = Effect.fnUntraced(function* (
  header: unknown,
): Effect.fn.Return<Jws.Header & Record<string, Schema.Json>, OAuthError.OAuthError> {
  if (header === undefined) {
    return { typ: defaultAssertionTyp };
  }

  const snapshot = yield* V.snapshotPlainJson(header, () =>
    V.invalidArgument("Invalid JWT assertion header"),
  );

  if (
    Object.hasOwn(snapshot, "alg") ||
    Object.hasOwn(snapshot, "crit") ||
    Object.hasOwn(snapshot, "b64")
  ) {
    return yield* V.invalidArgument("JWT assertion header cannot override alg, crit, or b64");
  }

  if (
    Object.hasOwn(snapshot, "typ") &&
    (typeof snapshot.typ !== "string" || snapshot.typ.length === 0 || snapshot.typ.length > 256)
  ) {
    return yield* V.invalidArgument("JWT assertion header typ must be a non-empty string");
  }

  if (
    Object.hasOwn(snapshot, "kid") &&
    (typeof snapshot.kid !== "string" || snapshot.kid.length === 0 || snapshot.kid.length > 256)
  ) {
    return yield* V.invalidArgument("JWT assertion header kid must be a non-empty string");
  }

  if (
    Object.hasOwn(snapshot, "cty") &&
    (typeof snapshot.cty !== "string" || snapshot.cty.length === 0 || snapshot.cty.length > 256)
  ) {
    return yield* V.invalidArgument("JWT assertion header cty must be a non-empty string");
  }

  if (!Object.hasOwn(snapshot, "typ")) {
    Object.defineProperty(snapshot, "typ", {
      value: defaultAssertionTyp,
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }

  return snapshot as Jws.Header & Record<string, Schema.Json>;
});

const signClientAssertion = Effect.fnUntraced(function* <K extends Jwk.SigningKey>(
  key: K,
  request: Request,
  options: JwtAssertionOptions<Record<string, Schema.Json | undefined>> | undefined,
): Effect.fn.Return<
  Applied,
  OAuthError.OAuthError,
  Jws.KeyRequirements<K> | SecureRandom.SecureRandom
> {
  if (options !== undefined && !Predicate.isObject(options)) {
    return yield* V.invalidArgument("Invalid JWT assertion options");
  }

  const validated = yield* validateRequest(request);

  const audience = yield* resolveAudience(
    options?.audience as string | ((request: Request) => string) | undefined,
    validated,
  );

  const lifetimeMs = yield* V.positiveFiniteMillis(
    "lifetime",
    (options?.lifetime as Duration.Input | undefined) ?? "60 seconds",
  );

  const header = yield* resolveAssertionHeader(options?.header);

  const random = yield* SecureRandom.SecureRandom;
  const jtiBytes = yield* random.randomBytes(16);

  if (jtiBytes.length !== 16) {
    return yield* Effect.die(
      new RangeError("SecureRandom.randomBytes(16) returned an unexpected byte length"),
    );
  }

  const jti = Base64Url.encode(jtiBytes);
  const iat = Math.floor((yield* Clock.currentTimeMillis) / 1000);
  const exp = iat + lifetimeMs / 1000;

  if (!Number.isFinite(exp) || exp <= iat) {
    return yield* V.invalidArgument("JWT assertion lifetime produces an invalid expiration");
  }

  const assertion = yield* Jwt.sign(
    AssertionClaims,
    {
      iss: validated.clientId,
      sub: validated.clientId,
      aud: audience,
      jti,
      iat,
      exp,
    },
    key,
    header,
  ).pipe(
    Effect.catchCause((cause) =>
      Effect.failCause(
        Cause.map(cause, (error) => clientAuthFailed("Could not sign JWT client assertion", error)),
      ),
    ),
  );

  ephemeralRedacted.add(assertion);

  return {
    headers: {},
    form: [
      ["client_id", validated.clientId],
      ["client_assertion_type", jwtBearerAssertionType],
      ["client_assertion", assertion],
    ],
  };
});

/**
 * Checks whether a value is a `ClientAuth.Method`.
 *
 * @internal
 */
export const isMethod = (u: unknown): u is Method<never> =>
  Predicate.isObject(u) &&
  Predicate.hasProperty(u, TypeId) &&
  Predicate.hasProperty(u, "name") &&
  Predicate.isString(u.name) &&
  Predicate.hasProperty(u, "apply") &&
  Predicate.isFunction(u.apply);

/**
 * Wipes per-request `Redacted` values allocated by built-in `ClientAuth`
 * methods after request encoding. Leaves caller-owned `Redacted` values
 * returned by custom {@link make} implementations intact.
 *
 * @internal
 */
export const wipeApplied = (applied: Applied): void => {
  if (!Predicate.isObject(applied)) return;
  if (Predicate.isObject(applied.headers)) {
    for (const value of Object.values(applied.headers)) {
      if (Redacted.isRedacted(value) && ephemeralRedacted.has(value as Redacted.Redacted<string>)) {
        Redacted.wipeUnsafe(value);
      }
    }
  }
  if (Array.isArray(applied.form)) {
    for (const entry of applied.form) {
      if (!Array.isArray(entry) || entry.length < 2) continue;
      const value: unknown = entry[1];

      if (Redacted.isRedacted(value) && ephemeralRedacted.has(value as Redacted.Redacted<string>)) {
        Redacted.wipeUnsafe(value);
      }
    }
  }
};

/**
 * Constructs a custom client authentication method with the registered method
 * name `name`.
 *
 * @stability unstable
 * @category constructors
 * @since 4.1.4
 */
export const make: <R = never>(
  name: string,
  apply: (request: Request) => Effect.Effect<Applied, OAuthError.OAuthError, R>,
) => Method<R> = (name, apply) =>
  Object.freeze({
    [TypeId]: TypeId,
    name,
    apply,
  });

/**
 * Defers resolution of a {@link Method} behind a fixed synchronous method
 * `name`.
 *
 * The bound `name` is known before any credentials are minted so metadata
 * validation, public-client PKCE enforcement, and `client_credentials` guards
 * evaluate without running `effect`. On each `apply`, the resolved method's
 * `name` must match `name`; mismatches and inner failures surface as
 * `ClientAuthFailed`.
 *
 * @stability unstable
 * @category combinators
 * @since 4.1.4
 */
export const unwrap: <R1, E, R2>(
  name: string,
  effect: Effect.Effect<Method<R1>, E, R2>,
) => Method<R1 | R2> = (name, effect) =>
  make(name, (request) => {
    if (typeof name !== "string" || name.length === 0 || name.length > 64) {
      return Effect.fail(V.invalidArgument("Invalid client authentication method name"));
    }

    return Effect.flatMap(
      effect.pipe(
        Effect.catchCause((cause) =>
          Effect.failCause(
            Cause.map(cause, (error) =>
              OAuthError.isOAuthError(error) && error.reason._tag === "ClientAuthFailed"
                ? error
                : clientAuthFailed("Could not resolve client authentication method", error),
            ),
          ),
        ),
      ),
      (resolved) => {
        if (!isMethod(resolved)) {
          return Effect.fail(clientAuthFailed("Resolved client authentication method is invalid"));
        }
        if (resolved.name !== name) {
          return Effect.fail(
            clientAuthFailed("Resolved client authentication method does not match expected name"),
          );
        }

        return resolved.apply(request);
      },
    );
  });

/**
 * Public-client authentication (`name: "none"`), sending `client_id` in the
 * form body with no client secret.
 *
 * @stability unstable
 * @category methods
 * @since 4.1.4
 */
export const none: Method<never> = make("none", (request) =>
  Effect.map(validateRequest(request), (validated) => ({
    headers: {},
    form: [["client_id", validated.clientId]],
  })),
);

/**
 * HTTP Basic client authentication (`name: "client_secret_basic"`), encoding
 * `client_id` and `secret` per RFC 6749 Appendix B in the `Authorization`
 * header.
 *
 * @stability unstable
 * @category methods
 * @since 4.1.4
 */
export const secretBasic: (secret: string | Redacted.Redacted<string>) => Method<never> = (
  secret,
) =>
  make(
    "client_secret_basic",
    Effect.fnUntraced(function* (
      request: Request,
    ): Effect.fn.Return<Applied, OAuthError.OAuthError> {
      const validated = yield* validateRequest(request);
      const revealed = yield* revealClientSecret(secret, 4096);

      const credential = yield* Effect.try({
        try: () =>
          Base64.encode(`${basicComponent(validated.clientId)}:${basicComponent(revealed)}`),
        catch: (cause) => clientAuthFailed("Could not encode HTTP Basic client credentials", cause),
      });

      return {
        headers: { authorization: makeEphemeral(`Basic ${credential}`) },
        form: [],
      };
    }),
  );

/**
 * Form-body client secret authentication (`name: "client_secret_post"`),
 * sending `client_id` and `client_secret` in the request body.
 *
 * @stability unstable
 * @category methods
 * @since 4.1.4
 */
export const secretPost: (secret: string | Redacted.Redacted<string>) => Method<never> = (secret) =>
  make(
    "client_secret_post",
    Effect.fnUntraced(function* (
      request: Request,
    ): Effect.fn.Return<Applied, OAuthError.OAuthError> {
      const validated = yield* validateRequest(request);
      const revealed = yield* revealClientSecret(secret, 8192);

      return {
        headers: {},
        form: [
          ["client_id", validated.clientId],
          ["client_secret", makeEphemeral(revealed)],
        ],
      };
    }),
  );

/**
 * Symmetric JWT client assertion authentication (`name: "client_secret_jwt"`)
 * per RFC 10070 §4 and OIDC Core §9.
 *
 * Accepts either a pre-imported `Jwk.SecretKey<Jwk.HmacAlgorithm>` or a raw
 * `string | Redacted<string>` client secret imported as UTF-8 octets with
 * `options.algorithm ?? "HS256"`.
 *
 * @stability unstable
 * @category methods
 * @since 4.1.4
 */
export const secretJwt: <
  H extends object & { readonly [P in keyof H]: Schema.Json | undefined } = Jws.Header,
>(
  secret: string | Redacted.Redacted<string> | Jwk.SecretKey<Jwk.HmacAlgorithm>,
  options?: JwtAssertionOptions<H> & { readonly algorithm?: Jwk.HmacAlgorithm | undefined },
) => Method<Mac.Mac | SecureRandom.SecureRandom> = (secret, options) =>
  make(
    "client_secret_jwt",
    Effect.fnUntraced(function* (
      request: Request,
    ): Effect.fn.Return<Applied, OAuthError.OAuthError, Mac.Mac | SecureRandom.SecureRandom> {
      if (options !== undefined && !Predicate.isObject(options)) {
        return yield* V.invalidArgument("Invalid JWT assertion options");
      }

      if (typeof secret !== "string" && !Redacted.isRedacted(secret)) {
        if (
          !Predicate.isObject(secret) ||
          secret._tag !== "SecretKey" ||
          !isHmacAlgorithm(secret.algorithm)
        ) {
          return yield* V.invalidArgument("secretJwt requires an HMAC Jwk.SecretKey");
        }
        if (options?.algorithm !== undefined && options.algorithm !== secret.algorithm) {
          return yield* V.invalidArgument(
            "secretJwt options.algorithm does not match the provided secret key",
          );
        }

        const hmacKey: Jwk.SecretKey<Jwk.HmacAlgorithm> = secret;

        return yield* signClientAssertion(hmacKey, request, options);
      }

      const algorithm = options?.algorithm ?? "HS256";

      if (!isHmacAlgorithm(algorithm)) {
        return yield* V.invalidArgument("secretJwt algorithm must be HS256, HS384, or HS512");
      }

      const revealed = yield* revealClientSecret(secret, 8192);
      const bytes = utf8Encoder.encode(revealed);

      const jwkSecret = Redacted.make({
        kty: "oct" as const,
        alg: algorithm,
        k: Base64Url.encode(bytes),
      });

      const key = yield* Jwk.importSecret(jwkSecret, algorithm).pipe(
        Effect.ensuring(
          Effect.sync(() => {
            bytes.fill(0);
            Redacted.wipeUnsafe(jwkSecret);
          }),
        ),
        Effect.catchCause((cause) =>
          Effect.failCause(
            Cause.map(cause, (error) =>
              clientAuthFailed("Could not import client secret for JWT assertion", error),
            ),
          ),
        ),
      );

      return yield* signClientAssertion(key, request, options);
    }),
  );

/**
 * Asymmetric JWT client assertion authentication (`name: "private_key_jwt"`)
 * per RFC 10070 §4.
 *
 * @stability unstable
 * @category methods
 * @since 4.1.4
 */
export const privateKeyJwt: <
  H extends object & { readonly [P in keyof H]: Schema.Json | undefined } = Jws.Header,
>(
  key: Jwk.PrivateKey,
  options?: JwtAssertionOptions<H>,
) => Method<Signature.Signature | SecureRandom.SecureRandom> = (key, options) =>
  make(
    "private_key_jwt",
    Effect.fnUntraced(function* (
      request: Request,
    ): Effect.fn.Return<
      Applied,
      OAuthError.OAuthError,
      Signature.Signature | SecureRandom.SecureRandom
    > {
      const rawKey: unknown = key;

      if (
        !Predicate.isObject(rawKey) ||
        (rawKey as { readonly _tag?: unknown })._tag !== "PrivateKey"
      ) {
        return yield* V.invalidArgument("privateKeyJwt requires a Jwk.PrivateKey");
      }

      return yield* signClientAssertion(key, request, options);
    }),
  );
