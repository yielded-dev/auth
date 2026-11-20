import * as Cause from "effect/Cause";
import * as Clock from "effect/Clock";
import * as Signature from "effect/crypto/Signature";
import * as Effect from "effect/Effect";
import * as Jwk from "effect/jose/Jwk";
import * as Jwks from "effect/jose/Jwks";
import * as Jwt from "effect/jose/Jwt";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";

import { origin } from "../../internal/origin";
import type * as OAuthScope from "../../OAuthScope";
import {
  AccessClaims,
  BearerToken,
  ConfigurationError,
  DefaultSubject,
  InvalidToken,
  Random,
  Scope,
  ScopeText,
  makeAccessSchema,
  makeScopesSchema,
  Text,
  Unavailable,
  Url,
} from "./models";

export const makeAccessTokenClaimsSchema = <Subject extends string>(
  subject: Schema.Codec<Subject, string>,
) =>
  Schema.Struct({
    iss: Text,
    sub: subject,
    aud: Text,
    iat: Schema.Natural,
    exp: Schema.Natural,
    jti: Random,
    grant_id: Random,
    client_id: Text,
    scope: ScopeText,
    auth_time: Schema.Natural,
    sid: Text,
    claims: Schema.optionalKey(AccessClaims),
  });

/** RFC 9068 access tokens use a distinct type and audience from ID tokens. */
export const AccessTokenClaims = makeAccessTokenClaimsSchema(DefaultSubject);

export type AccessTokenClaims<Subject extends string = string> = ReturnType<
  typeof makeAccessTokenClaimsSchema<Subject>
>["Type"];

export interface AccessTokenVerifierWithKeySetOptions<Subject extends string = string> {
  readonly issuer: string;
  readonly resource: string;
  /** Only these declared scopes are accepted when supplied. */
  readonly scopes?: ReadonlyArray<OAuthScope.OAuthScope> | undefined;
  /** Subject schema decoded from the JWT `sub` claim. */
  readonly subject?: Schema.Codec<Subject, string> | undefined;
}

export interface AccessTokenVerifierOptions<
  Subject extends string = string,
> extends AccessTokenVerifierWithKeySetOptions<Subject> {
  /** Trusted keys from the issuer's JWKS; reacquire this verifier when keys rotate. */
  readonly publicKeys: ReadonlyArray<Jwk.PublicJwk>;
}

/** @internal */
export const makeVerifierCore = Effect.fnUntraced(function* <
  Scope extends OAuthScope.OAuthScope,
  Subject extends string,
>(
  options: AccessTokenVerifierWithKeySetOptions<string>,
  scope: Schema.Codec<Scope, string>,
  subject: Schema.Codec<Subject, string>,
) {
  const signature = yield* Signature.Signature;
  const keys = yield* Jwks.Jwks;
  const ScopeSchema = Schema.toType(scope);
  const SubjectSchema = Schema.toType(subject);
  const ScopesSchema = makeScopesSchema(ScopeSchema);
  const AccessTokenClaimsSchema = makeAccessTokenClaimsSchema(subject);
  const AccessSchema = makeAccessSchema(ScopeSchema, SubjectSchema);

  const config = yield* Schema.decodeEffect(
    Schema.Struct({
      issuer: origin,
      resource: Url,
    }),
  )(options, { reportInput: false }).pipe(Effect.mapError(() => ConfigurationError.make({})));

  const decode = Effect.fnUntraced(function* (credential: Redacted.Redacted<string>) {
    if (!Schema.is(BearerToken)(Redacted.value(credential))) return yield* InvalidToken.make({});

    const { claims } = yield* Jwt.verifyWithKeySet(AccessTokenClaimsSchema, credential, {
      algorithms: ["RS256"],
      issuer: config.issuer,
      audience: config.resource,
      typ: "at+jwt",
      maxTokenAge: "10 minutes",
      requiredClaims: ["iss", "sub", "aud", "iat", "exp", "jti"],
    }).pipe(
      Effect.provideService(Jwks.Jwks, keys),
      Effect.provideService(Signature.Signature, signature),
      Effect.catchCause((cause) =>
        Effect.failCause(
          Cause.map(cause, (error) =>
            error._tag === "JoseError" &&
            (error.reason._tag === "InvalidKey" || error.reason._tag === "KeySetUnavailable")
              ? Unavailable.make({})
              : InvalidToken.make({}),
          ),
        ),
      ),
    );

    const seconds = (yield* Clock.currentTimeMillis) / 1000;

    if (
      claims.sub.length === 0 ||
      claims.iat > seconds ||
      claims.exp <= seconds ||
      claims.exp <= claims.iat ||
      claims.exp - claims.iat > 600 ||
      claims.auth_time > claims.iat
    )
      return yield* InvalidToken.make({});

    const scopes = yield* Schema.decodeUnknownEffect(ScopesSchema)(claims.scope.split(" ")).pipe(
      Effect.mapError(() => InvalidToken.make({})),
    );

    if (new Set(scopes).size !== scopes.length) return yield* InvalidToken.make({});

    return {
      claims,
      access: AccessSchema.make({
        subjectId: claims.sub,
        clientId: claims.client_id,
        grantId: claims.grant_id,
        resource: claims.aud,
        scopes,
        ...(claims.claims === undefined ? {} : { claims: claims.claims }),
      }),
    };
  });

  return {
    verify: Effect.fnUntraced(function* (credential: Redacted.Redacted<string>) {
      return (yield* decode(credential)).access;
    }),
    /** Verified protocol fields for an issuer checking its durable grant version. */
    decode,
  };
});

/** @internal */
export const makeLocalVerifierCore = Effect.fnUntraced(function* <
  Scope extends OAuthScope.OAuthScope,
  Subject extends string,
>(
  options: AccessTokenVerifierOptions<string>,
  scope: Schema.Codec<Scope, string>,
  subject: Schema.Codec<Subject, string>,
) {
  const publicKeys = yield* Schema.decodeUnknownEffect(
    Schema.NonEmptyArray(Jwk.PublicJwk).check(Schema.isMaxLength(16)),
  )(options.publicKeys, { reportInput: false }).pipe(
    Effect.mapError(() => ConfigurationError.make({})),
  );

  const keys = yield* Jwks.makeLocal({ keys: publicKeys }).pipe(
    Effect.mapError(() => ConfigurationError.make({})),
  );

  return yield* makeVerifierCore(options, scope, subject).pipe(
    Effect.provideService(Jwks.Jwks, keys),
  );
});

/** Verify offline with trusted public keys. Revocation and permission changes
 * take effect at token expiry; use short access lifetimes and renew through the issuer.
 * Retains only the signature service; verification uses the caller's clock and context.
 * Declared scopes narrow access only after every token scope passes validation.
 */
export function makeAccessTokenVerifier<
  const S extends ReadonlyArray<OAuthScope.OAuthScope>,
  Subject extends string,
>(
  options: AccessTokenVerifierOptions<Subject> & {
    readonly scopes: S;
    readonly subject: Schema.Codec<Subject, string>;
  },
): ReturnType<typeof makeLocalVerifierCore<S[number], Subject>>;

export function makeAccessTokenVerifier<const S extends ReadonlyArray<OAuthScope.OAuthScope>>(
  options: AccessTokenVerifierOptions<DefaultSubject> & {
    readonly scopes: S;
    readonly subject?: undefined;
  },
): ReturnType<typeof makeLocalVerifierCore<S[number], DefaultSubject>>;

export function makeAccessTokenVerifier<Subject extends string>(
  options: AccessTokenVerifierOptions<Subject> & {
    readonly scopes?: undefined;
    readonly subject: Schema.Codec<Subject, string>;
  },
): ReturnType<typeof makeLocalVerifierCore<OAuthScope.OAuthScope, Subject>>;

export function makeAccessTokenVerifier(
  options: AccessTokenVerifierOptions<DefaultSubject>,
): ReturnType<typeof makeLocalVerifierCore<OAuthScope.OAuthScope, DefaultSubject>>;

export function makeAccessTokenVerifier(options: AccessTokenVerifierOptions<string>) {
  return makeLocalVerifierCore(
    options,
    options.scopes === undefined ? Scope : Schema.Literals(options.scopes),
    options.subject ?? DefaultSubject,
  );
}

/** Verify with the supplied Jwks service, for example Jwks.layerRemote from
 * effect/jose. Captures only Jwks and Signature.Signature; the caller's clock and context
 * still govern verification. Retain the resolver's owning Scope while using the
 * verifier. Remote key failures become Unavailable; invalid tokens remain InvalidToken.
 *
 * The host configures the trusted key endpoint and owns its platform lifetime.
 * On Workers, retain the bounded verification with waitUntil and await its native
 * Promise in each request. Do not tie that retained verification to request abort.
 * Revocation and permission changes take effect at access-token expiry.
 */
export function makeAccessTokenVerifierWithKeySet<
  const S extends ReadonlyArray<OAuthScope.OAuthScope>,
  Subject extends string,
>(
  options: AccessTokenVerifierWithKeySetOptions<Subject> & {
    readonly scopes: S;
    readonly subject: Schema.Codec<Subject, string>;
  },
): ReturnType<typeof makeVerifierCore<S[number], Subject>>;

export function makeAccessTokenVerifierWithKeySet<
  const S extends ReadonlyArray<OAuthScope.OAuthScope>,
>(
  options: AccessTokenVerifierWithKeySetOptions<DefaultSubject> & {
    readonly scopes: S;
    readonly subject?: undefined;
  },
): ReturnType<typeof makeVerifierCore<S[number], DefaultSubject>>;

export function makeAccessTokenVerifierWithKeySet<Subject extends string>(
  options: AccessTokenVerifierWithKeySetOptions<Subject> & {
    readonly scopes?: undefined;
    readonly subject: Schema.Codec<Subject, string>;
  },
): ReturnType<typeof makeVerifierCore<OAuthScope.OAuthScope, Subject>>;

export function makeAccessTokenVerifierWithKeySet(
  options: AccessTokenVerifierWithKeySetOptions<DefaultSubject>,
): ReturnType<typeof makeVerifierCore<OAuthScope.OAuthScope, DefaultSubject>>;

export function makeAccessTokenVerifierWithKeySet(
  options: AccessTokenVerifierWithKeySetOptions<string>,
) {
  return makeVerifierCore(
    options,
    options.scopes === undefined ? Scope : Schema.Literals(options.scopes),
    options.subject ?? DefaultSubject,
  );
}
