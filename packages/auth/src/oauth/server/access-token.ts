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
  InvalidToken,
  Random,
  ScopeText,
  makeAccessSchema,
  makeScopesSchema,
  nonEmptySubject,
  Text,
  Unavailable,
  Url,
} from "./models";

/** RFC 9068 access tokens use a distinct type and audience from ID tokens. */
export const makeAccessTokenClaimsSchema = <S extends Schema.Codec<string, string>>(subject: S) =>
  Schema.Struct({
    iss: Text,
    sub: nonEmptySubject(subject),
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

export type AccessTokenClaims<Subject extends string = string> = ReturnType<
  typeof makeAccessTokenClaimsSchema<Schema.Codec<Subject, string>>
>["Type"];

export interface AccessTokenVerifierWithKeySetOptions {
  readonly issuer: string;
  readonly resource: string;
  /** Only these declared scopes are accepted when supplied. */
  readonly scopes?: ReadonlyArray<OAuthScope.OAuthScope>;
}

export interface AccessTokenVerifierOptions extends AccessTokenVerifierWithKeySetOptions {
  /** Trusted keys from the issuer's JWKS; reacquire this verifier when keys rotate. */
  readonly publicKeys: ReadonlyArray<Jwk.PublicJwk>;
}

export const makeVerifier = Effect.fnUntraced(function* <
  Scope extends OAuthScope.OAuthScope,
  Subject extends string,
>(
  options: AccessTokenVerifierWithKeySetOptions,
  scope: Schema.Codec<Scope, string>,
  subject: Schema.Codec<Subject, string>,
) {
  const signature = yield* Signature.Signature;
  const keys = yield* Jwks.Jwks;

  if (subject.ast.encoding !== undefined) return yield* ConfigurationError.make({});
  const ScopeSchema = Schema.toType(scope);
  const SubjectSchema = nonEmptySubject(subject);
  const ScopesSchema = makeScopesSchema(ScopeSchema);
  const AccessTokenClaimsSchema = makeAccessTokenClaimsSchema(SubjectSchema);
  const AccessSchema = makeAccessSchema(ScopeSchema, Schema.toType(SubjectSchema));

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

export const makeLocalVerifier = Effect.fnUntraced(function* <
  Scope extends OAuthScope.OAuthScope,
  Subject extends string,
>(
  options: AccessTokenVerifierOptions,
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

  return yield* makeVerifier(options, scope, subject).pipe(Effect.provideService(Jwks.Jwks, keys));
});
