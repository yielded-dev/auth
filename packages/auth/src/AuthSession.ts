import {
  Context,
  Crypto,
  DateTime,
  Duration,
  Effect,
  Layer,
  Option,
  type Redacted,
  Schema,
} from "effect";

import { AuthTokenCodec } from "./AuthTokenCodec";
import type { IdentityResolutionError, InvalidSession } from "./Errors";
import { AuthTokenError } from "./Errors";
import { AuthPolicy, revalidateSessionClaims } from "./Policy";
import {
  type Email,
  type SubjectId,
  SessionClaims,
  SessionSummary,
  SessionToken,
  SessionTokenId,
} from "./Schema";

export class IssuedSession extends Schema.Class<IssuedSession>("effect-auth/IssuedSession")({
  token: SessionToken,
  summary: SessionSummary,
}) {}

/** A verified session and an optional replacement issued by rolling renewal. */
export interface VerifiedSession {
  readonly claims: SessionClaims;
  readonly renewal: Option.Option<IssuedSession>;
}

const decodeSessionTokenId = Schema.decodeEffect(SessionTokenId);

export interface IssueSessionOptions {
  /** App-defined claims, signed into the envelope but opaque to effect-auth. */
  readonly ext?: unknown;
}

/** Flow data available when effect-auth issues a session through its HTTP API. */
export interface SessionExtContext {
  readonly subjectId: SubjectId;
  readonly email: Email;
}

/** A verified session whose app-defined extension has been decoded by its schema. */
export interface VerifiedSessionWithExt<A> extends VerifiedSession {
  readonly ext: Option.Option<A>;
}

export interface AuthSessionWithExtService<A> {
  readonly issue: (subjectId: SubjectId, ext: A) => Effect.Effect<IssuedSession, AuthTokenError>;
  readonly verify: (
    token: Redacted.Redacted<string>,
  ) => Effect.Effect<VerifiedSessionWithExt<A>, InvalidSession | AuthTokenError>;
  /** Verifies the token and renews it when the configured rolling interval is due. */
  readonly verifyAndRenew: (
    token: Redacted.Redacted<string>,
  ) => Effect.Effect<
    VerifiedSessionWithExt<A>,
    InvalidSession | AuthTokenError | IdentityResolutionError
  >;
  /** Issues from flow data using the optional builder in the declaration. */
  readonly issueFromContext: (
    context: SessionExtContext,
  ) => Effect.Effect<IssuedSession, AuthTokenError>;
}

export type SessionExtBuilder<A> = (context: SessionExtContext) => Effect.Effect<A>;

type AuthSessionWithExtOptions<S extends Schema.Codec<unknown, unknown>> = {
  /** App-defined claims schema. The decoded type becomes the service extension type. */
  readonly ext: S;
} & (SessionExtContext extends S["Encoded"]
  ? {
      /** Overrides automatic decoding from the HTTP session context. */
      readonly build?: SessionExtBuilder<NoInfer<S["Type"]>>;
    }
  : {
      /** Required when the schema cannot decode the HTTP session context directly. */
      readonly build: SessionExtBuilder<NoInfer<S["Type"]>>;
    });

type AuthSessionWithExtDefinition<S extends Schema.Codec<unknown, unknown>> =
  SessionExtContext extends S["Encoded"]
    ? S | AuthSessionWithExtOptions<S>
    : AuthSessionWithExtOptions<S>;

/** Context service class produced by {@link AuthSession.WithExt}. */
export interface AuthSessionWithExtClass<Self, Id extends string, A> extends Context.ServiceClass<
  Self,
  Id,
  AuthSessionWithExtService<A>
> {
  readonly ext: Schema.Codec<A, unknown>;
  readonly layer: Layer.Layer<Self, never, AuthSession>;
}

const makeAuthSessionWithExt =
  <Self>() =>
  <const Id extends string, S extends Schema.Codec<unknown, unknown>>(
    id: Id,
    definition: AuthSessionWithExtDefinition<S>,
  ): AuthSessionWithExtClass<Self, Id, S["Type"]> => {
    const definitionIsSchema = Schema.isSchema(definition);
    const ext = definitionIsSchema ? (definition as S) : definition.ext;
    const build = definitionIsSchema ? undefined : definition.build;
    const Service = Context.Service<Self, AuthSessionWithExtService<S["Type"]>>()(id);
    const extCodec: Schema.Codec<S["Type"], S["Encoded"]> = ext;
    const encodeExt = Schema.encodeEffect(extCodec);
    const decodeContext = Schema.decodeEffect(extCodec);
    // oxlint-disable-next-line no-restricted-properties -- SessionClaims.ext is an intentionally unknown wire boundary.
    const decodeExt = Schema.decodeUnknownEffect(ext);

    const layer = Layer.effect(
      Service,
      Effect.map(AuthSession, (sessions) => {
        const issue = Effect.fn(`${id}.issue`)(function* (subjectId: SubjectId, ext: S["Type"]) {
          const encoded = yield* encodeExt(ext).pipe(
            Effect.mapError((error) =>
              AuthTokenError.make({
                message: `Session extension encoding failed: ${error.message}`,
              }),
            ),
          );

          return yield* sessions.issue(subjectId, { ext: encoded });
        });

        return Service.of({
          issue,
          verify: Effect.fn(`${id}.verify`)(function* (token) {
            const claims = yield* sessions.verify(token);
            const ext = yield* Effect.option(decodeExt(claims.ext));

            return { claims, ext, renewal: Option.none() };
          }),
          verifyAndRenew: Effect.fn(`${id}.verifyAndRenew`)(function* (token) {
            const verified = yield* sessions.verifyAndRenew(token);
            const ext = yield* Effect.option(decodeExt(verified.claims.ext));

            return { ...verified, ext };
          }),
          issueFromContext: Effect.fn(`${id}.issueFromContext`)(function* (context) {
            const ext =
              build === undefined
                ? // The options type admits this branch only when the context
                  // structurally satisfies the schema's encoded input. TS does
                  // not narrow indexed access types through that conditional.
                  yield* decodeContext(context as S["Encoded"]).pipe(
                    Effect.mapError((error) =>
                      AuthTokenError.make({
                        message: `Session extension construction failed: ${error.message}`,
                      }),
                    ),
                  )
                : yield* build(context);

            return yield* issue(context.subjectId, ext);
          }),
        });
      }),
    );

    return Object.assign(Service, {
      ext,
      layer,
    });
  };

/**
 * Stateless session issuance and verification. Each token has a fixed expiry;
 * authenticated HTTP activity can replace it after the configured renewal
 * interval. There is no per-session revocation. Sign-out removes the browser
 * cookie, and bulk invalidation happens through key removal or by bumping the
 * configured session generation.
 */
export class AuthSession extends Context.Service<
  AuthSession,
  {
    readonly issue: (
      subjectId: SubjectId,
      options?: IssueSessionOptions,
    ) => Effect.Effect<IssuedSession, AuthTokenError>;
    readonly verify: (
      token: Redacted.Redacted<string>,
    ) => Effect.Effect<SessionClaims, InvalidSession | AuthTokenError>;
    /** Verifies the token and issues a replacement when rolling renewal is due. */
    readonly verifyAndRenew: (
      token: Redacted.Redacted<string>,
    ) => Effect.Effect<VerifiedSession, InvalidSession | AuthTokenError | IdentityResolutionError>;
  }
>()("effect-auth/AuthSession") {
  /**
   * Declares an app-typed session service from one extension schema. Passing
   * the schema directly automatically constructs extensions from compatible
   * HTTP session context; schemas with derived inputs provide a `build`
   * override. The core service remains opaque: this wrapper encodes before
   * issuance and decodes after verification, preserving `None` for legacy or
   * undecodable extensions.
   */
  static readonly WithExt = makeAuthSessionWithExt;

  static readonly layer: Layer.Layer<AuthSession, never, AuthTokenCodec | Crypto.Crypto> =
    Layer.effect(AuthSession)(
      Effect.gen(function* () {
        const policy = yield* AuthPolicy;
        const codec = yield* AuthTokenCodec;
        const crypto = yield* Crypto.Crypto;

        const issue = Effect.fn("AuthSession.issue")(function* (
          subjectId: SubjectId,
          options?: IssueSessionOptions,
        ) {
          const now = yield* DateTime.now;
          const expiresAt = DateTime.addDuration(now, policy.sessionLifetime);

          const uuid = yield* crypto.randomUUIDv4.pipe(
            Effect.mapError(() =>
              AuthTokenError.make({ message: "Secure randomness unavailable" }),
            ),
          );

          const tokenId = yield* decodeSessionTokenId(uuid).pipe(Effect.orDie);

          const claims = SessionClaims.make({
            ver: 1,
            gen: policy.sessionGeneration,
            kid: codec.activeKeyId,
            sub: subjectId,
            ...(options?.ext === undefined ? {} : { ext: options.ext }),
            iss: policy.issuer,
            aud: policy.audience,
            iat: now,
            exp: expiresAt,
            jti: tokenId,
          });

          const token = yield* codec.encodeSession(claims);

          return IssuedSession.make({
            token,
            summary: SessionSummary.make({ subjectId, expiresAt }),
          });
        });

        const verify = Effect.fn("AuthSession.verify")(function* (
          token: Redacted.Redacted<string>,
        ) {
          const claims = yield* codec.decodeSession(token);

          return yield* revalidateSessionClaims(claims, {
            issuer: policy.issuer,
            audience: policy.audience,
            sessionGeneration: policy.sessionGeneration,
            allowedSigningKeyIds: new Set(codec.keyIds),
          });
        });

        const renewIfDue = Effect.fn("AuthSession.renewIfDue")(function* (claims: SessionClaims) {
          const now = yield* DateTime.now;
          const issuedAtMillis = DateTime.toEpochMillis(claims.iat);
          const tokenLifetimeMillis = DateTime.toEpochMillis(claims.exp) - issuedAtMillis;
          const tokenAgeMillis = DateTime.toEpochMillis(now) - issuedAtMillis;
          const configuredLifetimeMillis = Duration.toMillis(policy.sessionLifetime);
          const renewalIntervalMillis = Duration.toMillis(policy.sessionRenewalInterval);

          const renewalDue =
            tokenLifetimeMillis !== configuredLifetimeMillis ||
            tokenAgeMillis >= renewalIntervalMillis;

          if (!renewalDue) return Option.none<IssuedSession>();

          const renewed = yield* issue(
            claims.sub,
            claims.ext === undefined ? undefined : { ext: claims.ext },
          );

          return Option.some(renewed);
        });

        return AuthSession.of({
          issue,
          verify,
          verifyAndRenew: Effect.fn("AuthSession.verifyAndRenew")(function* (token) {
            const claims = yield* verify(token);
            const renewal = yield* renewIfDue(claims);

            return { claims, renewal };
          }),
        });
      }),
    );
}
