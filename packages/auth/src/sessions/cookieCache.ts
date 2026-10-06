import { Crypto, DateTime, Effect, Redacted, Schema } from "effect";
import { Base64Url } from "effect/encoding";

import { reportAuthFailure } from "../internal/diagnostics";
import type { AuthCredentialCommand } from "../operations/credentials";
import { makeSessionSigningCodec, SessionSigningKeys } from "./crypto";
import { SessionInvalid, SessionUnavailable } from "./errors";
import type { SessionMetadata } from "./models";
import { type SessionPolicy, validateSessionTimeline } from "./policy";

export type SessionCacheCommand = AuthCredentialCommand & { readonly slot: "session-cache" };

/** Replaceable request cache. Entries bind a public session snapshot to its exact credential.
 * Cache failures fall back to authoritative verification; management never uses this service.
 * Implementations report unexpected backend failures before normalizing them to SessionUnavailable. */
export interface SessionCookieCache<Session> {
  readonly read: (
    credential: Redacted.Redacted<string>,
    cached: Redacted.Redacted<string>,
  ) => Effect.Effect<Session, SessionInvalid | SessionUnavailable>;
  readonly write: (
    credential: Redacted.Redacted<string>,
    session: Session,
    checkedAt: DateTime.Utc,
  ) => Effect.Effect<SessionCacheCommand, SessionUnavailable>;
}

/** A signed cookie avoids a storage lookup only for the explicitly configured window. */
export const makeSessionCookieCache = Effect.fnUntraced(function* <
  S extends Schema.Codec<SessionMetadata, unknown, unknown, unknown>,
>(moduleId: string, sessionSchema: S, policy: SessionPolicy) {
  const maximumAge = policy.positiveCacheMillis ?? 0;

  if (maximumAge === 0)
    return {
      read: () => Effect.fail(SessionInvalid.make({})),
      write: () => Effect.fail(SessionUnavailable.make({})),
    } satisfies SessionCookieCache<S["Type"]>;

  const SessionCodec: Schema.Codec<
    S["Type"],
    S["Encoded"],
    S["DecodingServices"],
    S["EncodingServices"]
  > = sessionSchema;

  const Envelope = Schema.Struct({
    purpose: Schema.Literal("effect-auth/session-cache"),
    moduleId: Schema.Literal(moduleId),
    issuer: Schema.Literal(policy.issuer),
    audience: Schema.Literal(policy.audience),
    generation: Schema.Literal(policy.generation),
    credentialDigest: Schema.String,
    cachedAt: Schema.DateTimeUtcFromMillis,
    expiresAt: Schema.DateTimeUtcFromMillis,
    session: SessionCodec,
  });

  const signing = yield* makeSessionSigningCodec(
    Envelope,
    yield* SessionSigningKeys,
    policy.maximumTokenBytes,
  );

  const crypto = yield* Crypto.Crypto;
  const encoder = new TextEncoder();

  const digest = (credential: Redacted.Redacted<string>) =>
    crypto.digest("SHA-256", encoder.encode(Redacted.value(credential))).pipe(
      Effect.tapCause((cause) => reportAuthFailure("session-crypto", cause)),
      Effect.map(Base64Url.encode),
      Effect.mapError(() => SessionUnavailable.make({})),
    );

  return {
    read: Effect.fnUntraced(function* (
      credential: Redacted.Redacted<string>,
      cached: Redacted.Redacted<string>,
    ) {
      const envelope = yield* signing.decode(cached);
      const credentialDigest = yield* digest(credential);
      const now = DateTime.toEpochMillis(yield* DateTime.now);
      const cachedAt = DateTime.toEpochMillis(envelope.cachedAt);
      const expiresAt = DateTime.toEpochMillis(envelope.expiresAt);

      if (
        maximumAge <= 0 ||
        cachedAt > now ||
        expiresAt <= now ||
        expiresAt <= cachedAt ||
        expiresAt - cachedAt > maximumAge ||
        envelope.credentialDigest !== credentialDigest
      )
        return yield* SessionInvalid.make({});
      yield* validateSessionTimeline(envelope.session, policy);

      return envelope.session;
    }),
    write: Effect.fnUntraced(function* (
      credential: Redacted.Redacted<string>,
      session: S["Type"],
      checkedAt: DateTime.Utc,
    ) {
      const now = yield* DateTime.now;

      const expiresAtMillis = Math.min(
        DateTime.toEpochMillis(checkedAt) + maximumAge,
        DateTime.toEpochMillis(session.expiresAt),
        DateTime.toEpochMillis(session.absoluteExpiresAt),
      );

      if (expiresAtMillis <= DateTime.toEpochMillis(now)) return yield* SessionUnavailable.make({});

      const cached = yield* signing.encode({
        purpose: "effect-auth/session-cache",
        moduleId,
        issuer: policy.issuer,
        audience: policy.audience,
        generation: policy.generation,
        credentialDigest: yield* digest(credential),
        cachedAt: checkedAt,
        expiresAt: DateTime.makeUnsafe(expiresAtMillis),
        session,
      });

      return {
        _tag: "Issue" as const,
        slot: "session-cache" as const,
        credential: cached,
        expiresAtMillis,
      };
    }),
  } satisfies SessionCookieCache<S["Type"]>;
});
