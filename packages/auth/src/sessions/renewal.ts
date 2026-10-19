import * as DateTime from "effect/DateTime";
import * as Schema from "effect/Schema";

/** Projection of a decoded public session; never a credential or authority source. */
export const RenewalSession = Schema.toType(
  Schema.Struct({
    sessionId: Schema.String,
    issuedAt: Schema.DateTimeUtcFromMillis,
    renewAfterMillis: Schema.optionalKey(Schema.Natural),
  }),
);

export const renewalKey = (session: typeof RenewalSession.Type): string =>
  JSON.stringify([session.sessionId, DateTime.toEpochMillis(session.issuedAt)]);
