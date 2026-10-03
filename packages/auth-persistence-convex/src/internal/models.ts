import { Record } from "@yielded/auth/OAuthServer";
import { Schema } from "effect";

const identifier = Schema.NonEmptyString.check(Schema.isMaxLength(2048));

export const GrantKey = Schema.Struct({ namespace: identifier, grantId: identifier });
export const Insert = Schema.Struct({ ...GrantKey.fields, payload: Schema.String });
export const CompareAndSet = Schema.Struct({ ...Insert.fields, version: Record.fields.version });

export const Cleanup = Schema.Struct({
  limit: Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 1000 })),
});

/** Effect Schema owns the persisted payload; Convex indexes only its retention deadline. */
export const Payload = Schema.fromJsonString(Record);

export const StoredGrant = Schema.Struct({
  ...GrantKey.fields,
  payload: Schema.String,
  expiresAtMillis: Record.fields.expiresAtMillis,
});
