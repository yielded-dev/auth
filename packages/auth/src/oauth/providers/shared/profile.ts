import * as Cause from "effect/Cause";
import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";

import { OAuthProtocolRejected } from "../../signInErrors";
import { type OAuthDisplayProfile, type OAuthNativeName } from "../../signInModels";

const text = Schema.String.check(Schema.isMaxLength(256));
const url = Schema.String.check(Schema.isMaxLength(2048));

/** Standard OpenID Connect user claims projected from verified ID tokens.
 * Protocol claims and credentials are excluded; provider assertions never
 * authorize local account linking by themselves. */
export const OidcStandardUserProfile = Schema.Struct({
  name: Schema.optionalKey(text),
  given_name: Schema.optionalKey(text),
  family_name: Schema.optionalKey(text),
  middle_name: Schema.optionalKey(text),
  nickname: Schema.optionalKey(text),
  preferred_username: Schema.optionalKey(text),
  profile: Schema.optionalKey(url),
  picture: Schema.optionalKey(url),
  website: Schema.optionalKey(url),
  email: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(320))),
  email_verified: Schema.optionalKey(Schema.Boolean),
  gender: Schema.optionalKey(text),
  birthdate: Schema.optionalKey(text),
  zoneinfo: Schema.optionalKey(text),
  locale: Schema.optionalKey(text),
  phone_number: Schema.optionalKey(text),
  phone_number_verified: Schema.optionalKey(Schema.Boolean),
  address: Schema.optionalKey(
    Schema.Struct({
      formatted: Schema.optionalKey(url),
      street_address: Schema.optionalKey(url),
      locality: Schema.optionalKey(text),
      region: Schema.optionalKey(text),
      postal_code: Schema.optionalKey(text),
      country: Schema.optionalKey(text),
    }),
  ),
  updated_at: Schema.optionalKey(
    Schema.Int.check(Schema.isBetween({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER })),
  ),
});

export type OidcStandardUserProfile = typeof OidcStandardUserProfile.Type;

const firstConsentName = Schema.Struct({
  name: Schema.optionalKey(
    Schema.Struct({
      firstName: Schema.optionalKey(text),
      lastName: Schema.optionalKey(text),
    }),
  ),
});

/** Decode Apple's web first-consent `user` form field. Malformed values carry no name. */
export const decodeAppleCallbackUser = Effect.fnUntraced(function* (
  user: string | undefined,
): Effect.fn.Return<OAuthNativeName | undefined> {
  if (user === undefined) return undefined;

  const parsed = yield* Schema.decodeEffect(Schema.fromJsonString(Schema.Unknown))(user).pipe(
    Effect.orElseSucceed(() => undefined),
  );

  if (parsed === undefined) return undefined;

  const payload = yield* Schema.decodeUnknownEffect(firstConsentName)(parsed).pipe(
    Effect.orElseSucceed(() => undefined),
  );

  if (payload?.name === undefined) return undefined;

  return {
    ...(payload.name.firstName === undefined ? {} : { givenName: payload.name.firstName }),
    ...(payload.name.lastName === undefined ? {} : { familyName: payload.name.lastName }),
  };
});

/** Fill missing ID-token names from Apple's first-consent name. Apple sends it only
 * once; later sign-ins leave these fields absent. */
export const mergeAppleName = (
  claims: Schema.JsonObject,
  name: OAuthNativeName | undefined,
): Schema.JsonObject => {
  if (name === undefined) return claims;
  const given = name.givenName?.trim();
  const family = name.familyName?.trim();

  const parts = [given, family].filter(
    (value): value is string => value !== undefined && value.length > 0,
  );

  const joined = parts.join(" ");
  // given_name and family_name each allow 256. The combined name must too.
  const mergedName = joined.length > 0 && joined.length <= 256 ? joined : undefined;

  return {
    ...claims,
    ...(given === undefined || given.length === 0 || claims.given_name !== undefined
      ? {}
      : { given_name: given }),
    ...(family === undefined || family.length === 0 || claims.family_name !== undefined
      ? {}
      : { family_name: family }),
    ...(mergedName === undefined || claims.name !== undefined ? {} : { name: mergedName }),
  };
};

/** Standard OpenID Connect user claims, plus Google's optional hosted domain.
 * Generic OIDC uses this schema unless a preset supplies its own. The adapter
 * projects these from verified ID tokens, optionally merged with UserInfo.
 * Protocol claims and credentials are excluded; provider assertions never
 * authorize local account linking by themselves. */
export const OidcUserProfile = Schema.Struct({
  ...OidcStandardUserProfile.fields,
  /** Hosted domain for a Google Workspace or Cloud organization. Present when
   * the verified claims include `hd`. */
  hd: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(253))),
});

export type OidcUserProfile = typeof OidcUserProfile.Type;

/** Fill missing ID-token claims from UserInfo. Omit null standard profile claims
 * such as Discord's unset display name or email; leave custom claims to the host schema. */
export const mergeUserInfo = (userInfo: Schema.JsonObject, claims: Schema.JsonObject) => ({
  ...Object.fromEntries(
    Object.entries(userInfo).filter(
      ([key, value]) => value !== null || !Object.hasOwn(OidcStandardUserProfile.fields, key),
    ),
  ),
  ...claims,
});

const standardFlags = ["email_verified", "phone_number_verified"] as const;

/** Keep every standard claim, and replace only flags the host codec normalized. */
const claimsWithHostFlags = (claims: unknown, profile: Schema.JsonObject) =>
  Schema.decodeUnknownEffect(Schema.Record(Schema.String, Schema.Unknown))(claims).pipe(
    Effect.map((raw) => {
      const normalized = { ...raw };

      for (const key of standardFlags) {
        const value = profile[key];

        if (typeof value === "boolean") normalized[key] = value;
      }

      return normalized;
    }),
  );

export const decodeOidcProfile = Effect.fn("OpenIdConnect.decodeProfile")(function* (
  claims: unknown,
  schema: Schema.Codec<Schema.JsonObject>,
): Effect.fn.Return<OAuthDisplayProfile | undefined, OAuthProtocolRejected> {
  // oxlint-disable-next-line no-restricted-properties -- Project claims from an ID token already verified against this issuer.
  const profile = yield* Schema.decodeUnknownEffect(schema)(claims).pipe(
    Effect.catchCause((cause) =>
      Effect.failCause(Cause.map(cause, () => OAuthProtocolRejected.make({}))),
    ),
  );

  // A host codec may turn Apple's "true"/"false" into a boolean and drop every
  // other claim. Display still comes from the verified claims; only that flag moves.
  const display = yield* Schema.decodeUnknownEffect(OidcStandardUserProfile)(claims).pipe(
    Effect.catch(() =>
      claimsWithHostFlags(claims, profile).pipe(
        Effect.flatMap((value) => Schema.decodeEffect(OidcStandardUserProfile)(value)),
      ),
    ),
    Effect.mapError(() => OAuthProtocolRejected.make({})),
  );

  if (Object.keys(profile).length === 0) return undefined;

  // The casual nickname, such as Discord's display name, reads better than a username.
  const displayName =
    display.name?.trim() || display.nickname?.trim() || display.preferred_username;

  return {
    ...(displayName === undefined ? {} : { displayName }),
    ...(display.preferred_username === undefined ? {} : { handle: display.preferred_username }),
    ...(display.picture === undefined ? {} : { avatarUrl: display.picture }),
    ...(display.profile === undefined ? {} : { profileUrl: display.profile }),
    ...(display.email === undefined ? {} : { email: display.email }),
    ...(display.email_verified === undefined ? {} : { emailVerified: display.email_verified }),
    providerData: profile,
  };
});
