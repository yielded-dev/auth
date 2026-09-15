import { Effect, Schema } from "effect";

import { OAuthProtocolRejected } from "../signInErrors";
import type { OAuthDisplayProfile } from "../signInModels";

const text = Schema.String.check(Schema.isMaxLength(256));
const url = Schema.String.check(Schema.isMaxLength(2048));

/** Standard OpenID Connect user claims returned in a verified ID token. This
 * does not request additional scopes or fetch UserInfo. Protocol claims and
 * credentials are excluded; values such as email_verified describe the provider's
 * assertion and never authorize local account linking by themselves. */
export const OidcUserProfile = Schema.Struct({
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

export type OidcUserProfile = typeof OidcUserProfile.Type;

export const decodeOidcProfile = Effect.fn("OpenIdClient.decodeProfile")(function* (
  claims: unknown,
): Effect.fn.Return<OAuthDisplayProfile | undefined, OAuthProtocolRejected> {
  // oxlint-disable-next-line no-restricted-properties -- Select standard user claims from an already verified ID token.
  const profile = yield* Schema.decodeUnknownEffect(OidcUserProfile)(claims).pipe(
    Effect.mapError(() => OAuthProtocolRejected.make({})),
  );

  if (Object.keys(profile).length === 0) return undefined;
  const displayName = profile.name?.trim() || profile.preferred_username;

  return {
    ...(displayName === undefined ? {} : { displayName }),
    ...(profile.preferred_username === undefined ? {} : { handle: profile.preferred_username }),
    ...(profile.picture === undefined ? {} : { avatarUrl: profile.picture }),
    ...(profile.profile === undefined ? {} : { profileUrl: profile.profile }),
    ...(profile.email === undefined ? {} : { email: profile.email }),
    ...(profile.email_verified === undefined ? {} : { emailVerified: profile.email_verified }),
    providerData: profile,
  };
});
