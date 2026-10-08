import { Effect, Schema } from "effect";

import { OAuthProtocolRejected } from "../signInErrors";
import { type OAuthDisplayProfile } from "../signInModels";

const text = Schema.String.check(Schema.isMaxLength(256));
const url = Schema.String.check(Schema.isMaxLength(2048));

const standardOidcUserProfile = Schema.Struct({
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

/** Standard OpenID Connect user claims projected from verified ID tokens.
 * Protocol claims and credentials are excluded; provider assertions never
 * authorize local account linking by themselves. */
export const OidcStandardUserProfile = standardOidcUserProfile;
export type OidcStandardUserProfile = typeof OidcStandardUserProfile.Type;

/** Standard OpenID Connect user claims, plus Google's optional hosted domain.
 * Generic OIDC uses this schema unless a preset supplies its own. The adapter
 * projects these from verified ID tokens, optionally merged with UserInfo.
 * Protocol claims and credentials are excluded; provider assertions never
 * authorize local account linking by themselves. */
export const OidcUserProfile = Schema.Struct({
  ...standardOidcUserProfile.fields,
  /** Hosted domain for a Google Workspace or Cloud organization. Present when
   * the verified claims include `hd`. */
  hd: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(253))),
});

export type OidcUserProfile = typeof OidcUserProfile.Type;

/** Google ID-token claims, including optional Workspace hosted domain. The preset
 * passes `hd` as a consent hint; applications enforce workspace policy against
 * this verified claim. */
export const GoogleUserProfile = OidcUserProfile;
export type GoogleUserProfile = OidcUserProfile;

/** GitLab ID-token claims, including optional group membership. Group lists are
 * application policy, not local identity. */
export const GitLabUserProfile = Schema.Struct({
  ...standardOidcUserProfile.fields,
  groups: Schema.optionalKey(Schema.Array(url).check(Schema.isMaxLength(1024))),
  groups_direct: Schema.optionalKey(Schema.Array(url).check(Schema.isMaxLength(1024))),
});

export type GitLabUserProfile = typeof GitLabUserProfile.Type;

/** Standard profile and workspace identifiers projected only from verified Slack
 * ID tokens. Workspace membership is application policy, not local identity. */
export const SlackUserProfile = Schema.Struct({
  ...standardOidcUserProfile.fields,
  "https://slack.com/team_id": Schema.optionalKey(text),
  "https://slack.com/user_id": Schema.optionalKey(text),
});

export type SlackUserProfile = typeof SlackUserProfile.Type;

export const decodeOidcProfile = Effect.fn("OpenIdConnect.decodeProfile")(function* (
  claims: unknown,
  schema: Schema.Codec<Schema.JsonObject>,
): Effect.fn.Return<OAuthDisplayProfile | undefined, OAuthProtocolRejected> {
  // oxlint-disable-next-line no-restricted-properties -- Project claims from an ID token already verified against this issuer.
  const profile = yield* Schema.decodeUnknownEffect(schema)(claims).pipe(
    Effect.mapError(() => OAuthProtocolRejected.make({})),
  );

  const display = yield* Schema.decodeUnknownEffect(standardOidcUserProfile)(claims).pipe(
    Effect.mapError(() => OAuthProtocolRejected.make({})),
  );

  if (Object.keys(profile).length === 0) return undefined;
  const displayName = display.name?.trim() || display.preferred_username;

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
