import { Context, Effect, Layer, Schema } from "effect";

import { AccessClaims, type Authentication, Scope, type Unavailable } from "./models";

export const OpenIdAuthorizationResult = Schema.Struct({
  scopes: Schema.Array(Scope).check(Schema.isMaxLength(32)),
  claims: Schema.optionalKey(AccessClaims),
});

export type OpenIdAuthorizationResult = typeof OpenIdAuthorizationResult.Type;

/** Recheck application permission before each code exchange and refresh.
 * Return only requested scopes; an empty result denies issuance. Claims are
 * recomputed on every invocation and never copied into an ID token.
 */
export class OpenIdAuthorization extends Context.Service<
  OpenIdAuthorization,
  {
    readonly authorize: (input: {
      readonly authentication: Authentication;
      readonly clientId: string;
      readonly resource: string;
      readonly scopes: ReadonlyArray<string>;
      readonly grantType: "authorization_code" | "refresh_token";
    }) => Effect.Effect<OpenIdAuthorizationResult, Unavailable>;
  }
>()("effect-auth/OAuthServer/OpenIdAuthorization") {
  /** Application scopes require an application authorization service. */
  static readonly default = OpenIdAuthorization.of({
    authorize: ({ scopes }) =>
      Effect.succeed({
        scopes: scopes.filter((scope) => ["openid", "profile", "email"].includes(scope)),
      }),
  });

  static readonly defaultLayer = Layer.succeed(OpenIdAuthorization, OpenIdAuthorization.default);
}
