import { Context, Effect, Schema, type Types } from "effect";

import { AccessClaims, type Authentication, Scope, type Unavailable } from "./models";

export const standardOpenIdScopes = ["openid", "profile", "email"] as const;

const makeResultSchema = <Scope extends string>(scope: Schema.Codec<Scope>) =>
  Schema.Struct({
    scopes: Schema.Array(scope).check(Schema.isMaxLength(32)),
    claims: Schema.optionalKey(AccessClaims),
  });

export const OpenIdAuthorizationResult = makeResultSchema(Scope);

export type OpenIdAuthorizationResult<Scope extends string = string> = ReturnType<
  typeof makeResultSchema<Scope>
>["Type"];

export const makeAuthorization = <const Id extends string, Scope extends string>(
  id: Id,
  scope: Schema.Codec<Scope>,
) => {
  /** Recheck permission at code exchange and refresh. Return only requested
   * scopes; an empty result denies issuance. Claims never enter an ID token.
   */
  const Service = Context.Service<
    {
      readonly server: Id;
      readonly kind: "openid-authorization";
      readonly scopes: Types.Invariant<Scope>;
    },
    {
      readonly authorize: (input: {
        readonly authentication: Authentication;
        readonly clientId: string;
        readonly resource: string;
        readonly scopes: ReadonlyArray<Scope>;
        readonly grantType: "authorization_code" | "refresh_token";
      }) => Effect.Effect<OpenIdAuthorizationResult<Scope>, Unavailable>;
    }
  >()(`effect-auth/OAuthServer/${id}/Authorization`);

  return {
    Service,
    Result: makeResultSchema(scope),
    default: Service.of({
      authorize: ({ scopes }) =>
        Effect.succeed({
          scopes: scopes.filter((scope) =>
            standardOpenIdScopes.some((standard) => standard === scope),
          ),
        }),
    }),
  };
};
