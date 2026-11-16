import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";
import type * as Types from "effect/Types";

import * as OAuthScope from "../../OAuthScope";
import type { SubjectId } from "../../Schema";
import {
  AccessClaims,
  type Authentication,
  Scope,
  maximumScopes,
  type Unavailable,
} from "./models";

export const standardOpenIdScopes = [
  OAuthScope.make("openid"),
  OAuthScope.make("profile"),
  OAuthScope.make("email"),
];

const isStandardOpenIdScope = Schema.is(Schema.Literals(standardOpenIdScopes));

export const makeResultSchema = <Scope extends OAuthScope.OAuthScope>(
  scope: Schema.Codec<Scope, string>,
) =>
  Schema.Struct({
    // The server then requires a unique subset of the requested scopes.
    scopes: Schema.Array(scope).check(Schema.isMaxLength(maximumScopes)),
    claims: Schema.optionalKey(AccessClaims),
  });

export const OpenIdAuthorizationResult = makeResultSchema(Scope);

export type OpenIdAuthorizationResult<Scope extends OAuthScope.OAuthScope = OAuthScope.OAuthScope> =
  ReturnType<typeof makeResultSchema<Scope>>["Type"];

export interface AuthorizationInput<Scope extends OAuthScope.OAuthScope> {
  readonly clientId: string;
  readonly resource: string;
  readonly scopes: ReadonlyArray<Scope>;
  readonly grantType: "authorization_code" | "refresh_token";
}

export const makeAuthorization = <const Id extends string, Scope extends OAuthScope.OAuthScope>(
  id: Id,
) => {
  /** Recheck permission at code exchange and refresh. Return only requested
   * scopes; an empty result denies issuance. Claims are recomputed each time.
   */
  const Service = Context.Service<
    {
      readonly server: Id;
      readonly kind: "authorization";
      readonly scopes: Types.Invariant<Scope>;
    },
    {
      readonly authorize: (
        input: AuthorizationInput<Scope> & { readonly subjectId: SubjectId },
      ) => Effect.Effect<OpenIdAuthorizationResult<Scope>, Unavailable>;
    }
  >()(`effect-auth/OAuthServer/${id}/Authorization`);

  return {
    Service,
    default: Service.of({ authorize: ({ scopes }) => Effect.succeed({ scopes }) }),
  };
};

export const makeOpenIdAuthorization = <
  const Id extends string,
  Scope extends OAuthScope.OAuthScope,
>(
  id: Id,
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
      readonly authorize: (
        input: AuthorizationInput<Scope> & { readonly authentication: Authentication },
      ) => Effect.Effect<OpenIdAuthorizationResult<Scope>, Unavailable>;
    }
  >()(`effect-auth/OAuthServer/${id}/OpenIdAuthorization`);

  return {
    Service,
    default: Service.of({
      authorize: ({ scopes }) =>
        Effect.succeed({
          scopes: scopes.filter(isStandardOpenIdScope),
        }),
    }),
  };
};
