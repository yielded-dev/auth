import { Effect, Schema } from "effect";

import type { ProviderDefinition } from "./providerDefinition";
import { provider as oidcProvider } from "./providers/layer";
import { OpenIdConnectConfigurationError } from "./providers/models";
import type { Requirements } from "./providers/oidc";
import { resolveOptions } from "./providers/options";
import { GoogleUserProfile } from "./providers/profile";
import type { OAuthUnavailable } from "./signInErrors";

const Registration = Schema.Struct({
  clientId: Schema.NonEmptyString,
  clientSecret: Schema.toType(Schema.RedactedFromValue(Schema.NonEmptyString)),
  configurationGeneration: Schema.optionalKey(Schema.Int),
  issuance: Schema.optionalKey(Schema.Literals(["active", "retired"])),
  scopes: Schema.optionalKey(Schema.Array(Schema.Literals(["openid", "profile", "email"]))),
  hd: Schema.optionalKey(Schema.NonEmptyString.check(Schema.isMaxLength(253))),
});

export type ProviderRegistration = typeof Registration.Type;

export type ProviderOptions = {
  /** Per-request timeout in seconds, from 1 to 30. Defaults to 10. */
  readonly timeoutSeconds?: number;
} & (ProviderRegistration | { readonly registrations: ReadonlyArray<ProviderRegistration> });

export { GoogleUserProfile };

/** Sign in with Google through the shared OIDC implementation. Defaults to the
 * openid scope, client_secret_post, S256 PKCE and advertised RS256.
 * GoogleUserProfile is carried through ID-token projection. Authorization always
 * sends prompt=select_account and access_type=offline so connected access can
 * receive a refresh token. hd is only a consent-screen hint: enforce Workspace
 * policy against the verified profile claim. No UserInfo request or retained API
 * access is installed. Credentials are captured when the host builds its Layer;
 * supply HttpClient and crypto in that Scope. */
export const provider = (
  options: ProviderOptions,
): ProviderDefinition<OpenIdConnectConfigurationError | OAuthUnavailable, Requirements> => ({
  configure: (binding) =>
    resolveOptions(() =>
      Effect.gen(function* () {
        const registrations = yield* Schema.decodeEffect(Schema.Array(Registration))(
          "registrations" in options ? options.registrations : [options],
        ).pipe(Effect.mapError(() => OpenIdConnectConfigurationError.make({ reason: "provider" })));

        return yield* oidcProvider({
          registrations: registrations.map(({ hd, ...registration }) => ({
            ...registration,
            protocol: "oidc" as const,
            issuer: "https://accounts.google.com",
            tokenEndpointAuthMethod: "client_secret_post" as const,
            profileSchema: GoogleUserProfile,
            authorizationParameters: {
              prompt: "select_account",
              access_type: "offline",
              ...(hd === undefined ? {} : { hd }),
            },
          })),
          ...(options.timeoutSeconds === undefined
            ? {}
            : { timeoutSeconds: options.timeoutSeconds }),
        }).configure(binding);
      }),
    ),
});
