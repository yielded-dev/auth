import { Effect, Schema } from "effect";

import type { ProviderDefinition } from "./providerDefinition";
import { provider as oidcProvider } from "./providers/layer";
import { OpenIdConnectConfigurationError } from "./providers/models";
import type { Requirements } from "./providers/oidc";
import { resolveOptions } from "./providers/options";
import { GitLabUserProfile } from "./providers/profile";
import type { OAuthUnavailable } from "./signInErrors";

const Registration = Schema.Struct({
  clientId: Schema.NonEmptyString,
  clientSecret: Schema.toType(Schema.RedactedFromValue(Schema.NonEmptyString)),
  configurationGeneration: Schema.optionalKey(Schema.Int),
  issuance: Schema.optionalKey(Schema.Literals(["active", "retired"])),
  scopes: Schema.optionalKey(Schema.Array(Schema.Literals(["openid", "profile", "email"]))),
  issuer: Schema.optionalKey(Schema.NonEmptyString.check(Schema.isMaxLength(2048))),
});

export type ProviderRegistration = typeof Registration.Type;

export type ProviderOptions = {
  /** Per-request timeout in seconds, from 1 to 30. Defaults to 10. */
  readonly timeoutSeconds?: number;
} & (ProviderRegistration | { readonly registrations: ReadonlyArray<ProviderRegistration> });

export { GitLabUserProfile };

/** Sign in with GitLab through the shared OIDC implementation. Defaults to
 * gitlab.com, the openid scope, client_secret_basic, S256 PKCE and advertised
 * RS256. Pass issuer for a self-hosted instance; the value is preserved exactly,
 * including an optional trailing slash. GitLab does not advertise response iss;
 * the HTTP host must give it a distinct callback. GitLabUserProfile is carried
 * through ID-token projection. Group membership is application policy. No
 * UserInfo request or retained API access is installed. Credentials are captured
 * when the host builds its Layer; supply HttpClient and crypto in that Scope. */
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
          registrations: registrations.map(({ issuer, ...registration }) => ({
            ...registration,
            protocol: "oidc" as const,
            issuer: issuer ?? "https://gitlab.com",
            responseIssuerMode: "unsupported" as const,
            profileSchema: GitLabUserProfile,
          })),
          ...(options.timeoutSeconds === undefined
            ? {}
            : { timeoutSeconds: options.timeoutSeconds }),
        }).configure(binding);
      }),
    ),
});
