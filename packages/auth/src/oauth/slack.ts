import { Effect, Schema } from "effect";

import type { ProviderDefinition } from "./providerDefinition";
import { discoveryProfile } from "./providers/discovery";
import { provider as oidcProvider } from "./providers/layer";
import { OpenIdConnectConfigurationError } from "./providers/models";
import type { Requirements } from "./providers/oidc";
import { resolveOptions } from "./providers/options";
import { SlackUserProfile } from "./providers/profile";
import type { OAuthUnavailable } from "./signInErrors";

const Registration = Schema.Struct({
  clientId: Schema.NonEmptyString,
  clientSecret: Schema.toType(Schema.RedactedFromValue(Schema.NonEmptyString)),
  configurationGeneration: Schema.optionalKey(Schema.Int),
  issuance: Schema.optionalKey(Schema.Literals(["active", "retired"])),
  scopes: Schema.optionalKey(Schema.Array(Schema.Literals(["openid", "profile", "email"]))),
  team: Schema.optionalKey(Schema.NonEmptyString.check(Schema.isMaxLength(256))),
});

export type ProviderRegistration = typeof Registration.Type;

export type ProviderOptions = {
  /** Per-request timeout in seconds, from 1 to 30. Defaults to 10. */
  readonly timeoutSeconds?: number;
} & (ProviderRegistration | { readonly registrations: ReadonlyArray<ProviderRegistration> });

/** Sign in with Slack through the shared OIDC implementation. Defaults to the
 * openid scope, client_secret_basic, S256 PKCE and advertised RS256. SlackUserProfile
 * is carried through ID-token projection. Slack does not advertise response iss;
 * the HTTP host must give it a distinct callback. team is only a consent-screen
 * hint: enforce workspace policy against verified profile claims. No UserInfo
 * request or retained API access is installed. Credentials are captured when the
 * host builds its Layer; supply HttpClient and crypto in that Scope. */
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
          registrations: registrations.map(({ team, ...registration }) => ({
            ...registration,
            protocol: "oidc" as const,
            issuer: "https://slack.com",
            responseIssuerMode: "unsupported" as const,
            profileSchema: SlackUserProfile,
            [discoveryProfile]: "slack" as const,
            ...(team === undefined ? {} : { authorizationParameters: { team } }),
          })),
          ...(options.timeoutSeconds === undefined
            ? {}
            : { timeoutSeconds: options.timeoutSeconds }),
        }).configure(binding);
      }),
    ),
});
