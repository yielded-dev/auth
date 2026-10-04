import { Effect, Layer } from "effect";

import { OAuthConnectedProtocol } from "../OAuthConnectedProtocol";
import { OAuthProtocol } from "../OAuthProtocol";
import { OAuthConnectedProfile, OAuthPermissionProfileKey } from "../permissionProfile";
import { type ProviderDefinition } from "../providerDefinition";
import { installOAuthConfigurations } from "../providers/configuration";
import type { OpenIdConnectConfigurationError } from "../providers/models";
import type { Requirements } from "../providers/native";
import {
  resolveOptions,
  resolveRegistration,
  type RegistrationOptions,
} from "../providers/options";
import { makeOpenIdConnectOAuthProtocol } from "../providers/protocol";
import { type OAuthUnavailable } from "../signInErrors";
import { gitHubOAuthAppProviderKey } from "./identity";
import type { GitHubOAuthAppConnectedProtocolOptions, GitHubOAuthAppGeneration } from "./models";
import {
  makeGitHubOAuthAppProvider,
  makeGitHubOAuthAppConnectedProtocol,
  makeGitHubOAuthAppProtocol,
} from "./protocol";

/** GitHub.com OAuth App credentials and one or more exact callback destinations. */
export type Registration = Pick<GitHubOAuthAppGeneration, "clientId" | "clientSecret"> &
  RegistrationOptions;

type Transport = {
  /** Per-request timeout in seconds, from 1 to 30. Defaults to 10. */
  readonly timeoutSeconds?: number;
};

export type Options = Transport &
  (Registration | { readonly registrations: ReadonlyArray<Registration> });

export type ConnectedRegistration = Registration &
  Pick<GitHubOAuthAppConnectedProtocolOptions["registrations"][number], "profiles">;

export type ConnectedOptions = Transport &
  (ConnectedRegistration | { readonly registrations: ReadonlyArray<ConnectedRegistration> });

const registration = Effect.fnUntraced(function* (input: Registration) {
  return { ...input, ...(yield* resolveRegistration(input, "github")) };
});

export type ProviderRegistration = Pick<GitHubOAuthAppGeneration, "clientId" | "clientSecret"> &
  Pick<RegistrationOptions, "configurationGeneration" | "issuance">;

export type ProviderOptions = Transport & {
  readonly access?: ReadonlyArray<OAuthConnectedProfile>;
} & (ProviderRegistration | { readonly registrations: ReadonlyArray<ProviderRegistration> });

/** Provider API permissions and token retention, supplied to OAuth.make({ access }). */
export const accessProfile = (options: {
  readonly clientId: string;
  readonly scopes?: ReadonlyArray<string>;
  readonly maximumRefreshLifetimeMillis?: number;
}) =>
  OAuthConnectedProfile.make({
    key: OAuthPermissionProfileKey.make("github"),
    generation: 1,
    issuance: "active",
    provider: gitHubOAuthAppProviderKey,
    clientRegistrationId: options.clientId,
    scopes: options.scopes ?? ["read:user"],
    resources: [],
    retention: "access-and-refresh",
    maximumAccessLifetimeMillis: 8 * 60 * 60 * 1000,
    maximumRefreshLifetimeMillis: options.maximumRefreshLifetimeMillis ?? 30 * 24 * 60 * 60 * 1000,
    refreshAheadMillis: 60_000,
    refresh: "rotating",
    revocation: "cohort",
  });

/** Declare GitHub for Http.layer. The host supplies its provider key and
 * callback destinations. Retired registrations remain available to finish flows.
 * Invalid registrations fail configure with OpenIdConnectConfigurationError. */
export const provider = (
  options: ProviderOptions,
): ProviderDefinition<OpenIdConnectConfigurationError | OAuthUnavailable, Requirements> => ({
  configure: Effect.fn("GitHub.provider.configure")(function* (binding) {
    const registrations = yield* resolveOptions(() =>
      Effect.forEach(
        "registrations" in options ? options.registrations : [options],
        Effect.fnUntraced(function* (input) {
          return {
            ...input,
            ...(yield* resolveRegistration(
              { ...input, callbacks: binding.callbacks },
              binding.provider,
            )),
          };
        }),
      ),
    );

    const providers = yield* Effect.forEach(registrations, makeGitHubOAuthAppProvider);

    const protocol = yield* makeOpenIdConnectOAuthProtocol(
      installOAuthConfigurations({
        providers: providers.map((input) => ({
          ...input,
          provider: binding.provider,
        })),
        timeoutSeconds: options.timeoutSeconds ?? 10,
      }),
    );

    const profiles = options.access;

    if (profiles === undefined) return protocol;

    const connected = yield* makeGitHubOAuthAppConnectedProtocol({
      registrations: registrations.map((input) => ({
        ...input,
        profiles: profiles.filter((profile) => profile.clientRegistrationId === input.clientId),
      })),
      timeoutSeconds: options.timeoutSeconds ?? 10,
    });

    return { ...protocol, connected };
  }),
});

/** GitHub OAuth sign-in. Defaults to callback ID github, generation 1, active
 * issuance and a 10-second request timeout. Does not install HTTP routes.
 * For rotation, provide registrations with one active generation and retain
 * retired generations through their issued flows' lifetime. Configuration is
 * validated when the Layer builds; existing protocol safety rules still apply. */
export const layer = (options: Options) =>
  Layer.effect(
    OAuthProtocol,
    resolveOptions(() =>
      Effect.forEach(
        "registrations" in options ? options.registrations : [options],
        registration,
      ).pipe(
        Effect.map((registrations) => ({
          registrations,
          timeoutSeconds: options.timeoutSeconds === undefined ? 10 : options.timeoutSeconds,
        })),
      ),
    ).pipe(Effect.flatMap(makeGitHubOAuthAppProtocol)),
  );

/** Configure GitHub API connections with the same callback/rotation defaults as
 * layer. Permission profiles remain explicit; connection grants are not logins. */
export const layerConnected = (options: ConnectedOptions) =>
  Layer.effect(
    OAuthConnectedProtocol,
    resolveOptions(() =>
      Effect.forEach(
        "registrations" in options ? options.registrations : [options],
        Effect.fnUntraced(function* (input) {
          return {
            ...(yield* registration(input)),
            profiles: input.profiles,
          };
        }),
      ).pipe(
        Effect.map((registrations) => ({
          registrations,
          timeoutSeconds: options.timeoutSeconds === undefined ? 10 : options.timeoutSeconds,
        })),
      ),
    ).pipe(Effect.flatMap(makeGitHubOAuthAppConnectedProtocol)),
  );
