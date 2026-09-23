import { Effect, Layer } from "effect";

import type { Provider as AppProvider } from "../app/models";
import { OAuthConnectedProfile, OAuthPermissionProfileKey } from "../connectedModels";
import { OAuthConnectedProtocol } from "../OAuthConnectedProtocol";
import { OAuthProtocol } from "../OAuthProtocol";
import type { OpenIdClientConfigurationError } from "../openid-client/models";
import {
  resolveOptions,
  resolveRegistration,
  type RegistrationOptions,
} from "../openid-client/options";
import { makeOpenIdClientOAuthProtocol } from "../openid-client/protocol";
import type { ProviderDefinition } from "../providerDefinition";
import type { OAuthUnavailable } from "../signInErrors";
import { gitHubOAuthAppProviderKey } from "./identity";
import type {
  GitHubOAuthAppConnectedProtocolOptions,
  GitHubOAuthAppGeneration,
  GitHubOAuthAppProtocolOptions,
} from "./models";
import {
  gitHubOAuthAppProvider,
  makeGitHubOAuthAppConnectedProtocol,
  makeGitHubOAuthAppProtocol,
} from "./protocol";

/** GitHub.com OAuth App credentials and one or more exact callback destinations. */
export type Registration = Pick<GitHubOAuthAppGeneration, "clientId" | "clientSecret"> &
  RegistrationOptions;

type Transport = {
  /** Per-request timeout in seconds, from 1 to 30. Defaults to 10. */
  readonly timeoutSeconds?: number;
  /** Trusted transport: honor abort; never retry token requests or log credentials. */
  readonly fetch?: GitHubOAuthAppProtocolOptions["fetch"];
};

export type Options = Transport &
  (Registration | { readonly registrations: ReadonlyArray<Registration> });

export type ConnectedRegistration = Registration &
  Pick<GitHubOAuthAppConnectedProtocolOptions["registrations"][number], "profiles">;

export type ConnectedOptions = Transport &
  (ConnectedRegistration | { readonly registrations: ReadonlyArray<ConnectedRegistration> });

const registration = (input: Registration): GitHubOAuthAppGeneration => ({
  ...input,
  ...resolveRegistration(input, "github"),
});

export type ProviderRegistration = Pick<GitHubOAuthAppGeneration, "clientId" | "clientSecret"> &
  Pick<RegistrationOptions, "configurationGeneration" | "issuance">;

export type ProviderOptions = Transport &
  (ProviderRegistration | { readonly registrations: ReadonlyArray<ProviderRegistration> });

export type AppProviderOptions = Transport &
  Pick<ProviderRegistration, "clientId" | "clientSecret"> & {
    /** API permissions; defaults to read:user. Refresh access is requested separately. */
    readonly scopes?: ReadonlyArray<string>;
    /** Local refresh retention; defaults to 30 days from the latest exchange. */
    readonly maximumRefreshLifetimeMillis?: number;
  };

/** GitHub.com OAuth App sign-in and API access through OAuthApp. Reuses the
 * GitHub verifier, S256 PKCE, issuer validation and rotating-token protocol.
 * Requests offline_access for expiring tokens; does not configure a GitHub App.
 */
export const appProvider = (
  options: AppProviderOptions,
): AppProvider<OpenIdClientConfigurationError | OAuthUnavailable> => ({
  configure: Effect.fn("GitHub.appProvider.configure")(function* (redirectUri) {
    const configured = yield* resolveOptions(() => {
      const profile = OAuthConnectedProfile.make({
        key: OAuthPermissionProfileKey.make("github"),
        generation: 1,
        issuance: "active",
        provider: gitHubOAuthAppProviderKey,
        clientRegistrationId: options.clientId,
        scopes: options.scopes ?? ["read:user"],
        resources: [],
        retention: "access-and-refresh",
        maximumAccessLifetimeMillis: 8 * 60 * 60 * 1000,
        maximumRefreshLifetimeMillis:
          options.maximumRefreshLifetimeMillis ?? 30 * 24 * 60 * 60 * 1000,
        refreshAheadMillis: 60_000,
        refresh: "rotating",
        revocation: "cohort",
      });

      return {
        profile,
        registration: { ...registration({ ...options, redirectUri }), profiles: [profile] },
      };
    });

    const protocol = yield* makeGitHubOAuthAppConnectedProtocol({
      registrations: [configured.registration],
      timeoutSeconds: options.timeoutSeconds ?? 10,
      ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
    });

    return { profile: configured.profile, protocol };
  }),
});

/** Declare GitHub for Http.layer. The host supplies its provider key and
 * callback destinations. Retired registrations remain available to finish flows. */
export const provider = (
  options: ProviderOptions,
): ProviderDefinition<OpenIdClientConfigurationError | OAuthUnavailable> => ({
  configure: (binding) =>
    resolveOptions(() => ({
      providers: ("registrations" in options ? options.registrations : [options]).map((input) => ({
        ...gitHubOAuthAppProvider({
          ...input,
          ...resolveRegistration({ ...input, callbacks: binding.callbacks }, binding.provider),
        }),
        provider: binding.provider,
      })),
      timeoutSeconds: options.timeoutSeconds ?? 10,
      ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
    })).pipe(Effect.flatMap(makeOpenIdClientOAuthProtocol)),
});

/** GitHub OAuth sign-in. Defaults to callback ID github, generation 1, active
 * issuance and a 10-second request timeout. Does not install HTTP routes.
 * For rotation, provide registrations with one active generation and retain
 * retired generations through their issued flows' lifetime. Configuration is
 * validated when the Layer builds; existing protocol safety rules still apply. */
export const layer = (options: Options) =>
  Layer.effect(
    OAuthProtocol,
    resolveOptions(() => ({
      registrations: ("registrations" in options ? options.registrations : [options]).map(
        registration,
      ),
      timeoutSeconds: options.timeoutSeconds === undefined ? 10 : options.timeoutSeconds,
      ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
    })).pipe(Effect.flatMap(makeGitHubOAuthAppProtocol)),
  );

/** Configure GitHub API connections with the same callback/rotation defaults as
 * layer. Permission profiles remain explicit; connection grants are not logins. */
export const layerConnected = (options: ConnectedOptions) =>
  Layer.effect(
    OAuthConnectedProtocol,
    resolveOptions(() => ({
      registrations: ("registrations" in options ? options.registrations : [options]).map(
        (input) => ({
          ...registration(input),
          profiles: input.profiles,
        }),
      ),
      timeoutSeconds: options.timeoutSeconds === undefined ? 10 : options.timeoutSeconds,
      ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
    })).pipe(Effect.flatMap(makeGitHubOAuthAppConnectedProtocol)),
  );
