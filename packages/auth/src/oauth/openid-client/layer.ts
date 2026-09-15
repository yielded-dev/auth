import { Effect, Layer } from "effect";

import { OAuthProtocol } from "../OAuthProtocol";
import type { ProviderDefinition } from "../providerDefinition";
import type { OAuthUnavailable } from "../signInErrors";
import type {
  OpenIdClientConfigurationError,
  OpenIdClientOAuthProtocolOptions,
  OpenIdClientOAuthProvider,
  OpenIdClientOidcProvider,
} from "./models";
import {
  resolveOptions,
  resolveProvider,
  type ProviderOptions as RegistrationInput,
} from "./options";
import { makeOpenIdClientOAuthProtocol } from "./protocol";

export type Provider<R = never> = RegistrationInput<
  | (Omit<OpenIdClientOidcProvider, "scopes"> & { readonly scopes?: ReadonlyArray<string> })
  | (Omit<OpenIdClientOAuthProvider<R>, "scopes"> & { readonly scopes?: ReadonlyArray<string> })
>;

export interface Options<R = never> {
  readonly providers: ReadonlyArray<Provider<R>>;
  /** Per-request timeout in seconds, from 1 to 30. Defaults to 10. */
  readonly timeoutSeconds?: number;
  /** Trusted transport: honor abort; never retry token requests or log credentials. */
  readonly fetch?: OpenIdClientOAuthProtocolOptions<R>["fetch"];
}

type WithoutBinding<P> = P extends unknown
  ? Omit<P, "provider" | "redirectUri" | "callbackId" | "callbacks">
  : never;

export type ProviderRegistration<R = never> = WithoutBinding<Provider<R>>;

export type ProviderOptions<R = never> = Pick<Options<R>, "timeoutSeconds" | "fetch"> &
  (ProviderRegistration<R> | { readonly registrations: ReadonlyArray<ProviderRegistration<R>> });

const resolve = <R>(providers: ReadonlyArray<Provider<R>>) =>
  providers.map((input) =>
    input.protocol === "oidc"
      ? {
          ...resolveProvider(input),
          scopes: input.scopes === undefined ? ["openid"] : input.scopes,
          idTokenSignedResponseAlg:
            input.idTokenSignedResponseAlg === undefined
              ? ("RS256" as const)
              : input.idTokenSignedResponseAlg,
        }
      : {
          ...resolveProvider(input),
          scopes: input.scopes === undefined ? [] : input.scopes,
          pkceS256: input.pkceS256 === undefined ? (true as const) : input.pkceS256,
        },
  );

/** Declare an OIDC or OAuth provider for Http.layer. No I/O runs until its
 * Layer builds. The HTTP host supplies the provider ID and callback URLs. */
export const provider = <R = never>(
  options: ProviderOptions<R>,
): ProviderDefinition<OpenIdClientConfigurationError | OAuthUnavailable, R> => ({
  configure: (binding) =>
    resolveOptions(() => ({
      providers: resolve(
        ("registrations" in options ? options.registrations : [options]).map((registration) => ({
          ...registration,
          ...binding,
        })),
      ),
      timeoutSeconds: options.timeoutSeconds ?? 10,
      ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
    })).pipe(Effect.flatMap(makeOpenIdClientOAuthProtocol<R>)),
});

/** One protocol Layer for all OAuth/OIDC hosts. Each provider defaults to
 * generation 1, active issuance, callback ID equal to its provider key, required
 * response issuer validation and S256 PKCE. OIDC defaults to RS256 and the openid
 * scope; plain OAuth defaults to no scopes. clientSecret uses client_secret_basic
 * unless tokenEndpointAuthMethod is supplied. Discovery must confirm the host's
 * capabilities. Invalid configuration fails when building the Layer.
 *
 * Keep retired generations in providers until their outstanding flows expire;
 * never reuse a generation for changed credentials or protocol configuration.
 * This Layer does not mount callback routes or infer a redirect URL. */
export const layer = <R = never>(options: Options<R>) =>
  Layer.effect(
    OAuthProtocol,
    resolveOptions(() => ({
      providers: resolve(options.providers),
      timeoutSeconds: options.timeoutSeconds === undefined ? 10 : options.timeoutSeconds,
      ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
    })).pipe(Effect.flatMap(makeOpenIdClientOAuthProtocol<R>)),
  );
