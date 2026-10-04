import type { Hmac } from "@yielded/crypto/Hmac";
import type { Signature } from "@yielded/crypto/Signature";
import type * as OAuth from "@yielded/oauth/OAuth";
import * as Oidc from "@yielded/oauth/Oidc";
import { type Crypto, Effect, type Redacted } from "effect";

import { OAuthUnavailable } from "../signInErrors";
import { installProvider, prepareConfigurations, type InstalledProvider } from "./configuration";
import {
  installConnectedProvider,
  prepareConnectedConfigurations,
  type InstalledConnectedProvider,
} from "./connected/configuration";
import type { OpenIdConnectConnectedProtocolOptions } from "./connected/models";
import { OpenIdConnectConfigurationError, type OpenIdConnectOAuthProtocolOptions } from "./models";
import type { Requirements as OAuthRequirements } from "./native";

export type Requirements = OAuthRequirements | Hmac | Signature;

const configurationError = (error: Effect.Error<ReturnType<typeof Oidc.discover>>) =>
  error._tag === "OAuthConfigurationError"
    ? OpenIdConnectConfigurationError.make({ reason: "metadata" })
    : OAuthUnavailable.make({});

const discover = (issuer: string, timeoutSeconds: number) =>
  Oidc.discover(issuer, { timeoutMs: timeoutSeconds * 1000 }).pipe(
    Effect.mapError(configurationError),
  );

const makeVerifier = Effect.fn("OpenIdConnect.makeVerifier")(function* (
  metadata: OAuth.Metadata,
  clientId: string,
  timeoutSeconds: number,
) {
  const context = yield* Effect.context<Crypto.Crypto | Hmac | Signature>();

  const verifier = yield* Oidc.makeVerifier({
    metadata,
    clientId,
    timeoutMs: timeoutSeconds * 1000,
  }).pipe(Effect.mapError(configurationError));

  return {
    verify: (token: Redacted.Redacted<string>, input: Oidc.VerificationInput) =>
      verifier.verify(token, input).pipe(Effect.provideContext(context)),
  };
});

/** Only the OIDC adapter installs discovery and signed ID-token verification. */
export const installConfigurations = Effect.fn("OpenIdConnect.installConfigurations")(function* <R>(
  input: OpenIdConnectOAuthProtocolOptions<R>,
) {
  const { providers, timeoutSeconds } = yield* prepareConfigurations(input);
  const installed: InstalledProvider<R>[] = [];

  for (const provider of providers) {
    const raw =
      provider.protocol === "oidc"
        ? yield* discover(provider.issuer, timeoutSeconds)
        : {
            issuer: provider.issuer,
            authorization_endpoint: provider.authorizationEndpoint,
            token_endpoint: provider.tokenEndpoint,
            authorization_response_iss_parameter_supported:
              provider.responseIssuerMode === "required",
          };

    const entry = yield* installProvider(provider, raw, timeoutSeconds);

    installed.push(
      provider.protocol === "oidc"
        ? {
            ...entry,
            verifier: yield* makeVerifier(entry.metadata, provider.clientId, timeoutSeconds),
          }
        : entry,
    );
  }

  return { installed, timeoutSeconds };
});

export const installConnectedConfigurations = Effect.fn(
  "OpenIdConnect.installConnectedConfigurations",
)(function* <R>(input: OpenIdConnectConnectedProtocolOptions<R>) {
  const { providers, timeoutSeconds } = yield* prepareConnectedConfigurations(input);
  const installed: InstalledConnectedProvider<R>[] = [];

  for (const provider of providers) {
    const raw =
      provider.protocol === "oidc"
        ? yield* discover(provider.issuer, timeoutSeconds)
        : {
            issuer: provider.issuer,
            authorization_endpoint: provider.authorizationEndpoint,
            token_endpoint: provider.tokenEndpoint,
            authorization_response_iss_parameter_supported:
              provider.responseIssuerMode === "required",
            ...(provider.revocation.mode === "rfc7009"
              ? { revocation_endpoint: provider.revocation.endpoint }
              : {}),
          };

    const entry = yield* installConnectedProvider(provider, raw, timeoutSeconds);

    installed.push(
      provider.protocol === "oidc"
        ? {
            ...entry,
            verifier: yield* makeVerifier(entry.metadata, provider.clientId, timeoutSeconds),
          }
        : entry,
    );
  }

  return { installed, timeoutSeconds };
});
