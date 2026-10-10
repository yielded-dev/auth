import type { Metadata } from "@yielded/oauth/OAuth";
import { Effect, Schema } from "effect";

import { OpenIdConnectConfigurationError } from "./models";

/** Private, first-party discovery supplements; generic OIDC remains strict. */
export const discoveryProfile = Symbol("effect-auth/OpenIdConnect/discoveryProfile");
export const DiscoveryProfile = Schema.Literal("slack");

export const supplementDiscovery = Effect.fnUntraced(function* (
  metadata: Metadata,
  profile: typeof DiscoveryProfile.Type | undefined,
) {
  if (profile === undefined) return metadata;
  if (
    metadata.issuer !== "https://slack.com" ||
    metadata.authorization_endpoint !== "https://slack.com/openid/connect/authorize" ||
    metadata.token_endpoint !== "https://slack.com/api/openid.connect.token" ||
    metadata.jwks_uri !== "https://slack.com/openid/connect/keys"
  )
    return yield* OpenIdConnectConfigurationError.make({ reason: "metadata" });

  // Slack documents code_verifier at docs.slack.dev/reference/methods/openid.connect.token/
  // but omits PKCE from discovery. Supply only the missing advertisement; an
  // explicit incompatible capability still fails the shared S256 validation.
  return {
    ...metadata,
    code_challenge_methods_supported: metadata.code_challenge_methods_supported ?? ["S256"],
  };
});
