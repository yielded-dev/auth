import * as Effect from "effect/Effect";

import type { OAuthConnectedConfiguration } from "./connectedModels";
import type { OAuthConnectedProtocol } from "./OAuthConnectedProtocol";
import type { OAuthProtocol } from "./OAuthProtocol";
import type { OAuthProviderKey } from "./schema";
import type { OAuthUnavailable } from "./signInErrors";
import type { OAuthNativeProtocolConfiguration, OAuthProtocolConfiguration } from "./signInModels";

const OAuthProtocolPreflightSymbol = Symbol.for("@yielded/auth/OAuthProtocolPreflight");

const OAuthConnectedProtocolPreflightSymbol = Symbol.for(
  "@yielded/auth/OAuthConnectedProtocolPreflight",
);

export interface OAuthProtocolPreflightCapability {
  /** True when the selected provider (and optional kind) has a lazy OIDC registration. */
  readonly needsLazy: (provider: OAuthProviderKey, kind?: "web" | "native") => boolean;
  /** Discovery-only preflight: static mismatches return Effect.void so post-consume
   * paths classify them identically to M5, while discovery or metadata mismatches
   * fail with OAuthUnavailable before any flow is consumed. */
  readonly preflight: (
    target: OAuthProtocolConfiguration | OAuthNativeProtocolConfiguration,
  ) => Effect.Effect<void, OAuthUnavailable>;
}

export interface OAuthConnectedProtocolPreflightCapability {
  /** True when any installed connected registration uses lazy OIDC discovery. */
  readonly hasLazy: boolean;
  /** True when the selected provider has a lazy OIDC connected registration. */
  readonly needsLazy: (provider: OAuthProviderKey) => boolean;
  /** Discovery-only preflight: static mismatches return Effect.void so post-consume
   * and post-claim paths classify them identically to M5, while discovery or
   * metadata mismatches fail with OAuthUnavailable before durable mutation. */
  readonly preflight: (
    target: OAuthConnectedConfiguration,
  ) => Effect.Effect<void, OAuthUnavailable>;
}

type WithProtocolPreflight = OAuthProtocol["Service"] & {
  readonly [OAuthProtocolPreflightSymbol]: OAuthProtocolPreflightCapability;
};

type WithConnectedProtocolPreflight = OAuthConnectedProtocol["Service"] & {
  readonly [OAuthConnectedProtocolPreflightSymbol]: OAuthConnectedProtocolPreflightCapability;
};

const getProtocolPreflight = (
  service: OAuthProtocol["Service"],
): OAuthProtocolPreflightCapability | undefined =>
  OAuthProtocolPreflightSymbol in service
    ? (service as WithProtocolPreflight)[OAuthProtocolPreflightSymbol]
    : undefined;

const getConnectedProtocolPreflight = (
  service: OAuthConnectedProtocol["Service"],
): OAuthConnectedProtocolPreflightCapability | undefined =>
  OAuthConnectedProtocolPreflightSymbol in service
    ? (service as WithConnectedProtocolPreflight)[OAuthConnectedProtocolPreflightSymbol]
    : undefined;

/** Attach internal lazy-discovery metadata as an enumerable symbol property so
 * object spreads (such as `{ ...protocol, connected }`) preserve it while
 * leaving string keys and public serialization unchanged. */
export const attachProtocolPreflight = (
  service: OAuthProtocol["Service"],
  capability: OAuthProtocolPreflightCapability,
): OAuthProtocol["Service"] => {
  const attached: WithProtocolPreflight = {
    ...service,
    [OAuthProtocolPreflightSymbol]: capability,
  };

  return attached;
};

export const attachConnectedProtocolPreflight = (
  service: OAuthConnectedProtocol["Service"],
  capability: OAuthConnectedProtocolPreflightCapability,
): OAuthConnectedProtocol["Service"] => {
  const attached: WithConnectedProtocolPreflight = {
    ...service,
    [OAuthConnectedProtocolPreflightSymbol]: capability,
  };

  return attached;
};

export const needsLazyProtocol = (
  service: OAuthProtocol["Service"],
  provider: OAuthProviderKey,
  kind?: "web" | "native",
): boolean => {
  const capability = getProtocolPreflight(service);

  return capability === undefined
    ? service.ready !== undefined
    : capability.needsLazy(provider, kind);
};

export const preflightProtocol = (
  service: OAuthProtocol["Service"],
  target: OAuthProtocolConfiguration | OAuthNativeProtocolConfiguration,
): Effect.Effect<void, OAuthUnavailable> => {
  const capability = getProtocolPreflight(service);

  if (capability !== undefined) return capability.preflight(target);

  return service.ready === undefined ? Effect.void : service.ready(target);
};

export const hasLazyConnectedProtocol = (service: OAuthConnectedProtocol["Service"]): boolean => {
  const capability = getConnectedProtocolPreflight(service);

  return capability === undefined ? service.ready !== undefined : capability.hasLazy;
};

export const needsLazyConnectedProtocol = (
  service: OAuthConnectedProtocol["Service"],
  provider: OAuthProviderKey,
): boolean => {
  const capability = getConnectedProtocolPreflight(service);

  return capability === undefined ? service.ready !== undefined : capability.needsLazy(provider);
};

export const preflightConnectedProtocol = (
  service: OAuthConnectedProtocol["Service"],
  target: OAuthConnectedConfiguration,
): Effect.Effect<void, OAuthUnavailable> => {
  const capability = getConnectedProtocolPreflight(service);

  if (capability !== undefined) return capability.preflight(target);

  return service.ready === undefined ? Effect.void : service.ready(target);
};
