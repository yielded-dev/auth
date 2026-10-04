export {
  layer,
  provider,
  type Options,
  type Provider,
  type ProviderOptions,
  type ProviderRegistration,
} from "./oauth/providers/layer";

export {
  type OpenIdConnectAuthentication,
  OpenIdConnectConfigurationError,
  type OpenIdConnectOAuthProtocolOptions,
  type OpenIdConnectOAuthProvider,
  type OpenIdConnectOidcProvider,
  type PlainOAuthIdentity,
} from "./oauth/providers/models";

export { OidcUserProfile } from "./oauth/providers/profile";

export {
  layer as layerConnected,
  type Options as ConnectedOptions,
  type Provider as ConnectedProvider,
} from "./oauth/providers/connected/layer";

export type {
  OpenIdConnectConnectedOAuthProvider,
  OpenIdConnectConnectedOidcProvider,
  OpenIdConnectConnectedProtocolOptions,
  OpenIdConnectConnectedRefreshExpiry,
  OpenIdConnectConnectedRevocation,
} from "./oauth/providers/connected/models";

export type { Requirements } from "./oauth/providers/native";
