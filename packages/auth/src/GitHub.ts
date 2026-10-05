export {
  layer,
  layerConnected,
  provider,
  accessProfile,
  type Options,
  type ProviderOptions,
  type ProviderRegistration,
  type Registration,
  type ConnectedOptions,
  type ConnectedRegistration,
} from "./oauth/github/options";

export {
  type GitHubOAuthAppConnectedProtocolOptions,
  type GitHubOAuthAppGeneration,
  type GitHubOAuthAppProtocolOptions,
} from "./oauth/github/models";

export { OpenIdConnectConfigurationError } from "./oauth/providers/models";

export { gitHubOAuthAppProvider } from "./oauth/github/protocol";

export { gitHubOAuthAppProviderKey } from "./oauth/github/identity";
export { GitHubUserProfile } from "./oauth/github/profile";
