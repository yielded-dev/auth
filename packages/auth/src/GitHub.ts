export {
  layer,
  layerConnected,
  provider,
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

export { OpenIdClientConfigurationError } from "./oauth/openid-client/models";

export {
  gitHubOAuthAppConnectedProtocolLayer,
  gitHubOAuthAppProtocolLayer,
  gitHubOAuthAppProvider,
  makeGitHubOAuthAppConnectedProtocol,
  makeGitHubOAuthAppProtocol,
} from "./oauth/github/protocol";

export { gitHubOAuthAppProviderKey } from "./oauth/github/identity";
export { GitHubUserProfile } from "./oauth/github/profile";
