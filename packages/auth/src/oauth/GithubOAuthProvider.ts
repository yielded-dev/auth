import { Effect, Option, Redacted, Schema } from "effect";
import { HttpClientRequest } from "effect/unstable/http";

import { OAuthProviderError } from "./errors";
import { type OAuthProvider, decodeStandardTokenGrant } from "./OAuthProvider";
import { OAuthIdentity, OAuthProviderKey } from "./schema";

export const githubOAuthProviderKey = Schema.decodeSync(OAuthProviderKey)("github");

/**
 * Credentials of the GitHub App whose user-to-server flow this provider
 * drives. These are the app's *OAuth* credentials (client id and client
 * secret) — not the private key or installation id used to mint
 * app-as-bot installation tokens. The tokens this provider yields are GitHub
 * App **user access tokens**: actions taken with them are attributed to the
 * authorizing user, scoped by the app's permissions and the user's own access.
 */
export interface GithubOAuthOptions {
  readonly clientId: string;
  readonly clientSecret: Redacted.Redacted<string>;
  /**
   * Base URL of the GitHub web host owning `/login/oauth/*` (default
   * `https://github.com`). Override for GitHub Enterprise Server or a test
   * stand-in.
   */
  readonly webBaseUrl?: string;
  /**
   * Base URL of the GitHub REST API (default `https://api.github.com`).
   * Override for GitHub Enterprise Server or a test stand-in.
   */
  readonly apiBaseUrl?: string;
}

const GithubUser = Schema.Struct({
  id: Schema.Natural,
  login: Schema.NonEmptyString,
});

// oxlint-disable-next-line no-restricted-properties -- The identity payload is untrusted JSON from GitHub.
const decodeGithubUser = Schema.decodeUnknownEffect(GithubUser);

const githubApiHeaders = {
  accept: "application/vnd.github+json",
  "user-agent": "effect-auth-oauth",
  "x-github-api-version": "2022-11-28",
};

/**
 * GitHub as an {@link OAuthProvider}. Everything here is mapping: endpoints,
 * the standard token-response decoder (GitHub answers errors with status 200,
 * which the standard decoder recognizes), identity normalization, and the
 * revocation request shape.
 *
 * The identity preserves GitHub's stable numeric user id as
 * `providerAccountId` (decimal string) and the login as `handle`. No scopes
 * are requested: GitHub App user access tokens derive their permissions from
 * the app installation, and GitHub ignores the OAuth-App-style `scope`
 * parameter for them.
 */
export const makeGithubOAuthProvider = (options: GithubOAuthOptions): OAuthProvider => {
  const webBaseUrl = options.webBaseUrl ?? "https://github.com";
  const apiBaseUrl = options.apiBaseUrl ?? "https://api.github.com";

  return {
    key: githubOAuthProviderKey,
    displayName: "GitHub",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    endpoints: {
      authorization: `${webBaseUrl}/login/oauth/authorize`,
      token: `${webBaseUrl}/login/oauth/access_token`,
    },
    scopes: [],
    authorizationParams: {},
    decodeTokenGrant: decodeStandardTokenGrant(githubOAuthProviderKey),
    identity: {
      url: `${apiBaseUrl}/user`,
      headers: githubApiHeaders,
      decode: (payload) =>
        decodeGithubUser(payload).pipe(
          Effect.mapBoth({
            onSuccess: (user) =>
              OAuthIdentity.make({
                provider: githubOAuthProviderKey,
                providerAccountId: String(user.id),
                handle: Option.some(user.login),
              }),
            onFailure: () =>
              OAuthProviderError.make({
                provider: githubOAuthProviderKey,
                message: "GitHub returned an unrecognized user identity",
              }),
          }),
        ),
    },
    revocation: Option.some((accessToken) =>
      HttpClientRequest.delete(
        `${apiBaseUrl}/applications/${encodeURIComponent(options.clientId)}/token`,
      ).pipe(
        HttpClientRequest.setHeaders(githubApiHeaders),
        HttpClientRequest.basicAuth(options.clientId, options.clientSecret),
        HttpClientRequest.bodyJsonUnsafe({ access_token: Redacted.value(accessToken) }),
      ),
    ),
  };
};
