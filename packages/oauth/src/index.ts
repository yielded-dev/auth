/**
 * Native Effect OAuth 2.1 and OpenID Connect protocol primitives.
 *
 * `Discovery` resolves and caches authorization-server metadata from local
 * configuration or remote well-known endpoints. `OAuthError` defines the single
 * error type and closed reason union returned across the package. `Pkce`
 * generates and derives RFC 7636 `S256` verifiers and challenges. `OAuth` and
 * `Oidc` implement authorization-code, refresh, revocation, and signed ID-token
 * verification flows.
 *
 * @stability unstable
 * @since 4.1.4
 */

// @barrel

/**
 * @stability unstable
 * @since 4.1.4
 */
export * as Discovery from "./Discovery.ts";

/**
 * @stability unstable
 * @since 4.1.4
 */
export * as OAuth from "./OAuth.ts";

/**
 * @stability unstable
 * @since 4.1.4
 */
export * as OAuthError from "./OAuthError.ts";

/**
 * @stability unstable
 * @since 4.1.4
 */
export * as Oidc from "./Oidc.ts";

/**
 * @stability unstable
 * @since 4.1.4
 */
export * as Pkce from "./Pkce.ts";
