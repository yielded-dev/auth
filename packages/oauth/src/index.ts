/**
 * Native Effect OAuth 2.1 and OpenID Connect protocol primitives.
 *
 * `ClientAuth` models extensible client authentication methods including RFC
 * 10070 JWT assertions. `Discovery` resolves and caches authorization-server
 * metadata from local configuration or remote well-known endpoints. `Grant`
 * builds redacted token grants and parses private token receipts. `OAuthError`
 * defines the single error type and closed reason union returned across the
 * package. `Pkce` generates and derives RFC 7636 `S256` verifiers and
 * challenges. `OAuth` and `Oidc` implement scoped client flows, authorization
 * transactions, signed ID-token verification, and UserInfo retrieval.
 *
 * @stability unstable
 * @since 4.1.4
 */

// @barrel

/**
 * @stability unstable
 * @since 4.1.4
 */
export * as ClientAuth from "./ClientAuth.ts";

/**
 * @stability unstable
 * @since 4.1.4
 */
export * as Discovery from "./Discovery.ts";

/**
 * @stability unstable
 * @since 4.1.4
 */
export * as Grant from "./Grant.ts";

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
