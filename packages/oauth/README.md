# @yielded/oauth

Effect OAuth authorization-code and refresh flows, PKCE S256, authorization-server
discovery, and signed OpenID Connect. Effect is its only runtime dependency;
applications own registered callbacks, provider configuration, permissions,
identity, and grant storage.

Use `Discovery.makeLocal` / `Discovery.layerLocal` for fixed metadata and
`Discovery.makeRemote` / `Discovery.layerRemote` for lazy, scoped remote discovery
from an OIDC (`/.well-known/openid-configuration`) or RFC 8414
(`/.well-known/oauth-authorization-server`) endpoint or explicit `url`. Remote
discovery validates options eagerly without network I/O, coalesces concurrent
fetches, caches the document for the `Scope` lifetime by default (`timeToLive: "Infinity"`),
throttles failed fetches with `cooldown`, enforces exact issuer matching unless an
`issuerMatcher` is supplied, and re-validates issuer and endpoint constraints after
any `supplement` hook.

Use `OAuth.make` for an installed client and the `Oidc` verification entrypoints for
ID tokens and UserInfo: `Oidc.verify` for a known `Jwk.PublicKey` or HMAC `Jwk.SecretKey`,
`Oidc.verifyWithKeySet` for a `Jwks.Jwks` service, `Oidc.makeVerifier` / `Oidc.layerVerifier`
for a `Discovery`-bound `Oidc.Verifier` with an explicit `Jwks.Jwks`, `Oidc.makeVerifierRemote` /
`Oidc.layerVerifierRemote` for lazy, scoped remote JWKS resolution, and `Oidc.fetchUserInfo`
for discovered UserInfo endpoints with mandatory `sub` matching (OIDC Core §5.3.2).
`Pkce.generate` and `Pkce.challenge` require Effect `SecureRandom` and `Digest`;
verification derives its crypto requirement (`Mac` or `Signature`) plus `Digest` from the
key or key set. Closing a service or factory's scope cancels and joins its active work and
prevents reuse.

`client.codeGrant` and `client.refreshGrant` return private `TokenReceipt` values.
Check the provider-specific receipt, then call `OAuth.tokens`. A JSON null
refresh token is omitted, and an array scope is joined with spaces. A receipt
alone does not establish a successful grant or authenticated identity. Tokens
stay redacted. Authorization
defaults to `response_mode=query`; `form_post` is available when the issuer POSTs
the callback. `client_secret_post` may omit its stored secret and take `clientSecret`
on that token request. For initial OIDC sign-in, require an ID token and verify it
with the flow `nonce`, `requestedAt` (when enforcing `maxAge`), `accessToken`, and
`code` (plus `requireCodeHash: true` for Hybrid or front-channel tokens). On refresh,
pass `previous` (`subject`, `issuer`, `audience`, and optional `nonce` and `authTime`);
accepting an omitted ID token is application policy.

Each exchange, refresh, or revocation makes one request. An uncertain outcome
requires application recovery, not an automatic retry. Provider endpoints require
HTTPS. HTTP endpoints and discovery URLs on `localhost`, `127.0.0.1`, or `[::1]`
are accepted only with an explicitly configured HTTP loopback issuer. Applications
must validate issuer input; require HTTPS for untrusted tenant-supplied issuers
to prevent plain-HTTP loopback requests. Custom HttpClients must preserve
cancellation and disable retries, redirects, and ambient cookies. Bound the
complete workflow as well as individual requests; keep token receipts out of logs
and telemetry.

Asymmetric remote OIDC verification requires an HTTPS `jwks_uri`, even for a loopback
issuer; an HTTP or missing `jwks_uri` fails with `OAuthError` (`InvalidArgument`).
`clockTolerance` defaults to `"30 seconds"` across `exp`, `nbf`, `iat`, `auth_time`,
and `requestedAt`; `typ` header validation runs immediately after signature verification
and before claim or expiry checks (accepting omitted `typ` or `"JWT"` / `"application/jwt"`
by default); multi-audience `aud` arrays require every entry to be a relying-party client ID
or listed in `additionalTrustedAudiences` and require `azp` by default. Supply an
`issuerPolicy` for non-exact issuers such as multi-tenant templates. All protocol
failures surface as `OAuthError` with a closed `reason` union (`InvalidArgument`,
`ClientAuthFailed`, `DiscoveryFailed`, `TransportFailed`, `InvalidResponse`,
`CallbackRejected`, `AuthorizationDenied`, `EndpointError`, or
`TokenVerificationFailed`). Each remote verifier owns a scoped JWKS cache, never
takes a key endpoint from a token, and never serves expired keys after refresh failure.

See the [public API comments](src/Discovery.ts), [OAuth client](src/OAuth.ts),
[OIDC verification](src/Oidc.ts), and [third-party notices](THIRD_PARTY_NOTICES.md).
