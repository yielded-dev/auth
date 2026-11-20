# @yielded/oauth

Effect OAuth 2.1 and OpenID Connect relying-party protocol primitives. Effect is its only
runtime dependency; applications own registered callbacks, provider configuration,
permissions, identity, and grant storage.

- **`ClientAuth`**: Extensible client authentication methods (`none`, `secretBasic`,
  `secretPost`, `secretJwt`, `privateKeyJwt`, `make`, name-bound `unwrap`, and
  `withPreparedRequest`).
  `secretJwt` and `privateKeyJwt` follow RFC 10070 §4 by default: single-string `aud`
  equal to `request.issuer`, `typ: "client-authentication+jwt"`, 128-bit random `jti`,
  and `"60 seconds"` lifetime (capped at `"1 hour"`, rounded up to whole seconds).
- **`Discovery`**: `Discovery.makeLocal` / `layerLocal` for fixed metadata and lazy,
  scoped `Discovery.makeRemote` / `layerRemote` for OIDC (`/.well-known/openid-configuration`)
  or RFC 8414 (`/.well-known/oauth-authorization-server`) discovery with `"Infinity"`
  default `timeToLive`, `cooldown`, `issuerMatcher`, and post-`supplement` validation.
- **`Grant`**: Redacted token grants (`make`, `authorizationCode`, `{ issuer, clientId }`-bound
  `fromTransaction`, `refreshToken`, `clientCredentials`), private `TokenReceipt`
  (`{ disallowJsonEncode: true }`), explicit `TokenReceiptFromJson` storage codec for
  encrypted persistence, and `parseTokens` (`TokenSet`).
- **`OAuth`**: Scoped `OAuth.Client` service (`make` / `layer`) capturing `Discovery`,
  `HttpClient`, and independent `clientAuth` / `revocationAuth` requirements, with
  `authorizationUrl`, single-snapshot `prepareAuthorization`, `OAuth.authorize`,
  `exchangeRaw`, `exchange`, RFC 7009 `revoke` (exact HTTP `200` success), and canonical
  callback helpers (`callbackParamsFromQuery`, `callbackParamsFromFormPost`, `validateCallback`).
- **`Oidc`**: `Oidc.authorize` (idempotent `"openid"`, consistent `nonce`, advertised
  PKCE by default), `Oidc.verify` (known `Jwk.PublicKey` or HMAC `Jwk.SecretKey`),
  `Oidc.verifyWithKeySet`, `Oidc.Verifier` (`makeVerifier` / `layerVerifier` and lazy,
  scoped `makeVerifierRemote` / `layerVerifierRemote`), and `Oidc.fetchUserInfo`
  (mandatory `sub` match, OIDC Core §5.3.2).
- **`Pkce`**: RFC 7636 `S256` `generate` and `challenge`.
- **`OAuthError`**: Single `Data.TaggedError` wrapping a closed `reason` union
  (`InvalidArgument`, `ClientAuthFailed`, `DiscoveryFailed`, `TransportFailed`,
  `InvalidResponse`, `CallbackRejected`, `AuthorizationDenied`, `EndpointError`,
  `TokenVerificationFailed`).

`exchange` and `exchangeRaw` are interruptible, single-attempt, and scoped through the
bounded response read (`<= 1 MiB` response, `<= 131,072`-byte encoded token request body).
An uncertain outcome requires application recovery, not an automatic retry. Authorization
URLs omit `response_mode` for `"query"` and emit `response_mode=form_post` only for
`"form_post"`. `OAuth.Client` rejects `client_credentials` with `ClientAuth.none` unless
`allowUnauthenticatedClientCredentials: true` is set, and rejects `Grant.fromTransaction`
when `issuer` or `clientId` does not match the client.

Provider endpoints require HTTPS. HTTP endpoints and discovery URLs on `localhost`,
`127.0.0.1`, or `[::1]` are accepted only with an explicitly configured HTTP loopback
issuer; asymmetric remote OIDC verification always requires an HTTPS `jwks_uri`. Custom
`HttpClient` instances must preserve cancellation and disable retries, redirects, and
ambient cookies. Closing a service's `Scope` cancels and joins its active work and
prevents reuse.

See the [public API comments](src/OAuth.ts), [client authentication](src/ClientAuth.ts),
[grants](src/Grant.ts), [discovery](src/Discovery.ts), [OIDC verification](src/Oidc.ts),
and [third-party notices](THIRD_PARTY_NOTICES.md).
