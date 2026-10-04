# @yielded/oauth

Native Effect OAuth authorization-code and refresh flows, PKCE S256, and signed
RS256 OpenID Connect. Runtime dependencies are Effect and `@yielded/jose`.

Use `OAuth.make` for an installed client and `Oidc.makeVerifier` for its OIDC
verifier. Both require `HttpClient` and an owning `Scope`; keep that scope open
for their lifetime. `Pkce` requires Effect `Crypto`; verification requires the
crypto services in `Jws.Requirements` and Effect `Crypto`. Runtime Layers belong
to the application. `Oidc.discover` retrieves metadata from the exact trusted
issuer's OIDC discovery endpoint.

Closing either factory's scope cancels and joins its active operations; pending
results and subsequent calls fail with `OAuthUnavailable`. Caller interruption
cancels and joins that operation while leaving the client or verifier usable.

`client.codeGrant` and `client.refreshGrant` return private `TokenReceipt` values.
Inspect `Redacted.value(receipt.body)` for provider-specific receipt rules, then
call `OAuth.tokens`. Its tokens remain redacted. Raw expiry extensions and scope
strings are retained unchanged, including provider-specific comma scopes.
`OAuth.tokens` accepts `expires_in` as a finite nonnegative number or a whole
decimal string such as `"60.5"`; whitespace, numeric-prefix junk, exponent syntax,
`NaN` and infinity are rejected. Provider checks can still require a raw number.
A returned receipt has not established grant success or an authenticated identity.
For OIDC, require an ID token on initial exchange and call `verifier.verify` with
the captured `verificationStartedAt`, nonce, access token and authorization code.
It verifies the signature before claims, checks present `at_hash`/`c_hash`, and
returns redacted verified claims for application-owned identity/profile mapping.
On refresh, verify any returned ID token with `previous` subject/authentication
time; an omitted refresh ID token is an application-owned continuation.

The application owns registered callbacks, expected state and response issuer,
provider generations, permissions, identity callbacks, grant retention and durable
receipts. This package makes one request per exchange, refresh or revocation.
`OAuthRejected` identifies a complete HTTP 400 `invalid_grant` or an authenticated
claim rejection. Malformed responses and expected transport, key and signature
failures are `OAuthUnavailable`; they do not authorize repeating a possibly
committed request. Implementation defects, including those in injected services,
remain in Effect's defect channel.

Provider endpoints require HTTPS and exact response URLs. Redirects, cookies and
HTTP tracing are disabled for Fetch; custom HttpClients must preserve cancellation
and have no retry, redirect or cookie middleware. Installed profile endpoints and
headers are validated before credentials are sent. Responses are bounded to 1 MiB
by default (configurable downward). JSON is limited to 64 object/array levels and
65,536 values, including the root in both limits; excess depth or size fails with
`OAuthUnavailable`. Installed metadata and returned JSON snapshots are deeply
frozen. Requests to token/revocation endpoints are bounded to 128 KiB and
authorization URLs to 16 KiB. `timeoutMs` covers each request
through body consumption. Applications bound their complete multi-step workflow.
The current Fetch reference is captured when constructing the client/verifier.

Each verifier owns one scoped JOSE JWKS cache: at most 64 keys and 64 waiters, a
10-minute cache lifetime and a 30-second refresh cooldown. There is no global
issuer cache, background polling, stale-on-error fallback, or token-supplied key
endpoint. The supported profile requires advertised code, S256 and RS256 support;
other OAuth grants and ID-token signature algorithms are outside this profile.

See [third-party notices](THIRD_PARTY_NOTICES.md) for pinned upstream contract
sources and licenses.
