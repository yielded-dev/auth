# @yielded/oauth

## 0.1.0-beta.50

### Patch Changes

- [#321](https://github.com/yielded-dev/auth/pull/321) [`ba2baeb`](https://github.com/yielded-dev/auth/commit/ba2baeb7fca5ec61cd83318fac95c7823d2e198e) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Fix a Microsoft Entra sign-in security issue by rejecting personal Microsoft accounts on `organizations` registrations. Require a matching signing-key issuer when `consumers` discovery returns the concrete issuer.

- [#324](https://github.com/yielded-dev/auth/pull/324) [`f97caf5`](https://github.com/yielded-dev/auth/commit/f97caf53e08458853f6d29ebcc32d3ac7d30d9d8) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Add canonical OAuth callback decoding and validation (`OAuth.callbackParamsFromQuery`, `OAuth.callbackParamsFromFormPost`, `OAuth.validateCallback`), wire them across HTTP and proxy callbacks, and enforce atomic `responseMode` binding in OAuth flow persistence.

  BEHAVIOR CHANGE: Callbacks reject front-channel token parameters (`id_token`, `access_token`, `token`, `token_type`, `expires_in`, `response`), cap `form_post` bodies at 16 KiB raw bytes, accept `user` only on `POST`, admit standard parameters (`state`, `code`, `error`, `error_description`, `error_uri`, `iss`, `scope`) plus `Http.make` provider names (`authuser`, `prompt`, `hd`), enforce RFC 6749 `code` syntax before consume, forward `OAuthCodeResponse.scope`, validate issuers under `OAuthIssuer` (failing closed at `begin`), and return `Cancelled` while clearing `request-binding` for bound provider errors. Observed transport is server-owned (`response.mode` removed; JSON completion routes record `"query"`, dedicated routes derive GET/POST, custom `form_post` hosts provide `OAuth.OAuthCallbackTransport`). Mapped tables must bind nullable `OAuthFlowTable.responseMode`, replacement persistence services must compare `access.responseMode` inside the conditional delete (`NULL` for native only), and dev databases need nullable `response_mode` on `${prefix}_oauthSignInFlows` and `${prefix}_oauthConnectedFlows` (or recreate them to clear in-flight browser flows; durable accounts, sessions, identities, and grants are unaffected).

- [#323](https://github.com/yielded-dev/auth/pull/323) [`49d2b01`](https://github.com/yielded-dev/auth/commit/49d2b01b6f1e2d4333269a7b7d90cd76b5a2ead4) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Add `ClientAuth` (including RFC 10070 `secretJwt`/`privateKeyJwt`, name-bound `unwrap`, and `withPreparedRequest`), `Grant` (`authorizationCode`, `{ issuer, clientId }`-bound `fromTransaction`, `refreshToken`, `clientCredentials`, `make`, `TokenReceipt`/`TokenReceiptFromJson`, `parseTokens`), scoped `OAuth.Client` (`make`/`layer`, single-snapshot `prepareAuthorization`, `OAuth.authorize`, `exchangeRaw`/`exchange`, `revoke`), and `Oidc.authorize` in `@yielded/oauth`, and migrate `@yielded/auth` providers including Apple and Strava onto them.

  BEHAVIOR CHANGE: Direct `@yielded/oauth` consumers must migrate from `OAuth.make({ metadata, authentication, timeoutMs })`, `client.codeGrant`/`refreshGrant`, and `OAuth.tokens` to `Discovery`, `ClientAuth`, `Grant`, and `OAuth.Client`; HTTP `5xx` responses now fail with `TransportFailed`. Across both `@yielded/oauth` and `@yielded/auth`, authorization URLs now omit `response_mode` for `"query"` (emitting `response_mode=form_post` only for `"form_post"`). In `@yielded/auth`, sign-in registrations now reserve `resource` (case-insensitively) in `authorizationParameters`, `tokenParameters`, and the authorization-endpoint query at configuration/install time (matching connected registrations). In `@yielded/auth` Strava, HTTP `401` token responses, `400` response bodies exceeding 1 MiB, `400` JSON objects carrying `scope`, and contradictory receipts combining token success fields with error indicators (on `200` or `400`, regardless of `Content-Type`) now report `OAuthUnavailable`; the token POST adds `Accept: application/json`, `;charset=UTF-8`, and a 10-second timeout, while both the token POST and refresh athlete GET enforce `credentials: "omit"`, `cache: "no-store"`, and disabled trace propagation (`b3`/`traceparent`). No stored-data reset is required.

- [#318](https://github.com/yielded-dev/auth/pull/318) [`0609a81`](https://github.com/yielded-dev/auth/commit/0609a813bd0f011fdf2338d2d782d0f8ac48087a) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Add the `Discovery` service (`Metadata`, `makeLocal`/`layerLocal`, and lazy, scoped `makeRemote`/`layerRemote`) to `@yielded/oauth`, remove `Oidc.discover` and `Oidc.discoveredIssuerMatches`, and move discovery-time Microsoft Entra `{tenantid}` / `consumers` matching into `@yielded/auth`.

  BEHAVIOR CHANGE: Direct `@yielded/oauth` consumers must replace `Oidc.discover` with `Discovery.makeRemote` or `Discovery.layerRemote` (and supply an explicit `issuerMatcher` for non-exact issuers such as Microsoft Entra `{tenantid}` templates). `@yielded/auth` OIDC and Entra discovery behavior is unchanged.

- [#317](https://github.com/yielded-dev/auth/pull/317) [`3e3eea0`](https://github.com/yielded-dev/auth/commit/3e3eea0157a560bf2166bebe35199243ad4f3286) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Replace `@yielded/oauth/Errors` with `OAuthError` and its closed `reason` union, reshape `Pkce` around `Verifier`, `Challenge`, `Pair`, infallible `generate`, and `challenge`, and raise the `effect` peer dependency floor to `^4.1.4` across the package family.

  BEHAVIOR CHANGE: Direct `@yielded/oauth` consumers must migrate from `@yielded/oauth/Errors` (`ConfigurationError`, `Rejected`, `Unavailable`) to `@yielded/oauth/OAuthError` (matching on `error.reason._tag`) and from `Pkce.make()` / `Pkce.random()` to `Pkce.generate` / `Pkce.challenge`. All packages in the family now require `effect@^4.1.4`.

- [#327](https://github.com/yielded-dev/auth/pull/327) [`fdb6b4c`](https://github.com/yielded-dev/auth/commit/fdb6b4cb4efc5a49907558c48ee7c0d0a9fb410d) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Resolve `@yielded/auth` OpenID Connect discovery lazily on first use with zero network I/O during Layer construction, expose `OAuthProtocol.ready` and `OAuthConnectedProtocol.ready` for opt-in startup warm-up, and measure `Discovery.makeRemote` failure cooldown from completion time.

  BEHAVIOR CHANGE: OIDC metadata checks (issuer matching, advertised authentication methods, PKCE, ID-token algorithms, verifier key setup, and `responseIssuerMode: "discovered"`) now run on first use — including the first callback, token refresh, or revocation after a restart — and fail with `OAuthUnavailable` without consuming pending flows, settling active grants, or claiming revocation jobs. Metadata-dependent OIDC configuration failures no longer fail Layer construction (static configuration errors still fail at build time) and report `OAuthUnavailable` until corrected. During revocation maintenance, each pass checks readiness for every installed connected registration before claiming, so one IdP outage delays all revocations in that installation until recovery rather than settling jobs to `Unknown`. Run `yield* ((yield* OAuthProtocol).ready?.() ?? Effect.void)` (and `yield* ((yield* OAuthConnectedProtocol).ready?.() ?? Effect.void)` when using connected grants) during startup if you require fail-fast boot validation.

- [#320](https://github.com/yielded-dev/auth/pull/320) [`a75187b`](https://github.com/yielded-dev/auth/commit/a75187b840f9332caabdbacd23780c9c9edd0aed) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Reshape `@yielded/oauth/Oidc` with key-based `verify`, key-set `verifyWithKeySet`, a `Discovery`-backed `Verifier` service (`makeVerifier`, `makeVerifierRemote`, and layers), `IssuerPolicy`, and `fetchUserInfo`. Move verify-time Microsoft Entra and LINE HS256 handling into `@yielded/auth`, require a per-key `issuer` and matching signed `tid` on concrete Entra v2 and `*.ciamlogin.com` authorities (including `Microsoft.provider({ tenant: "consumers" })`) while concrete Entra v1 (`sts.windows.net`) binds the signed `tid` and checks the key `issuer` only when present, and anchor `max_age` freshness checks to flow `requestedAt`.

  BEHAVIOR CHANGE: Direct `@yielded/oauth` consumers must migrate from `Oidc.makeVerifier({ metadata, ... })` to `Oidc.verify`, `Oidc.verifyWithKeySet`, `Oidc.makeVerifier`, or `Oidc.makeVerifierRemote` over `Discovery`, moving advertised metadata capability checks and provider-specific issuer policies (such as Entra `{tenantid}` and per-key `issuer`) to caller configuration. Across `@yielded/oauth` and `@yielded/auth`, ID-token verification now defaults `clockTolerance` to `"30 seconds"`, widens `@yielded/oauth` default asymmetric algorithms to all `effect/jose` asymmetric algorithms (`RS*`, `PS*`, `ES*`, `EdDSA`), validates protected-header `typ` immediately after signature verification (accepting omitted `typ` or `"JWT"` / `"application/jwt"` by default), enforces multi-audience `aud`/`azp` policy and refresh `aud` continuity, verifies `at_hash` and `c_hash` only when `accessToken` or `code` is supplied unless `requireCodeHash: true`, fixes `max_age: 0` with `>= 1s` login delay and refresh `auth_time` when the prior token omitted `auth_time`, enables `requireCodeHash: true` during native sign-in (`completeNativeSignIn`) whenever a native credential includes `code` (rejecting tokens that omit `c_hash`), and maps initial authorization-code ID-token post-signature rejections and UserInfo `subjectMismatch` (a valid `sub` differing from the verified ID token) to `OAuthProtocolRejected` while treating missing or malformed UserInfo `sub` (`InvalidResponse`) as `OAuthUnavailable` on both sign-in (previously rejected) and initial connected-account exchanges, and keeping connected refresh post-exchange failures `OAuthUnavailable`. Microsoft tenant subjects now use the canonical lowercase `tid`, and a binding stored with a non-lowercase `tid` (which Microsoft does not issue) must reconnect; other existing stored connected grants require no reset or reconnection.

- [#322](https://github.com/yielded-dev/auth/pull/322) [`f4a7c39`](https://github.com/yielded-dev/auth/commit/f4a7c397ea5fe2325a171a0b5dd1b5b1538584da) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Move plain-OAuth profile fetching, JSON token request bodies, and comma-delimited scope serialization out of `@yielded/oauth` into `@yielded/auth` provider helpers.

  BEHAVIOR CHANGE: Direct `@yielded/oauth` consumers can no longer pass `profile`, `tokenBodyFormat`, or `scopeSeparator` to `OAuth.make` or call `client.fetchProfile`; `@yielded/oauth` now handles only standard form-encoded token requests and space-separated scopes. `@yielded/auth` provider behavior and wire format are unchanged across authorization, token exchange, refresh, and profile requests.

## 0.1.0-beta.49

### Patch Changes

- [#291](https://github.com/yielded-dev/auth/pull/291) [`14bfbbc`](https://github.com/yielded-dev/auth/commit/14bfbbc2cbd3ebe6e812e57801b4be577671db09) Thanks [@leonitousconforti](https://github.com/leonitousconforti)! - Accept HTTP OAuth endpoints and discovery URLs on `localhost`, `127.0.0.1`, or `[::1]` only for explicitly configured HTTP loopback issuers. Keep asymmetric OIDC verification HTTPS-only for JWKS and report HTTP JWKS as a configuration error.

## 0.1.0-beta.48

### Minor Changes

- [#308](https://github.com/yielded-dev/auth/pull/308) [`058d118`](https://github.com/yielded-dev/auth/commit/058d118b6386cedaa1e3ec30b140bd19c44692b3) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Add native Sign in with Apple for any number of iOS and macOS apps, from Swift or Expo: declare `Apple.provider({ kind: "native", bundleIds })` without a signing key and expose `AuthContract.oauthNativeSignIn` and `AuthContract.oauthCompleteNativeSignIn`. `Oidc.makeVerifier` accepts several ID-token `audiences`.

### Patch Changes

- [#300](https://github.com/yielded-dev/auth/pull/300) [`e2705d9`](https://github.com/yielded-dev/auth/commit/e2705d950d6213f8befc8e07ed59c400b3869393) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Use Effect's bundled JOSE implementation and require Effect 4.1.2 across the package family. Replace `@yielded/jose` imports with `effect/jose`; use Effect durations for JWT age and remote JWKS settings, and match JOSE errors through their typed `reason`.

## 0.1.0-beta.47

### Patch Changes

- [#288](https://github.com/yielded-dev/auth/pull/288) [`109c420`](https://github.com/yielded-dev/auth/commit/109c4201e63637c8e9c23039c5a248b872fddca0) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Use Effect crypto and one `WebCrypto.layer` preset, and move Workers password hashing to `@yielded/auth-platform-workerd`. BEHAVIOR CHANGE: require Effect 4.1 and matching SQL drivers; replace `@yielded/crypto` and Auth's Workers subpaths with Effect crypto Layers or the Workers package, supply HTTP and the Kdf for `Testing.services()` separately, and use `Password.KdfAdmission.layer()`, optional `PasswordScrypt.layer`, and opaque Effect keys for JOSE.
- Updated dependencies [[`109c420`](https://github.com/yielded-dev/auth/commit/109c4201e63637c8e9c23039c5a248b872fddca0)]:
  - @yielded/jose@0.1.0-beta.47

## 0.1.0-beta.46

### Patch Changes

- Updated dependencies []:
  - @yielded/jose@0.1.0-beta.46

## 0.1.0-beta.45

### Patch Changes

- Updated dependencies []:
  - @yielded/jose@0.1.0-beta.45

## 0.1.0-beta.44

### Patch Changes

- Updated dependencies []:
  - @yielded/jose@0.1.0-beta.44

## 0.1.0-beta.43

### Patch Changes

- Updated dependencies [[`d29041b`](https://github.com/yielded-dev/auth/commit/d29041b595fe2c04a6c23dc974e3a40b49f8b307)]:
  - @yielded/jose@0.1.0-beta.43

## 0.1.0-beta.42

### Patch Changes

- [#243](https://github.com/yielded-dev/auth/pull/243) [`0a0ff7d`](https://github.com/yielded-dev/auth/commit/0a0ff7d6d81d8b9e0aacd39ec81991b1f259e956) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Preserve complete failure causes across authentication, persistence, provider, and native client boundaries, and report unexpected background and cleanup failures without exposing private data.
- Updated dependencies [[`0a0ff7d`](https://github.com/yielded-dev/auth/commit/0a0ff7d6d81d8b9e0aacd39ec81991b1f259e956)]:
  - @yielded/jose@0.1.0-beta.42

## 0.1.0-beta.41

### Patch Changes

- Updated dependencies []:
  - @yielded/jose@0.1.0-beta.41

## 0.1.0-beta.40

### Patch Changes

- Updated dependencies []:
  - @yielded/jose@0.1.0-beta.40

## 0.1.0-beta.39

### Patch Changes

- Updated dependencies []:
  - @yielded/jose@0.1.0-beta.39

## 0.1.0-beta.38

### Patch Changes

- Updated dependencies []:
  - @yielded/jose@0.1.0-beta.38

## 0.1.0-beta.37

### Patch Changes

- Updated dependencies []:
  - @yielded/jose@0.1.0-beta.37

## 0.1.0-beta.36

### Patch Changes

- Updated dependencies []:
  - @yielded/jose@0.1.0-beta.36

## 0.1.0-beta.35

### Patch Changes

- Updated dependencies [[`0a3254c`](https://github.com/yielded-dev/auth/commit/0a3254cfb5c4633d88a81aadb263a0efed7b3d85), [`b7f695b`](https://github.com/yielded-dev/auth/commit/b7f695bc71991164f0935ed7781a1898d9905aaf), [`948a3f1`](https://github.com/yielded-dev/auth/commit/948a3f12295b59c0bc560941edbbef59cc0b77b9), [`948a3f1`](https://github.com/yielded-dev/auth/commit/948a3f12295b59c0bc560941edbbef59cc0b77b9)]:
  - @yielded/jose@0.1.0-beta.35

## 0.1.0-beta.34

### Patch Changes

- [#203](https://github.com/yielded-dev/auth/pull/203) [`5264de7`](https://github.com/yielded-dev/auth/commit/5264de78aee570c82718b2841ec38ea17544fa3e) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Support Effect 4.0.3 across authentication workflows and companion packages. Require Effect 4.0.3 or later.
- Updated dependencies [[`5264de7`](https://github.com/yielded-dev/auth/commit/5264de78aee570c82718b2841ec38ea17544fa3e)]:
  - @yielded/jose@0.1.0-beta.34

## 0.1.0-beta.33

### Patch Changes

- [#181](https://github.com/yielded-dev/auth/pull/181) [`b9b43e2`](https://github.com/yielded-dev/auth/commit/b9b43e24f6fedda4168cfb65b081c296ffd9233f) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Add `Apple.provider` for Sign in with Apple, with ES256 client-secret JWTs from a `.p8` key. Accept form_post callbacks and first-consent names through direct routes with a `SameSite=None; Secure` request-binding cookie and through the callback proxy.

  BEHAVIOR CHANGE: Custom `Signature` services must implement `decodePrivateKey`.

- [#180](https://github.com/yielded-dev/auth/pull/180) [`0ad3e4c`](https://github.com/yielded-dev/auth/commit/0ad3e4cc67a954e3a2f20aae9491e1608fd5ccea) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Add Linear, Dropbox, and Notion sign-in. Plain OAuth identity can come from a GET, a POST, or the token response, and JSON token requests reject repeated parameter names.

- [#175](https://github.com/yielded-dev/auth/pull/175) [`2326161`](https://github.com/yielded-dev/auth/commit/232616128ad88418c375de9256614d37053c76e2) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Add LINE, Roblox, and Railway OpenID sign-in. LINE verifies web-login HS256 ID tokens with the channel secret, Roblox keeps its trailing-slash issuer, and Railway merges UserInfo from its published `/oauth` discovery document.

- [#178](https://github.com/yielded-dev/auth/pull/178) [`881f94d`](https://github.com/yielded-dev/auth/commit/881f94d31c9dfd3119bb2544925f9ee1d8b78368) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Add `Microsoft.provider` for Entra ID sign-in, with `oid:tid` subjects and a PKCE supplement for the v2.0 endpoints. Accept `{tenantid}` discovery issuers by substituting the verified `tid` and checking the selected signing key's issuer, including after a concrete tenant is pinned. Commercial `consumers` keeps the personal-account issuer, and a tenant domain is not accepted from that template. Refresh against the template requires the original `iss`.
- Updated dependencies [[`b9b43e2`](https://github.com/yielded-dev/auth/commit/b9b43e24f6fedda4168cfb65b081c296ffd9233f), [`881f94d`](https://github.com/yielded-dev/auth/commit/881f94d31c9dfd3119bb2544925f9ee1d8b78368)]:
  - @yielded/jose@0.1.0-beta.33

## 0.1.0-beta.32

### Patch Changes

- Updated dependencies []:
  - @yielded/jose@0.1.0-beta.32

## 0.1.0-beta.31

### Patch Changes

- [#171](https://github.com/yielded-dev/auth/pull/171) [`a1c5555`](https://github.com/yielded-dev/auth/commit/a1c555586cdf5415530ea71e08b25da3063772a3) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Let OAuth and OpenID presets carry their own profile schema, accept advertised ES256, PS256 and EdDSA ID tokens, and opt out of PKCE. Sign-in begin accepts prompt and loginHint, and OIDC can merge UserInfo into ID-token claims. EdDSA hash claims use SHA-512. Connected refresh keeps the stored identity and does not re-decode UserInfo-only profile fields.
- Updated dependencies []:
  - @yielded/jose@0.1.0-beta.31

## 0.1.0-beta.30

### Patch Changes

- Updated dependencies [[`dd0a495`](https://github.com/yielded-dev/auth/commit/dd0a4951597c230e6e7ef11725c626ce8b80318b)]:
  - @yielded/jose@0.1.0-beta.30

## 0.1.0-beta.29

### Patch Changes

- Updated dependencies []:
  - @yielded/jose@0.1.0-beta.29

## 0.1.0-beta.28

### Patch Changes

- Updated dependencies []:
  - @yielded/jose@0.1.0-beta.28

## 0.1.0-beta.27

### Patch Changes

- Updated dependencies []:
  - @yielded/jose@0.1.0-beta.27

## 0.1.0-beta.26

### Patch Changes

- Updated dependencies []:
  - @yielded/jose@0.1.0-beta.26

## 0.1.0-beta.25

### Patch Changes

- Updated dependencies []:
  - @yielded/jose@0.1.0-beta.25

## 0.1.0-beta.24

### Patch Changes

- Updated dependencies []:
  - @yielded/jose@0.1.0-beta.24

## 0.1.0-beta.23

### Patch Changes

- Updated dependencies []:
  - @yielded/jose@0.1.0-beta.23

## 0.1.0-beta.22

### Patch Changes

- Updated dependencies []:
  - @yielded/jose@0.1.0-beta.22

## 0.1.0-beta.21

### Patch Changes

- Updated dependencies []:
  - @yielded/jose@0.1.0-beta.21

## 0.1.0-beta.20

### Patch Changes

- [#123](https://github.com/yielded-dev/auth/pull/123) [`0c61f7a`](https://github.com/yielded-dev/auth/commit/0c61f7a766766929d642cc8e17b6091c89ea62e9) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Support OAuth requests on Cloudflare Workers while continuing to reject provider redirects.

- Updated dependencies []:
  - @yielded/jose@0.1.0-beta.20

## 0.1.0-beta.19

### Minor Changes

- [#107](https://github.com/yielded-dev/auth/pull/107) [`c4752e3`](https://github.com/yielded-dev/auth/commit/c4752e34b3b6f3a4f53270727fbdc3050d65935a) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Add reusable Effect crypto, Schema-typed JOSE, and OAuth/OIDC packages, and adopt them throughout Auth without changing stored credential formats. Remove unnecessary signing-service requirements from GitHub and use scoped HMAC keys for sessions and numeric proofs.

  BEHAVIOR CHANGE: Replace the former crypto/OpenID adapter imports with Auth's direct service Layers and `OpenIdConnect`/`GitHub` modules, supplying crypto and HTTP services explicitly. Implement scoped `Hmac.importKey` in custom backends, replace Auth `SubtleCrypto` overrides with `Hmac` Layers, and keep direct session/numeric-proof crypto constructors in an open Scope. Set managed storage's `prefix`, yield `Adapter.makeStorageMappings(storage)` with Effect Crypto supplied, and wrap application-owned Durable Object Drizzle databases with `SqliteDo.makeDatabase` for asynchronous transactions.

### Patch Changes

- [#107](https://github.com/yielded-dev/auth/pull/107) [`c4752e3`](https://github.com/yielded-dev/auth/commit/c4752e34b3b6f3a4f53270727fbdc3050d65935a) Thanks [@danieljvdm](https://github.com/danieljvdm)! - Require application-supplied crypto Layers throughout Auth and acquire storage-mapping dependencies through Effect requirements. Remove the unused Hmac requirement from JWKS and OIDC verification.

  BEHAVIOR CHANGE: Replace `Persistence.cryptoLayer` with your selected backend and provide it to the Auth Layer. Yield `Adapter.makeStorageMappings(storage)` inside an Effect with `Crypto` supplied.

- Updated dependencies [[`c4752e3`](https://github.com/yielded-dev/auth/commit/c4752e34b3b6f3a4f53270727fbdc3050d65935a), [`c4752e3`](https://github.com/yielded-dev/auth/commit/c4752e34b3b6f3a4f53270727fbdc3050d65935a)]:
  - @yielded/jose@0.1.0-beta.19
