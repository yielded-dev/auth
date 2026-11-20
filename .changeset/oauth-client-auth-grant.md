---
"@yielded/auth": patch
"@yielded/oauth": patch
---

Add `ClientAuth` (including RFC 10070 `secretJwt`/`privateKeyJwt` and name-bound `unwrap`), `Grant` (`authorizationCode`, `{ issuer, clientId }`-bound `fromTransaction`, `refreshToken`, `clientCredentials`, `make`, `TokenReceipt`/`TokenReceiptFromJson`, `parseTokens`), scoped `OAuth.Client` (`make`/`layer`, `prepareAuthorization`, `OAuth.authorize`, `exchangeRaw`/`exchange`, `revoke`), and `Oidc.authorize` in `@yielded/oauth`, and migrate `@yielded/auth` providers including Apple and Strava onto them.

BEHAVIOR CHANGE: Direct `@yielded/oauth` consumers must migrate from `OAuth.make({ metadata, authentication, timeoutMs })`, `client.codeGrant`/`refreshGrant`, and `OAuth.tokens` to `Discovery`, `ClientAuth`, `Grant`, and `OAuth.Client`; authorization URLs now omit `response_mode` for `"query"`, and HTTP `5xx` responses fail with `TransportFailed`. In `@yielded/auth`, Strava HTTP `401` token responses now report `OAuthUnavailable` instead of `OAuthProtocolRejected` to match all other providers; no stored-data reset is required.
