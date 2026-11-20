---
"@yielded/oauth": patch
"@yielded/auth": patch
"@yielded/auth-persistence": patch
"@yielded/auth-persistence-drizzle": patch
---

Add canonical OAuth callback decoding and validation (`OAuth.callbackParamsFromQuery`, `OAuth.callbackParamsFromFormPost`, `OAuth.validateCallback`), wire them across HTTP and proxy callbacks, and enforce atomic `responseMode` binding in OAuth flow persistence.

BEHAVIOR CHANGE: Callbacks reject front-channel token parameters (`id_token`, `access_token`, `token`, `token_type`, `expires_in`, `response`), cap `form_post` bodies at 16 KiB raw bytes, accept `user` only on `POST`, admit standard parameters (`state`, `code`, `error`, `error_description`, `error_uri`, `iss`, `scope`) plus `Http.make` provider names (`authuser`, `prompt`, `hd`), enforce RFC 6749 `code` syntax before consume, forward `OAuthCodeResponse.scope`, validate issuers under `OAuthIssuer` (failing closed at `begin`), and return `Cancelled` while clearing `request-binding` for bound provider errors. Observed transport is server-owned (`response.mode` removed; JSON completion routes record `"query"`, dedicated routes derive GET/POST, custom `form_post` hosts provide `OAuth.OAuthCallbackTransport`). Mapped tables must bind nullable `OAuthFlowTable.responseMode`, replacement persistence services must compare `access.responseMode` inside the conditional delete (`NULL` for native only), and dev databases need nullable `response_mode` on `${prefix}_oauthSignInFlows` and `${prefix}_oauthConnectedFlows` (or recreate them to clear in-flight browser flows; durable accounts, sessions, identities, and grants are unaffected).
