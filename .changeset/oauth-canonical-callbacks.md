---
"@yielded/oauth": patch
"@yielded/auth": patch
"@yielded/auth-persistence": patch
"@yielded/auth-persistence-drizzle": patch
---

Add canonical `query`/`form_post` callback decoding (`OAuth.callbackParamsFromQuery`, `OAuth.callbackParamsFromFormPost`) and validation (`OAuth.validateCallback`) in `@yielded/oauth`, wire them through `@yielded/auth` HTTP callbacks, sign-in, linking, connected flows, and `OAuthProxy`, and enforce atomic `responseMode` binding in OAuth flow persistence.

BEHAVIOR CHANGE: HTTP and proxy `response_type=code` callbacks now reject unsolicited front-channel token parameters (`id_token`, `access_token`, `token`, `token_type`, `expires_in`, `response`), forward `OAuthCodeResponse.scope` and `OAuthCallbackResponse.mode`, and return `Cancelled` while clearing `request-binding` for every bound provider error. `OAuthFlowTable`, `oauthSignInFlows`, and `oauthConnectedFlows` add a nullable `responseMode` (`response_mode`) column (`"query"` or `"form_post"` for browser flows; `NULL` reserved for native sign-in flows) checked atomically at consumption so wrong-mode callbacks leave pending flows untouched. Development reset scope: add the nullable `response_mode` (`responseMode`) column or recreate the ephemeral `oauth_sign_in_flow` / `oauth_connected_flow` tables and clear in-flight pending flows; durable accounts, sessions, identities, and connected grants are unaffected.
