---
description: OAuth configuration, routes, sessions, and provider adapters.
---

# OAuth reference

Start with the [OAuth guide](../guide/oauth) for the flow and choice of API.

## Authorization server

`OAuthServer.make(id, { scopes })` supplies `Identity`, `Service`, `routes`,
`middleware(requiredScopes)`, `paths`, and `cookieName`. It implements authorization
code with S256 PKCE for registered public clients. It issues MCP bearer tokens;
it does not issue OIDC ID tokens or implement the MCP transport.

Provide these to `oauth.layer`:

| Input                     | Purpose                                                                                                                            |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `origin`                  | Authorization server issuer; one server per origin                                                                                 |
| `resource`                | Exact MCP resource URL on that origin, with a non-root path and no query or fragment                                               |
| `clients`                 | `{ clientId, name, redirectUris }[]`; redirect URIs match exactly, including loopback ports                                        |
| `loginPath`               | Local login route that returns to `oauth.paths.authorize`                                                                          |
| `keys`                    | Signing keyring in the same format as session keys; use separate random key material                                               |
| `oauth.Identity`          | `current`: an Effect that verifies the application session and returns `SubjectId` or `undefined`; may require `HttpServerRequest` |
| `OAuthServer.Persistence` | Durable grant storage; use `OAuthServerPersistence.layer` with SQLite, D1, or PostgreSQL                                           |

`Identity.current` runs on every consent GET and POST. Return `undefined` for an
absent or invalid session and fail with `OAuthServer.Unavailable` for an unavailable
dependency. The built-in consent page names the client, subject, resource, scopes,
and redirect host. Approval requires the bound cookie, form token, same Origin,
and the same subject that saw the page. Switching accounts invalidates previously
rendered consent forms. Pending authorization survives the login
redirect in the cookie; do not put it into a login URL.

With `OAuthApp`, put `oauth.paths.authorize` first in `returnTargets` and use the
app's sign-in route as `loginPath`. Keep provider grants and MCP grants separate.

| Route (ID `mcp`, resource `/mcp`)               | Behavior                                                                  |
| ----------------------------------------------- | ------------------------------------------------------------------------- |
| `GET /.well-known/oauth-authorization-server`   | Issuer, endpoints, scopes, public-client authentication and PKCE metadata |
| `GET /.well-known/oauth-protected-resource/mcp` | Resource and authorization server metadata                                |
| `GET /oauth/mcp/authorize`                      | Validate the authorization request, sign in if needed, and show consent   |
| `POST /oauth/mcp/authorize`                     | Approve or deny the browser-bound request                                 |
| `POST /oauth/mcp/token`                         | Redeem a code or rotate a refresh token                                   |
| `POST /oauth/mcp/revoke`                        | Revoke a token's entire grant; unknown tokens also return 200             |

Authorization requires `response_type=code`, `client_id`, `redirect_uri`, `resource`,
`scope`, `code_challenge`, and `code_challenge_method=S256`. Optional `state` is echoed
with the issuer (`iss`) in the callback. Token requests are form-encoded and require
`client_id` and `resource`. Code redemption also requires the original `redirect_uri`
and `code_verifier`. Refresh can retain or reduce scopes; it cannot expand them.
Malformed or rejected requests return 400; dependency failures return 503.

Attach `oauth.middleware(scopes).layer` only to protected routes. It extracts Bearer
credentials with Effect's HTTP APIs, verifies the grant, checks scopes, and supplies
`CurrentAccess` for that request. Missing/invalid tokens return a 401 discovery
challenge; insufficient scope returns 403; unavailable storage returns 503.
`CurrentAccess` defaults to `undefined` outside those requests. Never install a
principal at server startup. Use Effect's existing Origin checks and CORS middleware;
expose `WWW-Authenticate` to browser MCP clients.

### Token lifecycle and storage

Consent expires after five minutes, authorization codes after one minute, access
tokens after ten minutes, and grants after thirty days. Refresh does not extend
the grant's lifetime. Signing keys must remain available through the lifetimes of
the credentials they signed. Tokens are opaque to clients and use Yielded's signed
envelope rather than JWT serialization.

Each grant occupies one row in `yielded_oauth_server`. Apply
`OAuthServerPersistence.migration` through your application's migrations. The adapter
rejects ambient transactions and uses a conditional write for every transition;
revocation cannot be overwritten by a concurrent refresh. It stores no bearer or
provider tokens. Expired rows can be deleted using `expires_at_millis`.

Verification checks storage on every request. Refresh immediately invalidates the
previous access token. Reusing a consumed code or refresh token revokes the entire
grant, including after concurrent refresh attempts. Clients must serialize refresh
and replace their stored token pair. Revocation stops subsequent requests, but does
not cancel work already authorized. Application logout does not revoke MCP grants;
trusted application code can call `Service.revoke(grantId)` when policy requires it.

Issuance returns credentials only after a confirmed commit. An uncertain commit
returns no credentials and is never retried by the server; start a new authorization.
HTTP operations time out after thirty seconds and preserve caller interruption.
Form bodies are limited to 16 KiB. Applications own ingress rate limits and database
cleanup. Exclude OAuth query strings, bodies, cookies, and credentials from access
logs and tracing; the runnable example disables request logging and tracing.

Run `vp run @yielded/example-auth#example:strava-mcp` with the Strava example's
variables plus `MCP_SIGNING_KEY`, `MCP_CLIENT_ID`, and `MCP_REDIRECT_URI`. Configure
that exact client ID and redirect URI in your MCP client. The example listens on
port 3000 and owns `strava-mcp.sqlite`; use HTTPS outside loopback development.

## Managed app setup

`OAuthApp.make(id, options)` defines an app's services and routes.

| Option                  | Default    | Purpose                                                 |
| ----------------------- | ---------- | ------------------------------------------------------- |
| `claims`                | Required   | Schema for public session claims                        |
| `returnTargets`         | Required   | Allowed relative destinations; the first is the default |
| `sessionLifetimeMillis` | 30 days    | Fixed session lifetime; 1 second–30 days                |
| `flowLifetimeMillis`    | 5 minutes  | Time to complete authorization; 1 second–15 minutes     |
| `exchangeTimeoutMillis` | 30 seconds | Dependency timeout; 1–120 seconds                       |

Provide these to `app.layer`:

| Dependency                                    | Application supplies                                                                         |
| --------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `origin`, `provider`                          | Trusted app origin and configured provider                                                   |
| `sessionKeys`, `transactionKeys`, `tokenKeys` | Three distinct keyrings                                                                      |
| `app.Accounts`                                | `resolve(verified)` → Effect of `{ subjectId, claims }`                                      |
| `OAuthApp.Persistence`                        | Durable flow and encrypted grant storage                                                     |
| Provider services                             | GitHub: `openid-client`; Strava: an Effect `HttpClient` without retry or redirect middleware |

`Accounts.resolve` checks invitations/status and owns provisioning. Reject with
`OAuthRejected`; map infrastructure failures to `OAuthUnavailable`.

A keyring is `{ activeKeyId, keys: [{ id, material }] }`. Each `material` is a
redacted base64url encoding of 32 random bytes. Keep old keys while sessions,
pending flows, or retained grants still reference them.

`OAuthAppPersistence.layer` accepts an Effect SQL client for SQLite, D1, or
PostgreSQL. Apply `OAuthAppPersistence.migration` with your migration runner;
it creates the independent `yielded_oauth_app` table. The adapter rejects ambient
transactions. A custom store implements the
[Persistence contract](https://github.com/yielded-dev/auth/blob/main/packages/auth/src/oauth/app/models.ts).

Exclude callback queries, tokens, and cookies from telemetry. Effect's server
tracer records query strings; the
[GitHub example](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/github-app.ts)
uses `HttpMiddleware.TracerDisabledWhen` on the outer server Layer to omit callback
spans. Application mutations need their own CSRF protection.

Run the GitHub example with `vp run @yielded/example-auth#example:github`. Set
`GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_USER_ID`, `SESSION_KEY`,
`OAUTH_TRANSACTION_KEY`, and `OAUTH_TOKEN_KEY`. It listens at `http://localhost:3000`
and owns `github-auth.sqlite`; `APP_ORIGIN` overrides the origin.

## Managed routes

Mount `app.routes`, or pass native requests to the provided service's `handle`.
Paths below use the app ID `github`.

| Request                                      | Behavior                                                                         |
| -------------------------------------------- | -------------------------------------------------------------------------------- |
| `GET /auth/github/sign-in?returnTo=/account` | Sets a browser binding and redirects to the provider; `returnTo` must be allowed |
| `GET /auth/github/callback`                  | Completes authorization, sets the session cookie, and redirects                  |
| `GET /auth/github/session`                   | Returns public session data; 401 for missing/invalid credentials                 |
| `POST /auth/github/sign-out`                 | Requires the same Origin; clears the cookie and returns 204                      |

Rejected flows return 400; unavailable dependencies return 503. Responses use
`Cache-Control: no-store`. Cookies are HttpOnly, SameSite=Lax, and Secure on HTTPS.
Session credentials never appear in redirect URLs.

## Sessions and connections

`app.sessionLayer({ origin, sessionKeys })` provides `app.Sessions` independently
of storage and providers. `verify(redactedCredential)` returns the typed session
or `SessionInvalid` / `OAuthUnavailable`.

Sessions use Yielded's signed envelope, not JWT serialization. Claims are readable
and fixed at sign-in. Sessions have no renewal or individual revocation: sign-out,
role changes, invitation removal, and provider disconnect do not invalidate an
issued credential. Choose a lifetime that fits your authorization policy.

| Service method                                 | Behavior                                                                                     |
| ---------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `withAccessToken({ subjectId, grantId }, use)` | Refreshes and saves provider tokens before calling `use(redactedToken)`; never retries `use` |
| `disconnect({ subjectId, grantId })`           | Disables local provider access; does not revoke tokens at the provider                       |

These methods are server capabilities. Obtain the connection reference from a
verified session or trusted storage. Disconnect cannot cancel work that already
obtained a token. An omitted refresh token preserves the existing token and its provider expiry.

| Failure                                 | Recovery                                                  |
| --------------------------------------- | --------------------------------------------------------- |
| `OAuthConnectedBusy`                    | Another operation is in progress; retry acquisition later |
| `OAuthConnectedReauthorizationRequired` | Start a fresh authorization                               |
| Uncertain code exchange or refresh      | Start a fresh authorization; never repeat the exchange    |

Refresh-claim expiry does not permit credential reuse. Retain grant identities,
including disconnected grants; do not clear claims to recover access. Expired flow
records may be pruned, and flow IDs must never be reused.

## Shared auth setup

Declare the actions for `OAuth` inside `Auth.make`:

```ts [auth-contract.ts]
import { Schema } from "effect";
import { AuthContract } from "@yielded/auth/contracts";

export const AuthApi = AuthContract.make("app/Auth", {
  claims: Schema.Struct({ displayName: Schema.String }),
  actions: (sessions) => ({
    signIn: AuthContract.oauthSignIn(),
    completeSignIn: AuthContract.oauthCompleteSignIn(sessions),
  }),
});
```

### Supply the services

With `AppAuth` from the guide and `AuthRoutes` from a provider page:

```ts [oauth-live.ts]
import { Layer } from "effect";
import { OAuth } from "@yielded/auth/strategies";
import { AppAuth } from "./auth";
import { AuthDependencies } from "./auth-dependencies";
import { resolveOAuthClaims } from "./auth-accounts";
import { transactionKeys } from "./auth-config";
import { OAuthPersistenceLive } from "./auth-persistence";
import { AuthRoutes } from "./github";

const OAuthLive = Layer.mergeAll(
  OAuthPersistenceLive,
  Layer.succeed(AppAuth.strategies.social.ClaimsForOAuth, { resolve: resolveOAuthClaims }),
  OAuth.OAuthTransactionProtector.xchacha20poly1305(transactionKeys),
  OAuth.OAuthReturnTargets.exactRoutes(["/account"]),
);

export const Routes = AuthRoutes.pipe(Layer.provide(OAuthLive), Layer.provide(AuthDependencies));
```

The application modules supply [OAuth persistence](./adapters#oauth), claims,
transaction keys, and [shared auth dependencies](./adapters#compose-the-application-layer).
Flows default to five minutes; the strategy's `policy` overrides this.

## Customize callbacks

Shared auth derives `/auth/{provider}/callback` from `origin` and the contract's
base path. Callbacks require HTTPS, except HTTP on `localhost`, `127.0.0.1`, or
`[::1]` for local development. Provider endpoints always require HTTPS.
Override a provider's path through `Http.layer`:

```ts
const AuthRoutes = Http.layer(AppAuth, {
  origin,
  oauth: {
    providers,
    callbacks: { github: { path: "/login/github/return" } },
  },
});
```

| Customization               | API                                                                                       |
| --------------------------- | ----------------------------------------------------------------------------------------- |
| Multiple destinations       | Array of `{ callbackId, path }`; paths must be unique                                     |
| Select a destination        | Pass `callbackId` at sign-in; otherwise the provider-named or sole entry is used          |
| Custom completion response  | `oauth.respond`, or a provider callback's `respond`                                       |
| Multiple completion actions | Select with `oauth.complete`                                                              |
| Custom HttpApi composition  | `Http.make(AppAuth, options)` exposes `handlers(api)`, `callbackRoutes()`, and middleware |
| Application-owned callback  | Use `GitHub.layer` or `OpenIdClient.layer` with an explicit `redirectUri`                 |

`respond` receives the schema-encoded public result and `{ flowId, provider, callbackId }`.
It returns `Effect<Response, OperationHttpError, R>`; cookie delivery remains managed.
Custom completion actions need `oauthCallback: true` and the single-use request-binding
mapping. See the [registration example](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/login-server.ts).

## Providers

| Integration                  | Configure                                                                            |
| ---------------------------- | ------------------------------------------------------------------------------------ |
| Managed GitHub app           | `GitHub.appProvider({ clientId, clientSecret, scopes })`                             |
| Managed Strava app           | `Strava.provider({ clientId, clientSecret, scopes })`                                |
| Other managed provider       | Implement `OAuthApp.Provider.configure(callbackUrl)`                                 |
| Shared auth with GitHub      | [`GitHub.provider`](../guide/github)                                                 |
| Shared auth with OIDC        | [`OpenIdClient.provider`](../guide/google) with issuer and credentials               |
| Shared auth with plain OAuth | `OpenIdClient.provider` with `protocol: "oauth"`, endpoints, and an identity decoder |

A managed provider returns a permission profile and `OAuthConnectedProtocol` service.
It owns response verification, accepted permissions, identity checks, and token exchange.
Keep required services and configuration failures in the configure Effect's types.

`GitHub.appProvider` uses a GitHub.com OAuth App, defaults to `read:user`, and requests
`offline_access` for rotating tokens. Local refresh retention defaults to thirty days;
set `maximumRefreshLifetimeMillis` to shorten it. Install `openid-client`.
See [GitHub's OAuth flow](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps).

The Strava adapter uses confidential-client authorization without PKCE. It checks
accepted scopes from the token response or bound callback and rechecks athlete
identity on refresh. Its refresh retention is thirty days from the last successful
exchange; this is library policy, not provider expiry. Use one managed owner per
client registration. Fetch redirects are disabled; custom HTTP clients must also reject redirects.
See [Strava's contract](https://developers.strava.com/docs/authentication/).

For plain OAuth with `OpenIdClient`, provide `authorizationEndpoint`, `tokenEndpoint`,
`identitySource.url`, and `identitySource.decodeIdentity`. The decoder returns an
Effect containing the stable `subject` and optional profile. Set scopes explicitly.

### OpenIdClient defaults

| Setting                                | Default               |
| -------------------------------------- | --------------------- |
| `callbackId`                           | Provider key          |
| `configurationGeneration` / `issuance` | `1` / `active`        |
| `timeoutSeconds`                       | `10` (range: 1–30)    |
| `tokenEndpointAuthMethod`              | `client_secret_basic` |
| OIDC scopes / signing algorithm        | `["openid"]` / RS256  |
| Plain OAuth scopes                     | `[]`                  |

S256 PKCE and response issuer validation are required by default. Set
`responseIssuerMode: "unsupported"` only for providers without issuer responses.
Public clients use `authentication: { method: "none", publicClient: true }`.
Load secrets with `Config.redacted`. Invalid settings fail Layer construction with
`OpenIdClientConfigurationError`.

### Configuration rotation

For shared auth, use `provider({ registrations: [...] })` to retain older entries
with `issuance: "retired"` while flows or connected grants reference them. Assign
a new `configurationGeneration` when settings change and keep one active generation.
Retain old callback paths until their flows expire.

Earlier GitHub adapters used the issuer `https://github.com`; the current identity
uses `https://github.com/login/oauth`. Old bindings are not reused automatically.
Revoke old grants before upgrading, then register/link and reconnect. Do not rewrite
stored issuers: they are part of identity keys and encrypted context.

## Provider profiles

Verified identity is the provider/issuer/subject tuple. `profile` is optional
metadata: display fields plus bounded `providerData`. It does not authorize account
linking or local roles. Expose only needed fields in claims; treat profile URLs as
untrusted input.

| Consumer                      | Profile access                                 |
| ----------------------------- | ---------------------------------------------- |
| Returning shared-auth sign-in | `ClaimsForOAuth.resolve(credential, verified)` |
| Shared-auth registration      | Server-side `OAuthRegistrationIntent.profile`  |
| Managed app account policy    | `app.Accounts.resolve(verified)`               |

`GitHubUserProfile` and `OidcUserProfile` schemas decode the adapters' provider data.
Missing fields remain absent; GitHub nullable values remain null. GitHub's `/user`
email is not asserted verified. Adapters do not fetch additional email or UserInfo
endpoints or retain unknown fields. Connected-grant refresh need not update profiles.

Detailed signatures and invariants live beside the
[OAuth source](https://github.com/yielded-dev/auth/tree/main/packages/auth/src/oauth).
