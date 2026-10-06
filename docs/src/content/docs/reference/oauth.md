---
title: OAuth reference
description: OAuth configuration, routes, sessions, and provider adapters.
---

Start with the [OAuth guide](../guide/oauth) for the flow and choice of API.

## Authorization server

`OAuthServer.make(id, { scopes })` supplies `Identity`, `Service`, `routes`,
`middleware(requiredScopes)`, and `paths`. The acquired `Service` exposes the
origin-dependent `cookieName`. It implements authorization code with S256 PKCE,
Client ID Metadata Documents (CIMD), and pre-registered public or confidential
clients for MCP's 2026-07-28 authorization profile. Effect owns the MCP transport.
OIDC ID tokens, dynamic registration, client-credentials grants,
and optional MCP authorization extensions are not supported.

Provide these to `oauth.layer`:

| Input                     | Purpose                                                                                                                                        |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `origin`                  | Authorization server issuer; one server per origin                                                                                             |
| `resource`                | Exact MCP resource URL on that origin, at the root or a path, without query or fragment                                                        |
| `clients`                 | Static `{ clientId, name, redirectUris, applicationType?, clientSecret?, clientAssertion?, grantTypes? }[]`; may be empty when CIMD is enabled |
| `clientMetadata`          | Optional `{ allowedOrigins: ["https://assistant.example"] }` trust policy for CIMD and its JWKS URLs                                           |
| `HttpClient.HttpClient`   | Required Effect HTTP client; supplies the network egress policy for metadata fetches                                                           |
| Crypto services           | `Crypto.Crypto`, `Hmac`, and `Signature`; supply an explicit `@yielded/crypto` backend, as in the runnable example                             |
| `loginPath`               | Local login route that returns to `oauth.paths.authorize`                                                                                      |
| `keys`                    | Signing keyring in the same format as session keys; use separate random key material                                                           |
| `oauth.Identity`          | `current`: an Effect that verifies the application session and returns `SubjectId` or `undefined`; may require `HttpServerRequest`             |
| `OAuthServer.Persistence` | Durable grants and assertion replay receipts; use `OAuthServerPersistence.layer` with SQLite, D1, or PostgreSQL                                |

`Identity.current` runs on every consent GET and POST. Return `undefined` for an
absent or invalid session and fail with `OAuthServer.Unavailable` for an unavailable
dependency. The built-in consent page names the client, subject, resource, scopes,
and redirect host. Approval requires the bound cookie, form token, same Origin,
and the same subject that saw the page. Switching accounts invalidates previously
rendered consent forms. Pending authorization survives the login
redirect in the cookie; do not put it into a login URL. HTTPS consent cookies use
`__Host-yielded-${id}-consent`, Secure, HttpOnly, SameSite=Lax, and Path=/ without a
Domain. Loopback HTTP development uses an unprefixed cookie.

Allow `oauth.paths.authorize` in `OAuthReturnTargets` and have your login page
request that return target. Set `loginPath` to that page. Keep provider and MCP grants separate.

| Route (ID `mcp`, resource `/mcp`)               | Behavior                                                                 |
| ----------------------------------------------- | ------------------------------------------------------------------------ |
| `GET /.well-known/oauth-authorization-server`   | Issuer, endpoints, scopes, client authentication, CIMD and PKCE metadata |
| `GET /.well-known/oauth-protected-resource/mcp` | Resource and authorization server metadata                               |
| `GET /oauth/mcp/authorize`                      | Validate the authorization request, sign in if needed, and show consent  |
| `POST /oauth/mcp/authorize`                     | Approve or deny the browser-bound request                                |
| `POST /oauth/mcp/token`                         | Redeem a code or rotate a refresh token                                  |
| `POST /oauth/mcp/revoke`                        | Revoke a token's entire grant; unknown tokens also return 200            |

Authorization requires `response_type=code`, `client_id`, `resource`, `scope`,
`code_challenge`, and `code_challenge_method=S256`. `redirect_uri` may be omitted
when the client has exactly one registered callback. Optional `state` is echoed
with `iss` in success and error callbacks. For an authenticated user, request
errors return to a validated static or same-origin metadata callback; other
metadata callbacks require an explicit return link. Unknown clients, invalid
callbacks, and unauthenticated request errors fail locally. Token requests are form-encoded and
require `resource` and client identification. Code redemption requires
`code_verifier`; an optional `redirect_uri` must match the actual authorization
callback exactly. Refresh can retain or reduce scopes; it cannot expand them.
Malformed or rejected requests return 400; failed HTTP Basic authentication returns
401 with a Basic challenge; unavailable dependencies return 503.

### Clients and metadata discovery

Static registrations take precedence over CIMD. A static client's optional
`clientSecret` is a `Redacted<string>`: setting it makes the client confidential,
requiring HTTP Basic or `client_secret` form authentication at both the token and
revocation endpoints. Alternatively, set `clientAssertion: { jwks }` or
`clientAssertion: { jwksUri: "https://client.example/keys.json" }` for
`private_key_jwt`. Configure exactly one key source and no `clientSecret`.
An optional `clientAssertion.algorithm` pins the signing algorithm. Public clients
cannot submit client credentials. PKCE is required for all clients.
`grantTypes` limits redemption to `authorization_code` and/or
`refresh_token`; omitting it permits both for static clients.

Callbacks match exactly. For a client with `applicationType: "native"` (CIMD:
`application_type`), HTTP loopback callbacks may vary only their port during
authorization. The selected callback remains bound to the code. Consent shows the
callback host and warns for HTTP loopback callbacks.

Set `clientMetadata.allowedOrigins` to trusted HTTPS DNS origins to enable CIMD;
discovery then advertises `client_id_metadata_document_supported: true`. Each
metadata URL must have a non-root path and no credentials, fragment, or dot
segments. Documents require `client_id`, `client_name`, and `redirect_uris`, with
an exact `client_id` match. `token_endpoint_auth_method` may be `"none"` (the
default) or `"private_key_jwt"`. The latter requires exactly one of `jwks` or
`jwks_uri`, and accepts an optional `token_endpoint_auth_signing_alg`.
JWKS URLs must use HTTPS DNS names; metadata-discovered key URLs must also belong
to `clientMetadata.allowedOrigins`. Shared-secret fields, private or symmetric
keys, and unsupported authentication methods are rejected.
Optional `grant_types` defaults to `authorization_code`; include
`refresh_token` to enable refresh. Unknown extension fields are ignored. The
consent page also displays the metadata URL's hostname.

Fetches accept only 200 JSON responses, reject redirects, limit metadata bodies to
5 KiB and JWKS bodies to 128 KiB,
time out after five seconds, and allow at most eight concurrent requests per
server Layer. Valid documents are cached according to HTTP freshness headers for
at most five minutes, with at most 256 entries in each cache. `no-store`, `no-cache`, `private`, `Vary: *`, invalid
documents, and errors are not cached; expired entries are never used on failure.
Metadata is checked again as needed during consent, redemption, and access-token
verification. Removing a callback can therefore invalidate an existing grant once
the cached document expires.

Supply an `HttpClient` even when CIMD is disabled. For metadata or JWKS fetches, use only
origins your application trusts and a client/network policy that blocks private,
loopback, and link-local destinations after DNS resolution, including DNS
rebinding. The HTTP client must not follow redirects or inject ambient credentials;
`FetchHttpClient` receives `redirect: "error"` and `credentials: "omit"`. Origin
validation alone does not enforce DNS/network isolation.

### Private-key client assertions

Send a new signed JWT in `client_assertion` for each token or revocation request,
with `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`.
Do not combine it with Basic or form-secret authentication. If `client_id` is
omitted, the unverified `sub` identifies the registration to look up; signature
and claim validation still establish authentication.

Assertions require `iss` and `sub` equal to the exact client ID, `jti` unique to
that client, and `exp` in the future and no more than five minutes ahead.
The audience must include the issuer or token endpoint URL; revocation also
accepts its own endpoint URL. Optional `nbf` and `iat` cannot be in the future;
`iat` must precede `exp`. There is no clock-skew allowance. Assertions are limited
to 8 KiB and support RS256, PS256, ES256, and EdDSA (Ed25519), advertised in
discovery. Key selection and verification use `@yielded/jose`; JWT headers never
supply key locations.

Key rotation takes effect when the cached JWKS expires. Publish overlapping keys
for that interval; there is no stale-key fallback on fetch failure. Every accepted
assertion consumes a durable receipt before processing the grant. Reuse fails
across endpoints and server instances, even if the subsequent operation failed.
A lost receipt acknowledgment returns 503; create a fresh assertion for a later
request. This does not make an uncertain token-issuance outcome safe to retry.

### Protecting MCP routes

Attach `oauth.middleware(scopes).layer` only to protected routes. It extracts Bearer
credentials with Effect's HTTP APIs, verifies the grant, checks scopes, and supplies
`CurrentAccess` for that request. Missing/invalid tokens return a 401 discovery
challenge; insufficient scope returns 403; unavailable storage returns 503.
`CurrentAccess` defaults to `undefined` outside those requests. Never install a
principal at server startup. Use Effect's existing Origin checks and CORS middleware;
expose `WWW-Authenticate` to browser MCP clients. Apply CORS to the token,
metadata, revocation, and MCP routes as needed; exclude the authorization endpoint.
Scope names are independent permissions; define any application hierarchy before
choosing the scopes required by a route.

### Token lifecycle and storage

Consent expires after five minutes, authorization codes after one minute, access
tokens after ten minutes, and grants after thirty days. Refresh does not extend
the grant's lifetime. Signing keys must remain available through the lifetimes of
the credentials they signed. Tokens are opaque to clients and use Yielded's signed
envelope rather than JWT serialization.

Each grant occupies one row in `yielded_oauth_server`. Apply each statement in
`OAuthServerPersistence.migrations` once through your application's migrations;
the second creates `yielded_oauth_client_assertion` for replay receipts. Existing
grant tables need only that additional table. Custom persistence adapters must
implement `consumeAssertion` as an atomic standalone insert that returns false
for a duplicate receipt. Retain receipts through their expiration; all server
instances sharing an issuer must share this storage. Only a digest of the client
ID and JWT ID is stored, alongside the issuer namespace and expiry. The adapter
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
cleanup. Apply admission limits to authorization GET requests too: a valid request
allocates a pending row before login. Pending rows expire after five minutes;
schedule cleanup of expired rows using `expires_at_millis`. Exclude OAuth query strings, bodies, cookies, and credentials from access
logs and tracing; the runnable example disables request logging and tracing.

Run `vp run @yielded/example-auth#example:strava-mcp` with the Strava example's
variables plus `MCP_SIGNING_KEY` and `MCP_REDIRECT_URI`. Set `MCP_CLIENT_ID` for a
static registration, or `MCP_CLIENT_METADATA_ORIGIN` to accept CIMD clients
from that trusted origin. The callback origin also sets the example's CORS policy;
apply the network restrictions above when enabling metadata discovery. The example listens on
port 3000 and owns `strava-mcp.sqlite`; use HTTPS outside loopback development.

## Retained access

`OAuth.make({ access: profile })` retains the provider grant during normal sign-in.
Without `access`, verified sign-in discards all provider tokens. The profile selects
provider/client registration, scopes/resources, token retention, refresh limits,
and revocation support. It does not provision accounts or select a session mode.

| Service/configuration                                        | Purpose                                                              |
| ------------------------------------------------------------ | -------------------------------------------------------------------- |
| `OAuthSignInPersistence`                                     | Existing account links and single-use sign-in flows                  |
| `OAuthConnectedPersistence`                                  | Grant retention, refresh, disconnect, and durable operation ordering |
| `OAuthConnectedProtocol`                                     | The single code exchange plus refresh and revocation                 |
| `OAuthTransactionProtector`                                  | Encrypted sign-in transaction secrets                                |
| `OAuthConnectedTransactionProtector`                         | Connected-operation transaction secrets                              |
| `OAuthConnectedTokenProtector`                               | Encrypted provider tokens and cleanup jobs                           |
| `OAuthConnectedUseAuthority`, `OAuthConnectedActionEvidence` | Current permission for token use and disconnect                      |
| `SessionClaims`, shared session services                     | Application claims and authentication completion                     |

The Drizzle connected mapping must include `signIn: { credential, flow }` pointing
to the same tables as sign-in persistence, plus `flow.encodeSignIn`. Connected-flow
`subjectId` must allow NULL while identity is unknown. Keep every required unique
constraint and use the database engine's wall clock. See the
[example storage](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/oauth-storage.ts).

The bound strategy exposes `access.ConnectedAccess`, `access.accessLayer`, and
`access.maintenanceLayer`. Install the maintenance service and run its bounded
passes through an application-owned scheduler when profiles support remote
revocation. `Auth` exposes `listAccountConnections` and `disconnectAccount`; public
completion results may include `{ connection: { grantId, profileKey } }`.

Confirmed retention precedes session delivery. A lost commit response releases no
session and never permits repeating the code. Refresh claims are single-use even
after their deadline; unknown external outcomes remain unresolved. Retain the
associated identities and receipts. Known losing exchanges use cohort cleanup jobs
when supported, or discard their tokens locally when revocation is unsupported.
Unresolved exchanges with unknown identity can block cohort cleanup for that client
registration and require application-owned reconciliation; expiry alone is not proof
that the provider operation did not happen.

### Connect an authenticated account

`OAuth.makeConnectedModule` manages provider access independently of sign-in.
Call `Connected.prepareBegin` first: it retains the generated grant identity,
PKCE/state, callback, profile, revisions, and expiry in native flow custody.
Preparation returns only a public flow ID and expiry, plus a private
`connected-intent` credential command. It cannot exchange a code or activate a grant.

A trusted server factor adapter calls `Connected.beginContext` with that private
credential and the original input, verifies independent evidence for the returned
challenge, and then calls `Connected.begin` with the same input and proof. Keep the
challenge's flow ID, binding digest, and full revision unchanged. Re-reading a target
must never rebind an already verified proof. `completeContext` resolves the original
callback target; `disconnectContext` resolves the native grant and command target.
These context methods are server-only services, not public HTTP operations. Factor
selection, proof custody and one-time consumption remain application-owned through
`OAuthConnectedActionEvidence`; ordinary session history is not an exact-action proof.

Use the existing Operation HTTP credential mapping to keep credentials out of JSON:

```ts
const beginRoute = OperationHttpContract.route(connected.operations.Begin, {
  path: "/auth/provider/begin",
  credentials: {
    preparationCredential: "connected-intent",
    actionProof: "pending-proof",
  },
});
```

`Complete` maps `requestBinding` to `request-binding`; map `actionProof` to your
private proof slot for complete and disconnect as well. Execute begin only after
proof authorization to receive the retained authorization URL and move the original
binder into `request-binding`. Keep flow and command IDs across retries. Duplicate
preparations and uncertain commits never authorize issuing a replacement credential.
Disconnect preserves its existing durable command replay and revocation receipts.

Custom persistence adapters must implement `prepare` and `inspectPrepared`, and
change `issue` to atomically promote the exact retained preparation to `Pending`.
Use `OAuthConnectedSealedTransaction` for connected flow storage and transaction
protectors; its bounded envelope includes the retained authorization URL.
Unclaimed connected-management flows from before this cutover must be restarted;
retain grants, exchange receipts and unresolved revocation work. Ordinary sign-in
flow envelopes are unchanged.

### Runnable examples

For sign-in without retained provider access, run the [Slack example](../guide/slack#run-the-example).

Run `vp run @yielded/example-auth#example:github` with `GITHUB_CLIENT_ID`,
`GITHUB_CLIENT_SECRET`, `GITHUB_USER_ID`, `SESSION_KEY`, `OAUTH_TRANSACTION_KEY`,
and `OAUTH_TOKEN_KEY`. Open `/login`; the Atom client starts sign-in through the shared
POST action. Register `http://localhost:3000/auth/github/callback` with the provider.
`APP_ORIGIN` overrides the origin; HTTPS is required outside loopback development.

A keyring is `{ activeKeyId, keys: [{ id, material }] }`, where each material is a
redacted base64url encoding of 32 random bytes. Use distinct keys for sessions,
transactions, and provider tokens. Retain old keys while records reference them.
The examples disable request logs and traces that could include callback credentials.

The Strava task is `example:strava`; use `STRAVA_CLIENT_ID`, `STRAVA_CLIENT_SECRET`,
and `STRAVA_ATHLETE_ID` instead, and register `/auth/strava/callback`. The examples own
new `github-auth-v2.sqlite`, `strava-auth-v2.sqlite`, and `strava-mcp-auth-v2.sqlite`
files. The allowlisted provider tuple is explicitly provisioned by the application;
other identities cannot sign in. The example denies connected management actions
until an application supplies independent exact-action evidence; ordinary session
metadata is not treated as a fresh proof.

The former OAuthApp cookie, flow, and grant format is removed. For development,
clear its cookies and reset its flow/grant table before using shared Auth storage.
Existing connected token envelopes also need resetting because they now bind the
exchange order. Preserve account subject IDs, identity tuples, and any receipts or
revocation work needed to reconcile real external credentials; the library performs
no automatic deletion or migration.

## Shared auth setup

Declare the actions for `OAuth` inside `Auth.make`:

```ts title="packages/domain/auth-contract.ts"
import { Schema } from "effect";
import { AuthContract } from "@yielded/auth";

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

```ts title="apps/server/oauth-live.ts"
import { Layer } from "effect";
import { OAuth } from "@yielded/auth";
import { FetchHttpClient } from "effect/http";
import { CryptoLive } from "./crypto-live";
import { AppAuth } from "./auth";
import { AuthDependencies } from "./auth-dependencies";
import { resolveOAuthClaims } from "./auth-accounts";
import { transactionKeys } from "./auth-config";
import { OAuthPersistenceLive } from "./auth-persistence";
import { AuthRoutes } from "./github";

const OAuthLive = Layer.mergeAll(
  OAuthPersistenceLive,
  Layer.succeed(AppAuth.strategies.social.SessionClaims, { resolve: resolveOAuthClaims }),
  OAuth.OAuthTransactionProtector.layer(transactionKeys),
  OAuth.OAuthReturnTargets.exactRoutes(["/account"]),
);

export const Routes = AuthRoutes.pipe(
  Layer.provide(OAuthLive),
  Layer.provide(AuthDependencies),
  Layer.provide(Layer.merge(CryptoLive, FetchHttpClient.layer)),
);
```

For sibling apps, configure [cross-origin return targets](../guide/http-and-client#sharing-sessions-across-apps).

The application modules supply [OAuth persistence](./adapters#oauth), claims,
transaction keys, and [shared auth dependencies](./adapters#compose-the-application-layer).
[`CryptoLive`](./crypto#use-with-auth) supplies Effect `Crypto` and the first-party
`Aead`, `Hmac`, and `Signature` services. Native `OpenIdConnect` and `GitHub`
providers require `HttpClient` and `Crypto`; OpenID Connect also requires `Signature`. Protectors need
`Aead` and `Crypto`. Keep the resulting Layer in the server's application scope:
provider clients and per-configuration JWKS caches close with that scope. Closure
cancels and joins active operations, including application identity decoders;
pending results and later calls fail with `OAuthUnavailable`. Do not
extract a configured provider from a completed `Effect.provide` and reuse it later.

Flows default to five minutes; the strategy's `policy` overrides this.
For account linking use `OAuth.OAuthLinkTransactionProtector.layer(transactionKeys)`.
Retained access also needs `OAuth.OAuthConnectedTransactionProtector.layer(transactionKeys)`
and `OAuth.OAuthConnectedTokenProtector.layer(tokenKeys)`, with a separate token keyring.

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
| Application-owned callback  | Use `GitHub.layer` or `OpenIdConnect.layer` with an explicit `redirectUri`                |

`respond` receives the schema-encoded public result and `{ flowId, provider, callbackId }`.
It returns `Effect<Response, OperationHttpError, R>`; cookie delivery remains managed.
Custom completion actions need `oauthCallback: true` and the single-use request-binding
mapping. See the [registration example](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/login-server.ts).

## Callback proxy

Use `OAuthProxy` for sign-in or registration from explicitly registered local and
preview environments. The [setup guide](../guide/oauth#local-and-preview-environments)
explains how the callback server fits into an app.
Account linking, retained grants, and connected-account workflows are unsupported;
omit `access` from the OAuth strategy.

### Callback server

`OAuthProxy.layer(options)` installs `OAuthProxy.Server`:

| Option         | Value                                                                    |
| -------------- | ------------------------------------------------------------------------ |
| `origin`       | Public HTTPS origin, such as `https://auth.example.com`                  |
| `path`         | Route prefix; defaults to `/oauth-proxy`                                 |
| `providers`    | Native provider declarations, such as `{ github: GitHub.provider(...) }` |
| `environments` | Registrations decoded with `OAuthProxy.Environment`                      |

Each environment is `{ id, secret, callbacks: [{ provider, callbackId, redirectUri }] }`.
Give it a distinct redacted secret containing 32 random bytes encoded as unpadded
base64url. Completion URLs must match exactly, with no wildcard, query, or fragment.
Only loopback completions may use HTTP; set `cookie: { secure: false }` in those apps.

Mount `OAuthProxy.routes` and register `{origin}{path}/{provider}/callback` with the
provider. Supply `OAuthProxy.protectorLayer(keys)` with a separate transaction keyring
and `OAuthProxyPersistence.layer` from `@yielded/auth-persistence` with a SQLite/D1 or
PostgreSQL Effect SQL client. Apply its `migration` once. Server replicas share storage
and protector keys. See the [complete composition](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/oauth-proxy-application.ts)
for the Layers, including [HTTP and crypto services](#supply-the-services).

For Drizzle, import `OAuthProxyPersistence` from your SQLite/D1 or PostgreSQL
driver module:

```ts
import { OAuthProxyPersistence } from "@yielded/auth-persistence-drizzle/SqliteBun";

export const proxyAttempts = OAuthProxyPersistence.table("oauth_proxy_attempts");
export const ProxyStorage = OAuthProxyPersistence.layer(proxyAttempts);
```

Export the table to Drizzle Kit and apply the generated migration before providing
`ProxyStorage` to the server. The Layer requires the driver's Effect SQL client.
For an existing table, pass column-key overrides as the second argument to `layer`.
Mapped columns use plain text and integer milliseconds; Drizzle value codecs and
write hooks do not run for these columns.

### App provider

Pass these options to `OAuthProxy.provider` in each app:

| Option        | Value                                                                        |
| ------------- | ---------------------------------------------------------------------------- |
| `url`         | Callback server's HTTPS base, such as `https://auth.example.com/oauth-proxy` |
| `environment` | Registered environment ID                                                    |
| `secret`      | That environment's redacted secret; keep it in server configuration          |
| `issuer`      | Expected provider issuer, such as `https://github.com/login/oauth`           |

The app keeps its normal [auth services](#supply-the-services). Supply an `HttpClient`
without retries, redirects, or cookie middleware.

### Hosting and recovery

When TLS terminates upstream, the trusted reverse proxy must preserve the public
`Host` and replace client-supplied `X-Forwarded-Proto` with `https`. `OAuthProxy.routes`
uses these to check the public origin. Restrict access to the upstream listener
to that proxy. Custom hosts calling
`Server.handle` directly must supply the public HTTPS request URL themselves.

Exclude authorization and callback query strings from logs and traces, including
at reverse proxies. The app checks the initiating browser when sign-in completes;
the callback server sets no browser cookie, and leaked state can consume an attempt.

| Behavior                        | Limit or action                                                                               |
| ------------------------------- | --------------------------------------------------------------------------------------------- |
| Sign-in attempt                 | Expires after five minutes                                                                    |
| Return to the app               | Single-use handoff; expires after sixty seconds or the attempt deadline, whichever is earlier |
| Timeout or lost response        | Start a new sign-in; exchange and redemption are not retried                                  |
| Removed environment or callback | Outstanding flows cannot complete with the new configuration                                  |
| Storage cleanup                 | Delete expired attempts only; retain encryption keys while attempts reference them            |

Persistence operations require standalone commits. Applications own cleanup and
ingress rate limits.

## Providers

| Integration             | Configure                                                                                                         |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------- |
| GitHub sign-in          | [`GitHub.provider`](../guide/github)                                                                              |
| Slack sign-in           | [`Slack.provider`](../guide/slack) with client credentials; no retained API access                                |
| GitHub with API access  | `GitHub.accessProfile({ clientId, scopes })` and `GitHub.provider({ clientId, clientSecret, access: [profile] })` |
| Strava sign-in / access | `Strava.provider({ clientId, clientSecret, access: profile })`; omit `access` for sign-in only                    |
| OIDC                    | [`OpenIdConnect.provider`](../guide/google) with issuer and credentials                                           |
| Plain OAuth             | `OpenIdConnect.provider` with endpoints and an identity decoder                                                   |

`GitHub.accessProfile` defaults to `read:user`, rotating refresh tokens, cohort
revocation, and thirty days of local refresh retention. `Strava.accessProfile`
requires scopes and declares unsupported remote revocation. Its adapter rechecks
athlete identity on refresh and limits response bodies to 1 MiB. Custom Effect HTTP clients must reject redirects and
must not retry token exchanges.

For generic providers, registration `access` supplies `clientRegistrationId`,
`profiles`, `resourceIndicators`, `refreshExpiry`, `revocation`, and optional
`refreshParameters`. Those are explicit provider contracts; no refresh or revocation
behavior is inferred from the sign-in scopes.

For plain OAuth with `OpenIdConnect`, provide `authorizationEndpoint`, `tokenEndpoint`,
`identitySource.url`, and `identitySource.decodeIdentity`. The decoder returns an
Effect containing the stable `subject` and optional profile; its service requirements
remain in the returned Layer type. Set scopes explicitly. Sign-in registrations may
use `additionalParameters` for provider-specific `resource` or `audience` values.
Connected profiles use their declared resources and reject these parameter overrides.

### OpenIdConnect defaults

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
Load secrets with `Config.Redacted`. Invalid settings fail Layer construction with
`OpenIdConnectConfigurationError`.

### Configuration rotation

For shared auth, use `provider({ registrations: [...] })` to retain older entries
with `issuance: "retired"` while flows or connected grants reference them. Assign
a new `configurationGeneration` when settings change and keep one active generation.
Retain old callback paths until their flows expire. When moving a retained permission
profile to another client registration, increase its profile `generation` too; client
exchange counters are independent, and an older profile cannot replace a newer grant.

Earlier GitHub adapters used the issuer `https://github.com`; the current identity
uses `https://github.com/login/oauth`. Old bindings are not reused automatically.
Revoke old grants before upgrading, then register/link and reconnect. Do not rewrite
stored issuers: they are part of identity keys and encrypted context.

## Provider profiles

Verified identity is the provider/issuer/subject tuple. `profile` is optional
metadata: display fields plus bounded `providerData`. It does not authorize account
linking or local roles. Normalized profile display URLs accept only HTTP(S).
Expose only needed fields in claims; still treat profile URLs as untrusted input.

| Consumer                      | Profile access                                                         |
| ----------------------------- | ---------------------------------------------------------------------- |
| Returning shared-auth sign-in | `SessionClaims.resolve({ subjectId, credential, provider, identity })` |
| Shared-auth registration      | Server-side `OAuthRegistrationIntent.profile`                          |

Declare provider schemas with `OAuth.make({ profiles })` or
`OAuth.makeRegistration({ profiles, registration, registrationPolicy })`.
Keys match the provider keys in `Http.make` or your protocol Layer:

```ts
const social = OAuth.make({
  profiles: {
    github: GitHub.GitHubUserProfile,
    google: OpenIdConnect.OidcUserProfile,
    slack: Slack.SlackUserProfile,
    strava: Strava.Athlete,
  },
});
```

The library validates `providerData` against the matching schema before invoking
`SessionClaims.resolve`. Its input is a discriminated union: narrow on `provider`
to read the corresponding `identity.profile?.providerData`. For example,
`provider === "github"` gives typed GitHub fields, including `email` as
`string | null | undefined`. With one declared provider, no narrowing is needed.
The same option works with retained access and `OAuth.makeModule`.

A supplied map rejects undeclared providers or malformed data before session
claims are resolved. Omitting `profiles` preserves the generic JSON object;
consumers can decode it explicitly using the exported profile schemas. Custom
providers use the same map with their own JSON-object schemas requiring no services.
Schemas validate the adapter's projection; they do not add claims, scopes, or requests.

Missing fields remain absent; GitHub nullable values remain null. GitHub's `/user`
email is not asserted verified. Adapters do not fetch additional email or UserInfo
endpoints or retain unknown fields. Connected-grant refresh need not update profiles.

The OIDC adapter also includes Google's `hd` hosted-domain claim in `providerData`
for verified Google ID tokens. Applications can use it to restrict access to a
Google Workspace or Cloud organization. Other issuers' private `hd` claims remain ignored.
Verified Slack ID tokens preserve `https://slack.com/team_id` and
`https://slack.com/user_id`; see [Slack workspace policy](../guide/slack#identity-and-workspace-policy).

Detailed signatures and invariants live beside the
[OAuth source](https://github.com/yielded-dev/auth/tree/main/packages/auth/src/oauth).
