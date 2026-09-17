---
description: Connect OAuth providers to your auth service and handle sign-in callbacks.
---

# OAuth setup

## Sign in and connect provider access

For a Strava-style application, `OAuthApp` handles one authorization that both
signs the user in and retains provider API access. It mounts sign-in, callback,
session, and sign-out routes, delivers an HttpOnly session cookie, and encrypts
provider tokens. It does not require `Auth.make`, password/passkey services, or a
session repository. MCP authorization servers are a separate concern.

```ts
import { OAuthAppPersistence } from "@yielded/auth-persistence";
import * as OAuthApp from "@yielded/auth/OAuthApp";
import * as Strava from "@yielded/auth/Strava";
import { Layer, Schema } from "effect";
import { FetchHttpClient } from "effect/unstable/http";

const app = OAuthApp.make("strava", {
  claims: Schema.Struct({ role: Schema.Literals(["owner", "member"]) }),
  returnTargets: ["/account"],
});

const live = app
  .layer({
    origin,
    sessionKeys,
    transactionKeys,
    tokenKeys,
    provider: Strava.provider({
      clientId,
      clientSecret,
      scopes: ["activity:read_all"],
    }),
  })
  .pipe(
    Layer.provide(Layer.succeed(app.Accounts, { resolve: resolveAccount })),
    Layer.provide(OAuthAppPersistence.layer),
    Layer.provide(FetchHttpClient.layer),
  );

const routes = app.routes.pipe(Layer.provide(live));
```

`resolveAccount` receives verified provider identity and profile, and returns
`{ subjectId, claims }` as an Effect. The application checks invitations or active
account status here and owns provisioning. Reject with `OAuthRejected`; translate
infrastructure failures to `OAuthUnavailable`. The library never links by email.
The returned claims are the authorization snapshot for this session.

Supply an Effect `SqlClient` to `OAuthAppPersistence.layer` and apply
`OAuthAppPersistence.migration` through your migration system. It creates one
`yielded_oauth_app` table for pending flows and encrypted grants. SQLite, D1, and
PostgreSQL use single-statement conditional transitions. No session rows are
stored. This storage is independent of the broader authentication schema;
applications can also implement the `OAuthApp.Persistence` port themselves.

Each keyring has `{ activeKeyId, keys: [{ id, material }] }`; `material` is a
redacted base64url encoding of 32 random bytes. Supply three distinct keyrings
for sessions, pending transactions, and provider tokens. Retain old session keys
through session expiry, transaction keys through pending-flow completion, and
token keys while any retained connection references them.

For the example above, register `/auth/strava/callback` at your trusted origin
with Strava. Link to `/auth/strava/sign-in` to start. An optional `returnTo` must
exactly match one of `returnTargets`. The callback sets the session cookie and
redirects without putting session credentials in the URL. GET
`/auth/strava/session` returns public session data; POST
`/auth/strava/sign-out` requires the same Origin and clears the browser cookie.
The default flow lifetime is five minutes, exchange timeout thirty seconds,
and session lifetime thirty days; configure their `*Millis` options in `make`.

Session verification is offline: `app.sessionLayer({ origin, sessionKeys })`
supplies `app.Sessions` without a provider, database, or account-policy service.
Call its `verify(redactedCredential)` method in application authentication
middleware. Sessions use Yielded Auth's signed envelope, not JWT serialization.
They have a fixed expiry and no renewal or individual revocation. Signing out,
removing an invitation, changing a role, or disconnecting Strava does not invalidate
an already issued session; choose the session lifetime to match application policy.
Claims are signed but readable; keep credentials and other private data out of them.
Browser application mutations must enforce their own CSRF protection. The library's
session endpoint returns 401 for missing/invalid credentials; auth routes return
400 for a rejected flow and 503 for unavailable dependencies, without error details.

For ingestion, call `app.Service.withAccessToken({ subjectId, grantId }, use)`
inside an Effect. Obtain that connection reference from a verified session or
trusted application storage. `use` receives a redacted token, and the library
refreshes and saves rotated tokens before invoking it. The callback is never
retried. This server-only capability does not itself authenticate arbitrary
caller-supplied connection references. `disconnect(reference)` disables local
provider access; it does not remotely revoke the provider's grant.

Only one callback can claim a flow. Failed or uncertain exchanges require a new
sign-in. Refresh claims are durable across workers. Concurrent callers receive
`OAuthConnectedBusy` while a refresh is within its deadline; a failed, timed-out, or
interrupted refresh cannot be retried with the same credential. A fresh user
authorization can replace that connection. An uncertain storage commit never
authorizes repeating the provider exchange. The adapter retains terminal flow
records and disconnected grant identities; do not delete grant identities or
reset refresh claims as a recovery mechanism.
Applications may prune expired flow records after their deadline; flow IDs must
never be reused. Disconnect blocks subsequent token acquisition, but cannot cancel
application work that already obtained a token.

Strava uses its confidential-client web flow and does not advertise PKCE support.
The library checks a separate browser binding, one-use state, exact callback,
verified athlete identity, and accepted scopes. It uses the token response's
scope receipt when present, otherwise the bound callback receipt. A refresh
rechecks athlete identity; the provider adapter's HttpClient must not install
automatic token-request retries. Provider configuration and grant authority are
isolated per application ID; use one managed owner for each client registration.
The default Strava refresh retention is thirty days from the last successful token
exchange. This is library retention policy, not a Strava token-expiry guarantee.
See [Strava's authorization contract](https://developers.strava.com/docs/authentication/).

For another provider, implement `OAuthApp.Provider`: `configure(callbackUrl)`
returns a permission profile and the public `OAuthConnectedProtocol` service.
The protocol verifies the provider response and returns verified identity, accepted
permissions, token material, and expiry. It must bind the exact configuration and
callback, validate identity on refresh, and perform each token exchange once.
Required services remain in the configure Effect's environment; return configuration
failures through its typed error channel. Application policy still runs through
`Accounts`, independently of the provider adapter. Public results and library spans
do not contain credentials; keep token bodies, callback queries, and cookies out of
application HTTP access logs and custom HttpClient tracing. Effect's server tracer
records query strings, so the runnable example disables server tracing for the
callback using `HttpMiddleware.TracerDisabledWhen` on the outer server Layer.
Apply an equivalent tracing policy when mounting these routes in your server.

The [runnable Strava example](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/strava-app.ts)
uses SQLite and an application-owned athlete allowlist. Set `STRAVA_CLIENT_ID`,
`STRAVA_CLIENT_SECRET`, `STRAVA_ATHLETE_ID`, `SESSION_KEY`,
`OAUTH_TRANSACTION_KEY`, and `OAUTH_TOKEN_KEY`, then run
`vp run @yielded/example-auth#example:strava`. It listens at
`http://localhost:3000`; set `APP_ORIGIN` for your deployment. The example owns
`strava-auth.sqlite`; real applications keep their migrations and data policy.

## Use the shared authentication service

Set up the auth service once, then add [GitHub](./github), [Google](./google), or
[another OAuth/OIDC provider](#other-providers).

## Enable sign-in

Declare the shared actions:

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

Bind your auth service:

```ts [auth.ts]
import { Auth, Sessions } from "@yielded/auth";
import { OAuth } from "@yielded/auth/strategies";
import { AuthApi } from "./auth-contract";

export const AppAuth = Auth.make(AuthApi, {
  sessions: Sessions.stateful(),
  strategies: {
    social: OAuth.make(),
  },
  defaultStrategy: "social",
});
```

Flows default to five minutes; override `policy` when needed.

`OAuth.make` signs in accounts with an existing provider link. To create accounts
during sign-in, use `OAuth.makeRegistration` with your registration schema and
account provisioning service.

## Supply the services

Provide services to the Layer from your provider setup page:

```ts [oauth-live.ts]
import { Layer } from "effect";
import { OAuth } from "@yielded/auth/strategies";

import { AppAuth } from "./auth";
import { AuthDependencies } from "./auth-dependencies";
import { resolveOAuthClaims } from "./auth-accounts";
import { transactionKeys } from "./auth-config";
import { OAuthPersistenceLive } from "./auth-persistence";
import { AuthRoutes } from "./github";

export const OAuthLive = Layer.mergeAll(
  OAuthPersistenceLive,
  Layer.succeed(AppAuth.strategies.social.ClaimsForOAuth, { resolve: resolveOAuthClaims }),
  OAuth.OAuthTransactionProtector.xchacha20poly1305(transactionKeys),
  OAuth.OAuthReturnTargets.exactRoutes(["/account"]),
);

export const Routes = AuthRoutes.pipe(Layer.provide(OAuthLive), Layer.provide(AuthDependencies));
```

The relative imports are your application modules. `OAuthPersistenceLive` supplies
flow storage and account lookup through [the OAuth adapter](../reference/adapters#oauth).
`AuthDependencies` supplies the shared
[session, account, and key configuration](../reference/adapters#compose-the-application-layer).
These services have no automatic defaults. The library supplies the encryption
and return-route helpers; you supply a dedicated encryption keyring and allowed routes.

`Http.layer` wires `AppAuth` and its providers, action handlers, and callbacks.
Merge it with your application route Layers.

## Complete the callback

`Http.layer` serves each callback and completes sign-in. It recovers the flow ID
from the verified HttpOnly binding cookie, validates the provider response, and
redirects to the flow's approved `returnTarget`. No browser callback page is needed.

The default path is `/auth/{provider}/callback`; a custom contract `basePath`
replaces `/auth`. Register the exact URL with the provider. After an uncertain
exchange, start a fresh sign-in instead of retrying the code.

`signIn({ provider, returnTarget })` creates a fresh attempt with server-generated
IDs. It is not automatically retried. The underlying `operations.Begin` accepts
explicit IDs for application-managed flows; supplying IDs does not make it replayable.

## Customize callbacks

Override a path in your HTTP configuration:

```ts
const AuthRoutes = Http.layer(AppAuth, {
  origin,
  oauth: {
    providers,
    callbacks: {
      github: { path: "/login/github/return" },
    },
  },
});

// Callback: https://app.example.com/login/github/return
```

For several destinations, use an array of `{ callbackId, path }` entries. Sign-in
defaults to the provider-named callback, or the only configured callback. Otherwise,
pass `callbackId` to select one. Unknown or ambiguous callbacks are rejected.
Callback paths must be unique.

Use `oauth.respond` to render registration or MFA, or choose a different response.
It receives the schema-encoded public result and `{ flowId, provider, callbackId }`,
and returns an `Effect<Response, OperationHttpError, R>`. Decode the result with
your completion action's success schema. Cookies remain managed by the HTTP adapter.
A provider's callback entry may override `respond`; see the
[registration example](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/login-server.ts).

`oauthCompleteSignIn` identifies the completion action. For a custom action,
set `oauthCallback: true` and retain its single-use replay and private request-binding
mapping. Use `oauth.complete` to select an action when more than one is declared.

For application-owned callback handling, use `GitHub.layer` or `OpenIdClient.layer`
with an explicit `redirectUri` and complete through your protected transport.

For custom HttpApi composition, `Http.make(AppAuth, options)` exposes
`handlers(api)`, `callbackRoutes()`, and middleware. Merge the callback routes
alongside your API and provide `http.layer` to share the configured auth service
and providers. `http.oauth.callbackUrl(provider)` returns the registered URL.

## Use the authenticated provider profile

The protocol result separates the stable provider/issuer/subject identity from
`profile`. The profile includes available `displayName`, `handle`, `avatarUrl`,
`profileUrl`, `email`, and `emailVerified`, plus bounded `providerData` with the
provider's original field names and null values. GitHub names take precedence over
usernames, with a username fallback when the name is empty or absent.

`GitHubUserProfile` from `@yielded/auth/GitHub` covers every documented field in
GitHub's authenticated [`/user` response](https://docs.github.com/en/rest/users/users#get-the-authenticated-user),
including account metadata returned with `read:user`. `OidcUserProfile` from
`@yielded/auth/OpenIdClient` covers the [standard OIDC user claims](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims)
present in a verified ID token. These adapters do not add scopes, fetch email lists
or UserInfo, or retain unknown response fields, tokens, nonce, or protocol secrets
as profile data. Missing profile fields remain absent; GitHub nullable fields remain
null in `providerData`. GitHub's `/user` email is not asserted to be verified.

For returning sign-in, `ClaimsForOAuth.resolve(credential, verified)` receives the
fresh verified profile only after the provider identity matches an active local
credential. Existing resolvers that accept only `credential` continue to work.
Select the public session fields deliberately:

```ts [profile-claims.ts]
import { Effect, Layer } from "effect";

import { AppAuth, accounts } from "./auth";

export const OAuthClaimsLive = Layer.succeed(AppAuth.strategies.social.ClaimsForOAuth, {
  resolve: (credential, verified) =>
    accounts.claims(credential.revision.subjectId).pipe(
      Effect.map((local) => ({
        ...local,
        displayName: verified.profile?.displayName ?? local.displayName,
      })),
    ),
});
```

For first registration, the original profile is retained in the server-side
`OAuthRegistrationIntent.profile` snapshot. Registration authority callbacks and
Drizzle's `encodeSubjectInsert({ intent, registration }, ids)` can read it when
provisioning the local account. The browser's `RegistrationRequired` result contains
only the reference, expiry, and return target; it does not receive or resubmit the
profile. Existing intents without a profile remain valid. No account, credential,
session, or database reset is required.

Provider-specific data can be narrowed with the exported Schema:

```ts
import { GitHubUserProfile } from "@yielded/auth/GitHub";
import { Schema } from "effect";

const decodeGitHubProfile = Schema.decodeUnknownEffect(GitHubUserProfile);
// After checking the trusted identity.provider is "github":
// const github = yield* decodeGitHubProfile(verified.profile?.providerData);
// github.name, github.login, github.bio, github.company, github.plan, ...
```

Profiles are metadata, not local identity, roles, MFA assurance, or permission to
link accounts. A provider's email verification flag does not grant automatic linking.
Profile URLs are not trusted redirect or server-fetch targets. Keep full provider
snapshots out of logs and expose only the fields your application needs in session
claims. Connected-grant metadata also carries the captured profile under its existing
account authorization; refresh does not promise to update that snapshot.

## Combine providers

Add providers to the same HTTP configuration:

```ts
const AuthRoutes = Http.layer(AppAuth, {
  origin,
  oauth: {
    providers: {
      github: GitHub.provider(github),
      google: OpenIdClient.provider(google),
    },
  },
});
```

Each map key names the provider and its default callback. Multiple entries may
use the same issuer with different client registrations.

## Other providers

Use `OpenIdClient.provider` for other OAuth and OpenID Connect hosts. The
[Google example](./google#configure-the-provider) shows an OIDC entry: supply the
issuer and credentials. Discovery verifies the host's capabilities; HTTP supplies
the provider key and callback URL.

For plain OAuth, set `protocol: "oauth"` and provide `authorizationEndpoint`,
`tokenEndpoint`, `identitySource.url`, and `identitySource.decodeIdentity`.
The decoder receives the authenticated profile response and returns an Effect
containing the provider's stable `subject` and optional display profile.
Set any required `scopes` explicitly.

### Defaults and overrides

| Setting                             | Default                        |
| ----------------------------------- | ------------------------------ |
| `callbackId`                        | Provider key, such as `github` |
| `configurationGeneration`           | `1`                            |
| `issuance`                          | `active`                       |
| `timeoutSeconds`                    | `10` (allowed range: 1–30)     |
| Generic `tokenEndpointAuthMethod`   | `client_secret_basic`          |
| OIDC `scopes` / signature algorithm | `["openid"]` / RS256           |
| Plain OAuth `scopes`                | `[]`                           |

Secrets must be redacted; load them with `Config.redacted` or wrap validated server
configuration with `Redacted.make`.

S256 PKCE and response issuer validation are required by default. Set
`responseIssuerMode: "unsupported"` only for hosts without issuer responses;
callback isolation checks still apply. Public clients use explicit
`authentication: { method: "none", publicClient: true }` instead of `clientSecret`.
Invalid settings fail Layer construction with `OpenIdClientConfigurationError`.

## Rotate configuration

When credentials or protocol settings change, assign a new
`configurationGeneration`. Retain the old entry with `issuance: "retired"` until
its outstanding flows expire. Keep exactly one active generation per provider.

Pass the entries in `GitHub.provider({ registrations: [...] })` or
`OpenIdClient.provider({ registrations: [...] })`. The default generation `1`
does not track credential changes automatically. Keep old callback paths mounted
until their flows expire; select a new callback ID when changing a destination.

## Accounts and API access

| Task                                 | API                                           |
| ------------------------------------ | --------------------------------------------- |
| Sign in an existing account          | `OAuth.make`                                  |
| Create an account                    | `OAuth.makeRegistration`                      |
| Link or unlink a login method        | `OAuth.makeAccounts`                          |
| Save a grant for provider API access | `OAuth.makeConnected` / `makeConnectedModule` |

Linking requires an authenticated local account and explicit authorization.
Provider email alone is never permission to merge accounts.

For API access, use `GitHub.layerConnected` or `OpenIdClientConnected.layer` with
explicit permission profiles. Access tokens stay inside
`ConnectedAccess.withAccessToken`; retain retired configurations while grants
reference them. See the [GitHub API example](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/github-oauth-app.ts)
for profiles, token storage, refresh, and revocation. Never retry an uncertain refresh.

### Email and social login

The combined [contract](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/login-contract.ts),
[server](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/login-server.ts), and
[client](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/login-client.ts)
share sessions across email, GitHub, and optional Google sign-in.

On `RegistrationRequired`, submit signup data to `auth.register` with the original
flow ID, returned reference, and a fresh command ID. Start a new sign-in after
`RegistrationAccepted`; handle `ProvisioningPending` through your application.
Bind accounts to the provider/issuer/subject identity. Protect private routes with
`auth.requireSession()`; HTTP middleware only supplies request context.

<details>
<summary>Upgrading from the previous GitHub issuer</summary>

Older adapters used `https://github.com` instead of `https://github.com/login/oauth`.
Start fresh sign-in attempts after upgrading. Pending flows with the old issuer
cannot complete, and old GitHub login bindings are not reused or linked automatically.
Register or explicitly link the corrected identity.

Revoke old connected grants before upgrading, then reconnect. Do not rewrite stored
issuer values: they are part of identity keys and encrypted transaction context.
Other providers, local subjects, and application data do not need a reset.

</details>
