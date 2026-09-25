# Yielded Auth

Composable authentication, sessions, and identity workflows for Effect.

Yielded Auth owns security-sensitive authentication behavior. Applications provide
identity authority, persistence, protocol verification, and credential delivery.
`@yielded/auth-persistence` supplies direct Effect SQL, Drizzle bindings, and opt-in
managed storage. Companion packages provide Cloudflare, OAuth/OIDC, and WebAuthn integrations.

For an app using GitHub, [managed OAuth](docs/guide/oauth.md#sign-in-and-connect-provider-access)
handles sign-in, encrypted provider tokens, refresh, and stateless session cookies
without a session repository. Supply your provider configuration, account policy,
keys, and SQL connection; see the [runnable example](examples/auth/src/github-app.ts).

See the [persistence examples](docs/reference/adapters.md#runnable-examples) for
managed Drizzle, application-owned Drizzle, raw SQL, and custom service implementations.

Install the beta release with Effect v4:

```sh
vp add @yielded/auth@beta effect@4.0.0-rc.117
```

## One API, server and client

Define the shared contract in `auth-contract.ts`:

<!-- #region auth-contract -->

```ts [auth-contract.ts]
import { Schema } from "effect";
import { AuthContract } from "@yielded/auth/contracts";

export const AuthApi = AuthContract.make("app/Auth", {
  claims: Schema.Struct({ displayName: Schema.String }),
  actions: (sessions) => ({ signIn: AuthContract.passwordSignIn(sessions) }),
});
```

<!-- #endregion auth-contract -->

Bind the server implementation and mount its HTTP routes:

<!-- #region auth-server -->

```ts [auth.ts]
import { Auth, Http, Sessions } from "@yielded/auth";
import { Password } from "@yielded/auth/strategies";

import { AuthApi } from "./auth-contract";

export const AppAuth = Auth.make(AuthApi, {
  sessions: Sessions.stateful(),
  strategies: { password: Password.make() },
  defaultStrategy: "password",
});

export const AuthRoutes = Http.layer(AppAuth, { origin: "https://app.example.com" });
```

<!-- #endregion auth-server -->

Supply your persistence and account Layers to `AuthRoutes`, then merge it with
your router. For application routes that call auth, use the middleware shown in the
[router composition](docs/guide/http-and-client.md#configure-the-server).
Inside an existing Effect handler, call the service directly:

<!-- prettier-ignore -->
```ts
const auth = yield* AppAuth;
const result = yield* auth.signIn({ email, password });
```

The request context supplies credentials and cookie delivery. `auth.getSession()`,
`auth.requireSession()`, and `auth.signOut()` use the same boundary. An
`Authenticated` sign-in result contains a session with typed `claims.displayName`.

Create the client and its atoms from the same contract:

<!-- #region auth-client -->

```ts [auth-client.ts]
import * as AuthAtom from "@yielded/auth/Atom";
import * as Client from "@yielded/auth/Client";

import { AuthApi } from "./auth-contract";

export const AppClient = Client.make(AuthApi, { baseUrl: "https://app.example.com" });
export const auth = AuthAtom.make(AppClient);
```

<!-- #endregion auth-client -->

Use the generated `auth.session`, `auth.signIn`, and `auth.signOut` atoms in your
application's Atom registry. Within an Effect using `AppClient`, call the named
client directly:

<!-- prettier-ignore -->
```ts
const client = yield* AppClient;
const result = yield* client.auth.signIn({ email, password });
```

Both calls return Effects; the remote client handles HTTP and schema decoding.
Use `auth.runtime` for client workflows that share the atoms' instance, or provide
`AppClient.layer` at a standalone program boundary. The
[getting-started guide](docs/guide/getting-started.md) and
[HTTP and client guide](docs/guide/http-and-client.md) show the full composition.

Start with the [documentation](https://yielded.dev/auth/) and
[consumer examples](examples/auth). The public library lives in
[`packages/auth`](packages/auth); examples are leaf workspaces.

## Development

Install Bun and Vite+, then run:

```sh
vp install
vp run patch:tsgo
vp run ready
```

The [toolchain guide](docs/TOOLCHAIN.md) covers release setup and contributor rules.
Shared versions live in the root catalog. Formatting, linting, strict TypeScript,
package exports, dependency purity, tests, and builds use Vite+.

## License

[MIT](LICENSE)
