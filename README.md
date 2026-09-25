# Yielded Auth

Composable authentication, sessions, and identity workflows for Effect.

Yielded Auth owns security-sensitive authentication behavior. Applications provide
identity authority, persistence, protocol verification, and credential delivery.
`@yielded/auth-persistence` supplies direct Effect SQL and shared storage contracts.
`@yielded/auth-persistence-drizzle` supplies Drizzle bindings and migration helpers.
Companion packages provide Cloudflare, OAuth/OIDC, WebAuthn, iOS React Native passkeys,
and maintained cryptography.
Core has only Effect as a runtime peer; applications supply adapter Layers.

Use generated auth tables and migrations, bring your own schema, or replace
individual services. [Choose how much you own](docs/src/content/docs/guide/storage.mdx); four [runnable account apps](docs/src/content/docs/guide/examples.md#run-an-account-app)
show how much control you can take.

For an app using GitHub, [`OAuth.make({ access })`](docs/src/content/docs/guide/oauth.md#sign-in-and-retain-provider-access)
signs users in and retains encrypted provider grants with refresh, through the same
sessions as your other methods. Supply your provider configuration, account policy,
keys, and storage; see the [runnable example](examples/auth/src/github-app.ts).

Install the beta release with Effect:

```sh
bun add @yielded/auth@beta effect
```

Prefer named namespace imports from `@yielded/auth`. Direct module paths such as
`@yielded/auth/AuthContract` remain available; see the
[import guide](docs/src/content/docs/reference/modules.md#imports-and-tree-shaking).

## One API, server and client

Want a working app first? [Download the starter](https://yielded.dev/auth/auth-starter.tar.gz)
and follow the [getting-started guide](docs/src/content/docs/guide/getting-started.md).
It includes registration, password and passkey sign-in, email verification, recovery,
and SQLite storage. Local email delivery needs no provider credentials.

Define the shared contract in `auth-contract.ts`:

<!-- #region auth-contract -->

```ts [auth-contract.ts]
import { Schema } from "effect";
import { AuthContract } from "@yielded/auth";

export const AuthApi = AuthContract.make("app/Auth", {
  claims: Schema.Struct({ displayName: Schema.String }),
  actions: (sessions) => ({ signIn: AuthContract.passwordSignIn(sessions) }),
});
```

<!-- #endregion auth-contract -->

Bind the server implementation and mount its HTTP routes:

<!-- #region auth-server -->

```ts [auth.ts]
import { Auth, Http, Password, Sessions } from "@yielded/auth";

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
[router composition](docs/src/content/docs/guide/http-and-client.md#configure-the-server).
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
import { Atom as AuthAtom, Client } from "@yielded/auth";

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
[getting-started guide](docs/src/content/docs/guide/getting-started.md) and
[HTTP and client guide](docs/src/content/docs/guide/http-and-client.md) show the full composition.

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
