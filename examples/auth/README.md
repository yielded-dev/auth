# Authentication examples

Consumer examples compose public `@yielded/auth` exports with application-owned
identity, persistence, and delivery. `getting-started.ts` shows application
composition; `session-contract.ts` and `session-http.ts` show the minimal session
service, cookies, selected routes, and protected HttpApi group. The runnable password, email, phone, session, and proof programs
use local example data.

`auth-contract.ts` owns the shared named API; `auth-server.ts` mounts it beside
application routes. `auth-client.ts` declares the client and its atoms;
`auth-react.ts` uses the application's standard Atom registry and React hooks.
`auth-ssr.ts` shows request-owned server rendering and browser hydration;
the host keeps each Scope alive until its render or mounted application finishes.

Run a declared example through `vp run -F @yielded/example-auth <task>`.
All consumer files are checked by the root validation command. TOTP adapter
fixtures that exercise private implementation helpers live under the library’s
`test/fixtures`, where they remain typechecked.

`login-contract.ts`, `login-server.ts`, and `login-client.ts` compose email OTP +
GitHub with shared sessions, HTTP, and Atom workflows. Google is optional.
See the [OAuth guide](../../docs/src/content/docs/guide/oauth.md) for setup.

For a later clean-start cutover, reset old accounts, auth/session/proof state,
per-account trips/conversations/settings/encrypted API keys, and browser caches.
Retire associated generated sites and build/address records. Allocate new subjects
and storage namespaces; users re-register and re-enter API keys. The consumer
release owns this reset; these examples perform no deletion.
