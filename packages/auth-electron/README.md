# @yielded/auth-electron

Main-process adapters for Yielded Auth browser login. Core owns the handoff,
callback validation, and exchange fence; Electron opens the system browser and
keeps native credentials and the canonical attempt in encrypted local storage.

Install alongside Electron and Effect:

```sh
bun add @yielded/auth-electron@beta @yielded/auth@beta effect
```

Import `BrowserLogin` from `@yielded/auth-electron`, or use the
`@yielded/auth-electron/BrowserLogin` subpath. See the
[runnable account example](../../examples/browser-login-electron) for composition
with the shared core client and a validated IPC boundary.

- Acquire `makeBrowser({ hostedUrl, returnUrl })` synchronously before waiting for
  Electron readiness, under the application's `Scope`. Hold Electron's
  single-instance lock first. `layerBrowser` is available when the host can
  construct its Layer before readiness.
- Supply `layerVault({ path })` after readiness, with Effect `FileSystem` and
  `Path`. Use one writer and a private absolute path per app/backend/client.
- Feed both services to core `BrowserLogin.makeClient` and the same native
  `OperationHttpClient`. Keep all credential-bearing work in main; encode only
  public sessions and sanitized errors for the renderer.

The browser opens only the configured hosted URL plus a canonical `attempt`
parameter. HTTPS is required except for loopback HTTP development. Callback
targets must match exactly. `ephemeral: true` fails: `shell.openExternal` cannot
promise a private browser session. Interruption removes the active waiter; it
cannot close an external browser tab. A bounded startup queue preserves up to
eight valid callback URLs until the client resumes. Each open expires after ten
minutes without deleting the durable attempt.

macOS requires a packaged app declaring the URL scheme in `Info.plist`. Linux
requires a packaged app with an installed `.desktop` handler already selected
as default. Windows supports packaged apps and development registration with
the executable and application paths. Unsupported or unsuccessful registration
fails before opening a browser. There is no embedded-login fallback.

The vault refuses unavailable OS encryption and Linux `basic_text` or unknown
backends. It encrypts the entire schema-encoded record using `safeStorage`,
fsyncs a private temporary file, closes it, atomically renames it, and syncs the
parent directory on POSIX. Windows flushes the replaced file; directory-entry
durability across abrupt power loss depends on the filesystem/OS. These adapters
do not promise exactly-once external effects or protection against a compromised
OS user. Windows DPAPI does not isolate secrets from other apps of the same user.

Corrupt or undecryptable storage fails closed. Never automatically delete it or
reset an `Exchanging` attempt: exchange may already have issued a native session.
Keep the app's signing identity stable for macOS Keychain access. Registration
outlives the application Scope; listeners and waiters do not.

Platform details: [deep links](https://www.electronjs.org/docs/latest/tutorial/launch-app-from-url-in-another-app),
[safeStorage](https://www.electronjs.org/docs/latest/api/safe-storage),
[IPC security](https://www.electronjs.org/docs/latest/tutorial/security).
