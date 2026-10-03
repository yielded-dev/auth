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

Custom-scheme callbacks require a packaged app declaring the scheme in `Info.plist`
on macOS, or an installed `.desktop` handler already selected as default on Linux.
Windows supports packaged apps and development registration with the executable
and application paths. Unsupported or unsuccessful registration fails before
opening a browser. Custom-scheme registration does not verify app ownership and
cannot enable automatic browser-session reuse. There is no embedded-login fallback.

HTTPS return URLs use Universal Links on packaged macOS apps only. The adapter
accepts them exclusively from Electron's `continue-activity` event with
`NSUserActivityTypeBrowsingWeb`; command-line arguments and ordinary URL events
cannot complete that flow. It never registers a default HTTPS handler. Windows,
Linux, unpackaged apps, and HTTPS callbacks with a nondefault port fail closed.

For a return URL such as `https://links.example.com/auth/callback`:

- Enable Associated Domains for the app's stable App ID and provisioning profile.
  Sign the main app with `com.apple.developer.associated-domains` containing
  `applinks:links.example.com`, preserving Electron's other required entitlements.
- Serve `https://links.example.com/.well-known/apple-app-site-association` over
  valid HTTPS without redirects. Its `applinks` entry must name the signed app's
  `<Application Identifier Prefix>.<Bundle Identifier>` and the exact callback
  path. Generate it from the server's registered clients as shown in the
  [browser login guide](../../docs/src/content/docs/guide/browser-login.mdx).
- Install the signed app locally; Developer ID apps must launch once before
  macOS fetches their associations. Use the normal signing and notarization
  process for distribution.

Use a callback subdomain distinct from the hosted account page. Safari can keep
same-domain links in the browser, and other browsers may not support Universal
Links. Automatic session reuse does not guarantee automatic app launch: a user
may still need to choose **Open in app**. Keep the HTTPS destination on HTTPS;
never forward its callback code to an unverified custom scheme.

macOS verifies the app/site association when routing the Universal Link. Electron
has no association preflight API; a packaged flag or an application-side AASA fetch
does not establish it. Missing signing or association configuration leaves the
attempt waiting until timeout. The unsigned example remains a custom-scheme flow;
signed Universal Link delivery and relaunch require separate macOS verification.

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
[associated domains](https://developer.apple.com/documentation/xcode/supporting-associated-domains),
[Universal Link routing](https://developer.apple.com/documentation/technotes/tn3155-debugging-universal-links),
[safeStorage](https://www.electronjs.org/docs/latest/api/safe-storage),
[IPC security](https://www.electronjs.org/docs/latest/tutorial/security).
