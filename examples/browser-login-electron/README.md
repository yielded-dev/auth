# Browser login in Electron

This app uses the full account workflow in `examples/persistence-sql`: registration,
password login, email verification, recovery, and account switching stay in the
system browser. Electron main owns the native session. The renderer receives
public session data through validated IPC actions, never bearer credentials,
PKCE material, callback URLs, passwords, or private delivery results.

The example imports `handoff` and `nativeSession` from
[`examples/shared/account/browser-login-contract.ts`](../shared/account/browser-login-contract.ts).
The default hosted URL is `http://localhost:4183/login`, client ID `electron`, and
return URL `dev.yielded.auth://callback`. Set `YIELDED_HOSTED_URL` **in the main
process environment** for another compatible backend; packaged Finder launches
do not inherit terminal environment overrides. Native requests add
`x-auth-client: yielded-native` (a public admission marker, not authentication).
Main uses Effect's Node HTTP client without cookies or redirect following. Node's
fetch adds browser fetch metadata that this native transport correctly rejects.

## Run

From the repository root, after `vp install`:

```sh
vp run @yielded/example-persistence-sql#start
vp run @yielded/example-browser-login-electron#package
```

The package command builds a self-contained app for the current platform under
`out/`. The runtime uses Electron's supported version from the root catalog.
If installation skipped Electron's binary lifecycle, packaging downloads the
matching binary itself. An internet connection is needed on the first package.

On macOS, open the generated **Yielded Browser Login.app** in Finder (or use
`open` with its path). Packaging supplies `CFBundleURLTypes`. A development
`electron .` run cannot register this scheme on macOS; browser login fails closed.
The OS may ask for Keychain access. Allow access to the example's own key only
if you intend to run it; production distributions need a stable signing identity.

On Windows, launch the packaged executable. Development also supports
`vp run @yielded/example-browser-login-electron#start`; registration includes the
application path. On Linux, install a `.desktop` entry whose `Exec` invokes the
packaged executable with `%u`, declare
`MimeType=x-scheme-handler/dev.yielded.auth;`, and select that entry using
`xdg-mime default <your-entry>.desktop x-scheme-handler/dev.yielded.auth`.
The adapter checks this registration and requires a supported secret store
(GNOME Keyring or KWallet); it rejects `basic_text` without a plaintext fallback.

## Try the account workflow

1. Start the hosted account app and packaged Electron app. Choose **Sign in with
   browser**. Complete registration or sign in in the browser, then choose
   **Continue to app**. Accept the browser's external-application prompt. Electron
   must show the same display name and email, with no credentials in its UI.
2. Quit and reopen Electron. Its native session must still load. Browser and
   native sessions have separate sign-out authority.
3. Choose **Use another account**. Main first signs out the old native session
   and waits for that result. In the browser, sign out to switch accounts, sign
   in to the second account, and explicitly continue. Electron must show only
   the new account. **Sign out here** must return it to signed out.
4. Start a login, quit Electron before approving it, then approve in the browser.
   The OS relaunches the packaged app. Choose **Resume login** to consume the
   queued callback for the stored attempt. Also check **Cancel login** while
   waiting: it interrupts the waiter and cancels the server attempt.

Use synthetic accounts and the hosted app's local delivery configuration. Do
not send email/SMS as part of this acceptance run. Keep screenshots/transcripts
outside the product repository; redact browser callback URLs and network headers.
Record the build revision, OS/Electron version, steps, and observed account names.

An uncertain exchange is retained as `Exchanging` and cannot be resumed or
cancelled into a new issuance. **Recover saved session** retires the attempt only
when the server's completion receipt matches an independently verified stored
session. Otherwise, ask the backend operator to revoke the possible session, or
confirm its absolute expiry. The attempt's short timeout is not session expiry.
After that reconciliation, quit the app and reset only its development vault at
`<Electron userData>/auth/vault.bin` to retire that local attempt and credentials.
Do not reset the hosted account database or another application's storage.

## Checks and boundaries

```sh
vp run --filter @yielded/auth-electron --filter @yielded/example-browser-login-electron check
vp run @yielded/auth-electron#build
vp run @yielded/example-browser-login-electron#build
```

The local renderer uses a secure custom protocol, sandbox, context isolation,
restricted CSP, blocked navigation/window creation, and sender/main-frame/origin
checks. Effect Atom owns renderer queries and actions; main owns replacement,
cancellation, storage, transport, and the application Scope. No new tests or
separate backend are required to run this example.
