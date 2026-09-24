# Drizzle with managed auth storage

A runnable account app: registration, email verification, password and passkey sign-in,
password recovery, and sign-out. Accounts and sessions survive restarts in `.data/auth.sqlite`;
private proof and request-binding keys live in `.data/keys.json`.

Export `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_API_TOKEN`, or copy `.env.example` to
`.env` in this directory and fill them in. `AUTH_EMAIL_FROM` defaults to
`hello@effect-agent.com`; use an address on your configured Cloudflare sending domain.

```sh
vp -C examples/persistence-drizzle-managed run start
```

Open http://localhost:4181 and create an account with an email you can receive.
Enter the emailed code to verify it while staying signed in. Password recovery requires
a verified address. This app accepts passwords from 8 characters; new passwords are screened
with [Pwned Passwords](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange),
sending only five SHA-1 prefix characters with response padding.

Pending verification and reset requests survive a refresh in the same tab. A resend
countdown preserves the current code during the cooldown. Only public flow metadata
is kept in session storage; passwords, codes, and private credentials are never stored there.
Confirming the registered email requires a valid session and the emailed code.
Session reads reload application claims, so verification appears immediately without
extending the session or asking for the password again.

While signed in, use **Add passkey** and follow the browser's
prompt. The saved key appears on your account; after signing out, choose **Sign in with
a passkey**. Use `localhost:4181` consistently: passkeys are bound to that relying party
and allowed origin. Cancellation leaves the account signed in without adding a key.
The existing valid session authorizes enrollment without another password prompt.
Adding a key preserves that session and its original authentication time and assurance.

[Cloudflare Email Sending](https://developers.cloudflare.com/email-service/api/send-emails/rest-api/)
runs server-side over REST. Codes never appear in the app or public auth responses.
Ambiguous sends are not automatically retried. The server binds to loopback.

[Schema](src/schema.ts) maps the application's customer table and selects managed
auth tables. [Drizzle Kit](drizzle.config.ts) reads the exported tables and generates
versioned SQL and snapshots in [drizzle](drizzle). After changing the schema, run:

```sh
vp -C examples/persistence-drizzle-managed run db:generate --name=describe_change
```

Generation compacts JSON snapshots to one line; Git marks them as generated.

Review and commit the generated migration. [MigrationsLive](src/migrations.ts) applies
those files with Drizzle before auth starts, recording them in `__drizzle_migrations`.
Run `vp -C examples/persistence-drizzle-managed run db:migrate` to apply them separately.
Startup never generates or pushes schema changes.

[Layers](src/live.ts) provide subject creation, claims, and [custom hashing](../shared/account/hashing.ts). The library commits customer creation,
identifier binding, password storage, and the registration receipt together. Existing
account registration and exact request replays never overwrite a password.
`Passkey.make()` and `Passkey.makeManagement()` enable the managed passkey tables.
`PasskeyConfig` supplies the relying party to both persistence and the server verifier;
the app supplies session authorization and claims.

`AUTH_DATA_DIR` changes the data directory. Removing `.data` resets this example's
accounts, sessions, proofs, and keys. It does not affect the other examples.

`vp -C examples/persistence-drizzle-managed run test` checks registration rollback
after credential storage fails, through HTTP against a temporary database. It sends no email.

All three SQL examples import the same [AuthApi](../shared/account/contract.ts),
[AppAuth](../shared/account/auth.ts), and [client](../shared/account/email-client.ts).
This app's [live.ts](src/live.ts) supplies its persistence and account Layers.
Hashing, Cloudflare delivery, forms, and Atom workflows also live in
[shared/account](../shared/account).
