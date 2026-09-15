import { BunHttpServer, BunRuntime, BunServices } from "@effect/platform-bun";
import * as SqliteClient from "@effect/sql-sqlite-bun/SqliteClient";
import { Http, Client } from "@yielded/auth";
import { CompromisedPasswords } from "@yielded/auth/Password";
import { EmailProofDelivery, type ProofDeliveryMessage } from "@yielded/auth/Proofs";
import type { SessionMetadata } from "@yielded/auth/Sessions";
import {
  Clock,
  ConfigProvider,
  Context,
  DateTime,
  Effect,
  FileSystem,
  Layer,
  Redacted,
} from "effect";
import { HttpRouter } from "effect/unstable/http";
import { KeyValueStore } from "effect/unstable/persistence";
import type { Atom } from "effect/unstable/reactivity";
import { AtomRegistry } from "effect/unstable/reactivity";
import { SqlClient } from "effect/unstable/sql";

import { AppAuth } from "../src/auth";
import { makeClient } from "../src/client";
import { AuthApi } from "../src/contract";
import { DatabaseLive, KeysLive } from "../src/data";
import { AuthLive } from "../src/live";
import { makePasskeyBrowser } from "./fixtures/passkey-browser";

const assert: (condition: unknown, message: string) => asserts condition = (condition, message) => {
  if (!condition) throw new Error(message);
};

const assertSameSession = (before: SessionMetadata, after: SessionMetadata | null) => {
  assert(
    after !== null &&
      after.sessionId === before.sessionId &&
      after.securityRevision === before.securityRevision &&
      JSON.stringify(after.assurance) === JSON.stringify(before.assurance) &&
      DateTime.toEpochMillis(after.assurance.authenticatedAt) ===
        DateTime.toEpochMillis(before.assurance.authenticatedAt) &&
      DateTime.toEpochMillis(after.issuedAt) === DateTime.toEpochMillis(before.issuedAt) &&
      DateTime.toEpochMillis(after.expiresAt) === DateTime.toEpochMillis(before.expiresAt) &&
      DateTime.toEpochMillis(after.absoluteExpiresAt) ===
        DateTime.toEpochMillis(before.absoluteExpiresAt),
    "Account update replaced, revoked, extended, or upgraded the original session",
  );
};

const origin = "http://localhost:4181";
const email = "customer@example.invalid";
const password = "indigo42";
const replacement = "violet73";

const program = Effect.gen(function* () {
  const fs = yield* FileSystem.FileSystem;
  const directory = yield* fs.makeTempDirectoryScoped();
  const messages: ProofDeliveryMessage[] = [];
  const cookies = new Map<string, string>();
  const liveClock = yield* Clock.Clock;
  let elapsed = 0;
  const currentTimeMillisUnsafe = () => liveClock.currentTimeMillisUnsafe() + elapsed;

  const currentTimeNanosUnsafe = () =>
    liveClock.currentTimeNanosUnsafe() + BigInt(elapsed) * 1_000_000n;

  const clock = Layer.succeed(Clock.Clock, {
    currentTimeMillisUnsafe,
    currentTimeMillis: Effect.sync(currentTimeMillisUnsafe),
    currentTimeNanosUnsafe,
    currentTimeNanos: Effect.sync(currentTimeNanosUnsafe),
    monotonicTimeNanosUnsafe: () => liveClock.monotonicTimeNanosUnsafe(),
    monotonicTimeNanos: liveClock.monotonicTimeNanos,
    sleep: (duration) => liveClock.sleep(duration),
  });

  const delivery = EmailProofDelivery.layer({ vendorId: "test", idempotencyMillis: 0 }, (message) =>
    Effect.sync(() => {
      messages.push(message);

      return { _tag: "Accepted" } as const;
    }),
  );

  const application = AuthLive.pipe(
    Layer.provide([
      DatabaseLive,
      KeysLive,
      delivery,
      Layer.succeed(CompromisedPasswords, { check: () => Effect.succeed({ _tag: "Allowed" }) }),
    ]),
    Layer.provide(
      Layer.succeed(
        ConfigProvider.ConfigProvider,
        ConfigProvider.fromUnknown({ AUTH_DATA_DIR: directory }),
      ),
    ),
    Layer.provide(BunServices.layer),
  );

  const routes = Http.make(AppAuth, {
    origin,
    cookie: { secure: false, prefix: "managed-example-" },
  })
    .routes()
    .pipe(
      Layer.provide(application),
      Layer.provide(BunHttpServer.layerHttpServices),
      Layer.provideMerge(clock),
    );

  const open = Effect.acquireRelease(
    Effect.sync(() => HttpRouter.toWebHandler(Layer.fresh(routes), { disableLogger: true })),
    (web) => Effect.promise(() => web.dispose()),
  );

  const sql = <A, E, R>(query: Effect.Effect<A, E, R>) =>
    query.pipe(Effect.provide(SqliteClient.layer({ filename: `${directory}/auth.sqlite` })));

  const code = (proofId: string) => {
    const message = messages.find((item) => item.reference.proofId === proofId);

    assert(message !== undefined, "No private email delivery for the issued proof");

    return Redacted.value(message.secret);
  };

  const fetchFor =
    (web: Effect.Success<typeof open>, jar = cookies): typeof globalThis.fetch =>
    async (input, init) => {
      const request = new Request(input, init);
      const headers = new Headers(request.headers);

      headers.set("origin", origin);
      headers.set("cookie", [...jar].map(([name, value]) => `${name}=${value}`).join("; "));
      const response = await web.handler(new Request(request, { headers }));

      for (const header of response.headers.getSetCookie()) {
        const pair = header.split(";", 1)[0];
        const equals = pair.indexOf("=");
        const name = pair.slice(0, equals);
        const value = pair.slice(equals + 1);

        if (value === "") jar.delete(name);
        else jar.set(name, value);
        if (value !== "")
          assert(header.toLowerCase().includes("httponly"), "Auth credential was not HttpOnly");
      }

      return response;
    };

  const api = Effect.fn("test.client")(function* (web: Effect.Success<typeof open>, jar = cookies) {
    const client = Client.make(AuthApi, { baseUrl: origin, fetch: fetchFor(web, jar) });

    return (yield* client.make).auth;
  });

  const initial = yield* Effect.scoped(
    Effect.gen(function* () {
      const call = yield* api(yield* open);

      assert((yield* call.getSession(undefined)) === null, "Fresh database already authenticated");

      const submission = {
        requestId: "first-registration",
        email,
        newPassword: password,
        registration: { displayName: "Ada" },
      };

      const registered = yield* call.register(submission);

      assert(
        registered._tag === "RegistrationAccepted",
        "Registration failed from an empty database",
      );
      yield* call.register({ ...submission, newPassword: replacement });
      yield* call.register({ ...submission, email: "other@example.invalid" });

      const duplicate = yield* call.register({
        ...submission,
        requestId: "another-registration",
        newPassword: replacement,
      });

      assert(
        duplicate._tag === "RegistrationAccepted",
        "Duplicate registration revealed account existence",
      );

      const wrong = yield* call
        .passwordSignIn({
          email,
          password: replacement,
        })
        .pipe(Effect.result);

      const unknown = yield* call
        .passwordSignIn({
          email: "missing@example.invalid",
          password,
        })
        .pipe(Effect.result);

      assert(
        wrong._tag === "Failure" && unknown._tag === "Failure",
        "Registration replay replaced a password or created another account",
      );
      // Opposite SQL/locale ordering must not change which credentials authorize recovery.
      yield* sql(
        Effect.gen(function* () {
          const db = yield* SqlClient.SqlClient;

          yield* db`update customer_auth_passwords set credential_id = 'a-password'`;
          yield* db`update customer_auth_credentials set credential_id = 'a-password'`;
        }),
      );
      const signedIn = yield* call.passwordSignIn({ email, password });

      assert(
        signedIn._tag === "Authenticated" && !signedIn.session.claims.emailVerified,
        "Registration forged email verification",
      );
      const unverifiedCookies = new Map(cookies);
      const before = messages.length;

      yield* call.requestReset({
        email,
        flowId: "unverified-reset",
        requestId: "unverified-reset",
        locale: "en",
      });
      assert(messages.length === before, "An unverified email enabled password recovery");

      // An application insert must roll back if credential storage fails afterward.
      yield* sql(
        Effect.gen(function* () {
          const db = yield* SqlClient.SqlClient;

          yield* db`create trigger reject_password before insert on customer_auth_passwords begin select raise(abort, 'test rejection'); end`;
        }),
      );

      const failed = yield* call
        .register({
          ...submission,
          requestId: "rolled-back",
          email: "rollback@example.invalid",
          registration: { displayName: "Rollback" },
        })
        .pipe(Effect.result);

      assert(failed._tag === "Failure", "Credential write failure was accepted");
      yield* sql(
        Effect.gen(function* () {
          const db = yield* SqlClient.SqlClient;

          yield* db`drop trigger reject_password`;
          const rows = yield* db`select * from customers`;

          assert(rows.length === 1, "Failed or duplicate registration left an orphan customer");

          const receipts =
            yield* db`select * from customer_auth_passwordRegistrations where request_id = 'rolled-back'`;

          assert(receipts.length === 0, "A failed registration left a committed receipt");
        }),
      );

      yield* call.beginEmailAddress({ flowId: "verify-email" });
      const base = { email, flowId: "verify-email", commandId: "verify-email" };

      const challenge = yield* call.requestEmailVerification({
        ...base,
        requestId: "verify-email",
        locale: "en",
      });

      const secret = code(challenge.reference.proofId);

      const wrongCode = yield* call
        .verifyEmailAddress({
          ...base,
          reference: challenge.reference,
          secret: secret === "000000" ? "111111" : "000000",
        })
        .pipe(Effect.result);

      assert(wrongCode._tag === "Failure", "Wrong email code accepted");

      const attempt = yield* call.verifyEmailAddress({
        ...base,
        reference: challenge.reference,
        secret,
      });

      const replay = yield* call
        .verifyEmailAddress({
          ...base,
          reference: challenge.reference,
          secret,
        })
        .pipe(Effect.result);

      assert(replay._tag === "Failure", "Consumed email code replayed");

      const completed = yield* call.completeEmailVerification({
        ...base,
        continuationId: attempt.continuation.continuationId,
      });

      const confirmed = yield* call.getSession(undefined);

      assert(completed.invalidation === undefined, "Confirmation reported session invalidation");
      assertSameSession(signedIn.session, confirmed);
      assert(
        confirmed?.claims.emailVerified,
        "The existing session did not reflect email verification",
      );
      assert(
        [...unverifiedCookies].every(([name, value]) => cookies.get(name) === value),
        "Confirmation changed the session credential",
      );
      assertSameSession(
        signedIn.session,
        yield* (yield* api(yield* open, unverifiedCookies)).getSession(),
      );
      yield* sql(
        Effect.gen(function* () {
          const db = yield* SqlClient.SqlClient;

          yield* db`update customer_auth_credentials set credential_id = 'Z-email' where credential_id in (select credential_id from customer_auth_emailCredentials)`;
          yield* db`update customer_auth_emailCredentials set credential_id = 'Z-email'`;
        }),
      );
      const verified = yield* call.passwordSignIn({ email, password });

      assert(
        verified._tag === "Authenticated" && verified.session.claims.emailVerified,
        "Email verification was not persisted",
      );

      return { subjectId: verified.session.subjectId };
    }),
  );

  // Closing and reopening the real app Layers must preserve the database and keys.
  yield* Effect.scoped(
    Effect.gen(function* () {
      const call = yield* api(yield* open);
      const session = yield* call.getSession(undefined);

      assert(
        session?.subjectId === initial.subjectId && session.claims.displayName === "Ada",
        "Account or session was lost on restart",
      );
      const oldCookies = new Map(cookies);
      const base = { email, flowId: "reset-password" };

      const challenge = yield* call.requestReset({
        ...base,
        requestId: "reset-password",
        locale: "en",
      });

      const secret = code(challenge.reference.proofId);

      const verified = yield* call.verifyReset({
        ...base,
        reference: challenge.reference,
        secret,
      });

      yield* call.completeReset({
        ...base,
        commandId: "reset-password",
        continuationId: verified.continuation.continuationId,
        newPassword: replacement,
      });
      assert(
        (yield* (yield* api(yield* open, oldCookies)).getSession()) === null,
        "Password reset did not revoke old sessions",
      );

      const oldPassword = yield* call.passwordSignIn({ email, password }).pipe(Effect.result);

      assert(oldPassword._tag === "Failure", "Old password still works after recovery");

      const restored = yield* call.passwordSignIn({
        email,
        password: replacement,
      });

      assert(restored._tag === "Authenticated", "New password was not persisted");
      yield* call.signOut(undefined);
      assert((yield* call.getSession(undefined)) === null, "Sign-out left an active session");
      yield* call.passwordSignIn({ email, password: replacement });
      yield* sql(
        Effect.gen(function* () {
          const db = yield* SqlClient.SqlClient;

          yield* db`update customers set enabled = 0, auth_revision = 'disabled' where customer_key = ${initial.subjectId}`;
        }),
      );
      assert((yield* call.getSession(undefined)) === null, "Disabled customer retained a session");
    }),
  );
  // Run the actual UI atoms: registration and notices must survive account transitions.
  yield* Effect.scoped(
    Effect.gen(function* () {
      const jar = new Map<string, string>();
      const options = { baseUrl: origin, fetch: fetchFor(yield* open, jar) };

      const store = Context.get(
        yield* Layer.build(KeyValueStore.layerMemory),
        KeyValueStore.KeyValueStore,
      );

      const storage = Layer.merge(Layer.succeed(KeyValueStore.KeyValueStore, store), clock);

      const openUi = Effect.gen(function* () {
        const ui = makeClient(options, storage);

        const registry = yield* Effect.acquireRelease(
          Effect.sync(() => AtomRegistry.make()),
          (value) => Effect.sync(() => value.dispose()),
        );

        const dispatch = Effect.fn("test.dispatch")(function* <I, A, E>(
          atom: Atom.AtomResultFn<I, A, E>,
          input: I,
        ) {
          yield* AtomRegistry.mount(registry, atom);
          registry.set(atom, input);

          return yield* AtomRegistry.getResult(registry, atom, { suspendOnWaiting: true }).pipe(
            Effect.timeout("5 seconds"),
          );
        });

        yield* AtomRegistry.mount(registry, ui.auth.session);
        yield* AtomRegistry.mount(registry, ui.notice);
        yield* AtomRegistry.mount(registry, ui.verification);
        yield* AtomRegistry.mount(registry, ui.recovery);
        yield* AtomRegistry.mount(registry, ui.verificationWindow);

        return {
          ui,
          registry,
          dispatch,
          session: AtomRegistry.getResult(registry, ui.auth.session, { suspendOnWaiting: true }),
        };
      });

      const email = "workflow@example.invalid";

      const challenge = yield* Effect.scoped(
        Effect.gen(function* () {
          const { ui, registry, dispatch, session } = yield* openUi;

          assert((yield* session) === null, "Fresh UI was authenticated");
          yield* dispatch(ui.createAccount, { email, password, displayName: "Grace" });
          const challenge = yield* AtomRegistry.getResult(registry, ui.verification);

          assert(challenge !== null, "Sign-in discarded the verification step");
          assert((yield* session)?.claims.displayName === "Grace", "Registration did not sign in");

          return challenge;
        }),
      );

      // Recreate both the client and registry, retaining only tab storage and HttpOnly cookies.
      const { ui, registry, dispatch, session } = yield* openUi;
      const restored = yield* AtomRegistry.getResult(registry, ui.verification);

      assert(
        restored?.reference.proofId === challenge.reference.proofId &&
          restored.flowId === challenge.flowId,
        "Refresh lost the pending verification",
      );
      const before = messages.length;
      const binding = [...jar];

      yield* dispatch(ui.sendVerification, email);
      assert(messages.length === before, "The resend cooldown allowed another delivery");
      assert(
        (yield* AtomRegistry.getResult(registry, ui.verification))?.reference.proofId ===
          challenge.reference.proofId,
        "An early resend replaced the working code reference",
      );
      assert(
        binding.every(([name, value]) => jar.get(name) === value),
        "An early resend replaced a private credential",
      );
      assert(
        registry.get(ui.verificationWindow).resendInSeconds > 0,
        "Refresh lost the resend countdown",
      );
      const unverified = yield* session;

      assert(unverified !== null, "Refresh lost the signed-in account");
      yield* dispatch(ui.verifyEmail, code(challenge.reference.proofId));
      assertSameSession(unverified, yield* session);
      assert(registry.get(ui.notice) === "Email verified.", "Verification notice was lost");
      assert((yield* session)?.claims.emailVerified, "UI did not read the verified email");
      yield* dispatch(ui.signOut, undefined);
      assert((yield* session) === null, "UI sign-out did not clear the session");
      assert(registry.get(ui.notice) === "You have signed out.", "Sign-out notice was lost");
      yield* dispatch(ui.requestReset, email);
      const reset = yield* AtomRegistry.getResult(registry, ui.recovery);

      assert(reset !== null, "Reset request did not reach the rendered state");
      yield* dispatch(ui.resetPassword, {
        code: code(reset.reference.proofId),
        password: replacement,
      });
      assert(
        (yield* AtomRegistry.getResult(registry, ui.recovery)) === null,
        "Password reset left the old challenge",
      );
      assert(registry.get(ui.notice)?.startsWith("Password updated."), "Reset notice was lost");
      yield* dispatch(ui.signIn, { login: email, password: replacement });
      assert((yield* session)?.claims.emailVerified, "Recovered UI could not sign in");
      yield* dispatch(ui.signOut, undefined);

      const resendEmail = "resend@example.invalid";

      yield* dispatch(ui.createAccount, { email: resendEmail, password, displayName: "Lin" });
      const original = yield* AtomRegistry.getResult(registry, ui.verification);

      assert(original !== null, "Registration did not begin verification");
      const sent = messages.length;

      elapsed += 31_000;
      yield* dispatch(ui.sendVerification, resendEmail);
      const resent = yield* AtomRegistry.getResult(registry, ui.verification);

      assert(
        resent !== null &&
          resent.reference.proofId !== original.reference.proofId &&
          messages.length === sent + 1,
        "A resend after cooldown did not deliver a new code",
      );
      yield* dispatch(ui.verifyEmail, code(resent.reference.proofId));
      assert(
        registry.get(ui.notice)?.startsWith("Email verified."),
        "The resent code was unusable",
      );
      yield* dispatch(ui.signOut, undefined);

      const confirmationEmail = "confirmation@example.invalid";

      yield* dispatch(ui.createAccount, {
        email: confirmationEmail,
        password,
        displayName: "Rita",
      });
      const originalSession = yield* session;
      const issued = messages.length;

      assert(originalSession !== null, "Registration did not establish a session");
      elapsed += 360_000;

      const wrongTarget = yield* dispatch(ui.sendVerification, "unbound@example.invalid").pipe(
        Effect.result,
      );

      assert(
        wrongTarget._tag === "Failure" && messages.length === issued,
        "Initial confirmation authorized an address other than the registered email",
      );
      yield* dispatch(ui.sendVerification, confirmationEmail);
      const late = yield* AtomRegistry.getResult(registry, ui.verification);

      assertSameSession(originalSession, yield* session);
      assert(
        late !== null && messages.length === issued + 1,
        "An older valid session could not request initial email confirmation",
      );
      const beforeCompletion = messages.length;

      elapsed += 31_000;
      yield* dispatch(ui.verifyEmail, code(late.reference.proofId));
      assertSameSession(originalSession, yield* session);
      assert(
        registry.get(ui.notice) === "Email verified." &&
          (yield* session)?.claims.emailVerified &&
          (yield* AtomRegistry.getResult(registry, ui.verification)) === null &&
          messages.length === beforeCompletion,
        "An older valid session could not complete initial email confirmation",
      );
    }),
  );
  // Enrollment uses an older valid session, without password authentication or session replacement.
  elapsed = -600_000;
  yield* Effect.scoped(
    Effect.gen(function* () {
      const web = yield* open;
      const jar = new Map<string, string>();
      const call = yield* api(web, jar);
      const customerEmail = "passkey@example.invalid";

      yield* call.register({
        requestId: "passkey-customer",
        email: customerEmail,
        newPassword: password,
        registration: { displayName: "Passkey Customer" },
      });
      const signedIn = yield* call.passwordSignIn({ email: customerEmail, password });

      assert(signedIn._tag === "Authenticated", "Passkey customer did not sign in");
      elapsed = 0;
      assert(
        currentTimeMillisUnsafe() -
          DateTime.toEpochMillis(signedIn.session.assurance.authenticatedAt) >=
          600_000,
        "Enrollment fixture did not age the original authentication",
      );

      const authenticator = yield* makePasskeyBrowser(origin);

      const ui = makeClient(
        { baseUrl: origin, fetch: fetchFor(web, jar) },
        KeyValueStore.layerMemory,
        authenticator.layer,
      );

      const registry = yield* Effect.acquireRelease(
        Effect.sync(() => AtomRegistry.make()),
        (value) => Effect.sync(() => value.dispose()),
      );

      const dispatch = Effect.fn("test.passkeyDispatch")(function* <I, A, E>(
        atom: Atom.AtomResultFn<I, A, E>,
        input: I,
      ) {
        yield* AtomRegistry.mount(registry, atom);
        registry.set(atom, input);

        return yield* AtomRegistry.getResult(registry, atom, { suspendOnWaiting: true }).pipe(
          Effect.timeout("5 seconds"),
        );
      });

      yield* AtomRegistry.mount(registry, ui.auth.session);
      yield* AtomRegistry.mount(registry, ui.notice);
      yield* AtomRegistry.mount(registry, ui.passkeys);
      const savedKeys = AtomRegistry.getResult(registry, ui.passkeys, { suspendOnWaiting: true });

      assert((yield* savedKeys).credentials.length === 0, "Fixture already had a passkey");

      authenticator.state.cancel = true;
      const cancelled = yield* dispatch(ui.addPasskey, { name: "Laptop" }).pipe(Effect.result);

      assert(
        cancelled._tag === "Failure" && authenticator.state.registrations === 1,
        "Browser cancellation was not propagated",
      );
      assertSameSession(signedIn.session, yield* call.getSession(undefined));
      assert((yield* savedKeys).credentials.length === 0, "Cancellation added a credential");

      authenticator.state.cancel = false;
      yield* dispatch(ui.addPasskey, { name: "Laptop" });
      const enrolled = yield* savedKeys;

      assert(
        enrolled.credentials.length === 1 && enrolled.credentials[0].name === "Laptop",
        "Passkey was not saved and named",
      );
      assertSameSession(signedIn.session, yield* call.getSession(undefined));
      assert(
        registry.get(ui.notice)?.startsWith("Passkey added."),
        "Enrollment success was not shown",
      );
      const restarted = yield* api(yield* open, jar);

      assertSameSession(signedIn.session, yield* restarted.getSession(undefined));

      const revoked = yield* api(web, new Map(jar));

      yield* dispatch(ui.signOut, undefined);

      const guest = yield* revoked
        .enrollPasskey({
          commandId: "guest-enrollment",
          flowId: "guest-enrollment",
          profileId: "default",
          name: "Guest",
        })
        .pipe(Effect.result);

      assert(guest._tag === "Failure", "Enrollment accepted a revoked session credential");
      yield* dispatch(ui.signInWithPasskey, undefined);
      assert(
        (yield* call.getSession(undefined))?.subjectId === signedIn.session.subjectId,
        "Added passkey could not sign in",
      );
      elapsed = 31 * 24 * 60 * 60 * 1_000;

      const expired = yield* call
        .enrollPasskey({
          commandId: "expired-enrollment",
          flowId: "expired-enrollment",
          profileId: "default",
          name: "Expired",
        })
        .pipe(Effect.result);

      assert(
        expired._tag === "Failure" && (yield* call.getSession(undefined)) === null,
        "Enrollment accepted an expired session",
      );
      elapsed = 0;
    }),
  );
  yield* Effect.log(
    "Managed app: registration, rollback, verification, refresh, resend, session continuity, restart, recovery, session revocation, UI workflows, and passkey enrollment without reauthentication passed.",
  );
});

if (import.meta.main)
  BunRuntime.runMain(program.pipe(Effect.scoped, Effect.provide(BunServices.layer)));
