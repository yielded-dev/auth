import { BunRuntime } from "@effect/platform-bun";
import { AuthRequest } from "@yielded/auth/Auth";
import { guest, type AuthCredentialCommand } from "@yielded/auth/Operations";
import { PhoneRequestContext } from "@yielded/auth/PhoneOtp";
import { Effect, Layer, Redacted } from "effect";

import { HashingStats } from "../src/hashing";
import { AppAuth } from "./fixtures/phone/auth";
import { Inbox } from "./fixtures/phone/delivery";
import { AuthLive, disableCustomer } from "./fixtures/phone/live";
import { MigrationsLive } from "./fixtures/phone/migrations";
import { customerId, email, password, phoneNumber } from "./fixtures/phone/seed";

const assert: (condition: unknown, message: string) => asserts condition = (condition, message) => {
  if (!condition) throw new Error(message);
};

const program = Effect.gen(function* () {
  // Reapplying migrations preserves the seeded customer and credentials.
  yield* Effect.scoped(
    Effect.gen(function* () {
      yield* Layer.buildWithScope(Layer.fresh(MigrationsLive), yield* Effect.scope);
    }),
  );
  const auth = yield* AppAuth;
  const inbox = yield* Inbox;
  const commands: AuthCredentialCommand[] = [];

  const request = <A, E, R>(effect: Effect.Effect<A, E, R>, session?: Redacted.Redacted<string>) =>
    effect.pipe(
      Effect.provideService(AuthRequest, {
        invocation: guest,
        credentials: session === undefined ? {} : { session },
        credentialCommandSink: (items) =>
          Effect.sync(() => {
            commands.push(...items);
          }),
      }),
      Effect.provideService(PhoneRequestContext, {
        networkKey: Redacted.make("example/trusted-network"),
      }),
    );

  const token = (slot: "session" | "request-binding") => {
    const found = [...commands]
      .reverse()
      .find((command) => command._tag === "Issue" && command.slot === slot);

    assert(found?._tag === "Issue", `Missing ${slot} credential`);

    return found.credential;
  };

  const signedIn = yield* request(auth.signIn("password", { email, password }));

  assert(
    signedIn._tag === "Authenticated" && signedIn.session.subjectId === customerId,
    "Password sign-in failed",
  );
  const firstSession = token("session");

  assert(
    (yield* auth.verifySession(firstSession)).claims.displayName === "Dan",
    "Customer claims lost",
  );

  const wrongPassword = yield* request(auth.signIn("password", { email, password: "wrong" })).pipe(
    Effect.result,
  );

  const unknownCustomer = yield* request(
    auth.signIn("password", { email: "missing@example.invalid", password }),
  ).pipe(Effect.result);

  assert(
    wrongPassword._tag === "Failure" && unknownCustomer._tag === "Failure",
    "Invalid password accepted",
  );

  const challenge = yield* request(auth.signIn("phone", { phoneNumber }));
  const binding = Redacted.value(token("request-binding"));
  const message = (yield* inbox.messages).find((item) => item.id === challenge.reference.proofId);

  assert(message !== undefined, "SMS not delivered to the private inbox");
  const code = Redacted.value(message.body);

  const completion = {
    flowId: challenge.flowId,
    phoneNumber,
    requestBinding: binding,
    reference: challenge.reference,
    code,
  };

  const wrongCode = yield* request(
    auth.completeSignIn("phone", { ...completion, code: code === "000000" ? "111111" : "000000" }),
  ).pipe(Effect.result);

  assert(wrongCode._tag === "Failure", "Wrong code accepted");
  const phoneSignIn = yield* request(auth.completeSignIn("phone", completion));

  assert(
    phoneSignIn._tag === "Authenticated" && phoneSignIn.session.subjectId === customerId,
    "Phone sign-in failed",
  );
  const phoneSession = token("session");
  const replay = yield* request(auth.completeSignIn("phone", completion)).pipe(Effect.result);

  assert(replay._tag === "Failure", "Consumed code replayed");

  yield* request(auth.signOut(), firstSession);
  const signedOut = yield* auth.verifySession(firstSession).pipe(Effect.result);

  assert(signedOut._tag === "Failure", "Signed-out session remained valid");
  yield* disableCustomer;
  const disabled = yield* auth.verifySession(phoneSession).pipe(Effect.result);

  assert(disabled._tag === "Failure", "Disabled customer retained a session");

  const counts = yield* (yield* HashingStats).read;

  assert(
    counts.hashes > 0 && counts.verifications > 0 && counts.dummies > 0,
    "Custom hashing was bypassed",
  );
  yield* Effect.log(
    "Password and phone sign-in passed; invalid credentials, proof replay, sign-out, and disabled customers checked.",
  );
});

if (import.meta.main) BunRuntime.runMain(program.pipe(Effect.provide(AuthLive)));
