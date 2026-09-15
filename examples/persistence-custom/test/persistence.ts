import { BunRuntime } from "@effect/platform-bun";
import { AuthRequest } from "@yielded/auth/Auth";
import { guest, type AuthCredentialCommand } from "@yielded/auth/Operations";
import type { Redacted } from "effect";
import { Effect, Layer } from "effect";

import { AppAuth } from "./fixtures/password/auth";
import { HashingLive, HashingStats } from "./fixtures/password/hashing";
import {
  Customers,
  PersistenceLive,
  customerId,
  email,
  password,
} from "./fixtures/password/persistence";

const AuthLive = AppAuth.layer.pipe(
  Layer.provideMerge(PersistenceLive),
  Layer.provideMerge(HashingLive),
);

const program = Effect.gen(function* () {
  const auth = yield* AppAuth;
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
    );

  const signIn = () => request(auth.signIn("password", { email, password }));

  const token = () => {
    const command = [...commands]
      .reverse()
      .find((command) => command._tag === "Issue" && command.slot === "session");

    if (command?._tag !== "Issue") throw new Error("No session credential");

    return command.credential;
  };

  const result = yield* signIn();

  if (result._tag !== "Authenticated" || result.session.subjectId !== customerId)
    return yield* Effect.die("Custom persistence did not authenticate");
  const first = token();

  yield* auth.verifySession(first);

  const wrong = yield* request(auth.signIn("password", { email, password: "wrong" })).pipe(
    Effect.result,
  );

  const unknown = yield* request(
    auth.signIn("password", { email: "missing@example.invalid", password }),
  ).pipe(Effect.result);

  if (wrong._tag !== "Failure" || unknown._tag !== "Failure")
    return yield* Effect.die("Invalid password accepted");
  yield* request(auth.signOut(), first);
  const revoked = yield* auth.verifySession(first).pipe(Effect.result);

  if (revoked._tag !== "Failure") return yield* Effect.die("Signed-out session survived");
  yield* signIn();
  const second = token();

  yield* (yield* Customers).disable;
  const disabled = yield* auth.verifySession(second).pipe(Effect.result);

  if (disabled._tag !== "Failure") return yield* Effect.die("Disabled customer retained a session");
  const counts = yield* (yield* HashingStats).read;

  if (counts.hashes === 0 || counts.verifications === 0 || counts.dummies === 0)
    return yield* Effect.die("Custom hashing bypassed");
  yield* Effect.log(
    "Custom services passed password sign-in, rejection, revocation, and customer deactivation without SQL or Drizzle.",
  );
});

if (import.meta.main) BunRuntime.runMain(program.pipe(Effect.provide(AuthLive)));
