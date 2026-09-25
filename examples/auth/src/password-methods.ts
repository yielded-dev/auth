import { BunRuntime } from "@effect/platform-bun";
import * as PasswordCrypto from "@yielded/auth-crypto/Password";
import { AuthRequest } from "@yielded/auth/Auth";
import { LifecycleHooks } from "@yielded/auth/Hooks";
import { guest, type AuthCredentialCommand } from "@yielded/auth/Operations";
import { CompromisedPasswords, PasswordKdfAdmission } from "@yielded/auth/Password";
import { EmailProofDelivery, type ProofDeliveryMessage } from "@yielded/auth/Proofs";
import { layerWebCrypto } from "@yielded/auth/WebCrypto";
import { DateTime, Effect, Encoding, Layer, Redacted } from "effect";

import {
  makePasswordConsumer,
  passwordAuth,
  sessions,
  sessionPolicy,
} from "./password-method-consumer";

const hashing = PasswordCrypto.layer().pipe(
  Layer.provide(PasswordKdfAdmission.layer()),
  Layer.provide(layerWebCrypto),
);

const base = Layer.mergeAll(layerWebCrypto, LifecycleHooks.empty, hashing);

const screening = Layer.succeed(CompromisedPasswords, {
  // Public local fixture only; production must supply a maintained corpus/checker.
  check: (password) =>
    Effect.succeed(
      Redacted.value(password) === "a commonly guessed password"
        ? { _tag: "Rejected" as const, reason: "common" as const }
        : { _tag: "Allowed" as const },
    ),
});

const program = Effect.gen(function* () {
  const model = yield* makePasswordConsumer;
  const deliveries: ProofDeliveryMessage[] = [];
  const collector: AuthCredentialCommand[] = [];

  const call = {
    credentials: {},
    credentialCommandSink: (commands: readonly AuthCredentialCommand[]) =>
      Effect.sync(() => {
        collector.push(...commands);
      }),
  };

  const strategy = sessions
    .statelessLayer(sessionPolicy, {
      activeKeyId: "example",
      keys: [
        {
          id: "example",
          material: Redacted.make(Encoding.encodeBase64Url(new Uint8Array(32).fill(42))),
        },
      ],
    })
    .pipe(Layer.provide(base));

  const completion = sessions
    .completionLayer()
    .pipe(Layer.provide(Layer.mergeAll(strategy, model.layer)), Layer.provide(base));

  const delivery = EmailProofDelivery.layer(
    { vendorId: "local-fixture", idempotencyMillis: 0 },
    (message) =>
      Effect.sync(() => {
        deliveries.push(message);

        return { _tag: "Accepted" as const };
      }),
  );

  const sessionHandlers = sessions
    .handlersLayer({ maximumAgeMillis: 60_000 })
    .pipe(Layer.provide(Layer.mergeAll(strategy, completion)));

  yield* Effect.gen(function* () {
    const auth = yield* passwordAuth.make;
    const email = "reader@example.invalid";
    const original = "An original manager generated passphrase";
    const changed = "A changed manager generated passphrase";
    const resetPassword = "A recovered manager generated passphrase";

    const registration = yield* auth.register({
      requestId: "register",
      email,
      newPassword: original,
      registration: { team: "staff" },
    });

    if (registration._tag !== "RegistrationAccepted")
      return yield* Effect.die("registration failed");
    // Same public request replay cannot overwrite or expose the original credential.
    yield* auth.register({
      requestId: "register",
      email,
      newPassword: "A different replayed manager passphrase",
      registration: { team: "attacker" },
    });
    const signIn = yield* auth.signIn({ email, password: original });

    if (signIn._tag !== "Authenticated" || signIn.session.claims.team !== "staff")
      return yield* Effect.die("sign in or claims failed");

    const caller = {
      _tag: "Authenticated" as const,
      subjectId: signIn.session.subjectId,
      sessionId: signIn.session.sessionId,
      assurance: signIn.session.assurance,
    };

    const firstToken = collector.find(
      (command) => command._tag === "Issue" && command.slot === "session",
    );

    if (firstToken?._tag !== "Issue") return yield* Effect.die("session collector missing");
    const wrong = yield* auth.signIn({ email, password: "wrong" }).pipe(Effect.result);

    const unknown = yield* auth
      .signIn({ email: "missing@example.invalid", password: "wrong" })
      .pipe(Effect.result);

    if (
      wrong._tag !== "Failure" ||
      unknown._tag !== "Failure" ||
      wrong.failure._tag !== "PasswordRejected" ||
      unknown.failure._tag !== "PasswordRejected"
    )
      return yield* Effect.die("rejection shape differs");

    const changedResult = yield* auth
      .changePassword({
        commandId: "change",
        currentPassword: original,
        newPassword: changed,
      })
      .pipe(Effect.provideService(AuthRequest, { ...call, invocation: caller }));

    if (changedResult.invalidation.existingSessions !== "original-absolute-expiry")
      return yield* Effect.die("stateless window misreported");
    // Pure stateless old credentials retain their original bound, honestly reported above.
    yield* sessions.operations.Verify.invoke(guest, {
      credential: Redacted.value(firstToken.credential),
    });
    const old = yield* auth.signIn({ email, password: original }).pipe(Effect.result);

    if (old._tag !== "Failure") return yield* Effect.die("old password accepted");

    const beforeVerification = yield* auth.requestReset({
      flowId: "not-verified",
      requestId: "not-verified",
      email,
      locale: "en",
    });

    if (!beforeVerification.reference || deliveries.length !== 0)
      return yield* Effect.die("unverified email was used for recovery");
    yield* model.verifyEmailFixture(email); // Independent identifier verifier would own this revision bump.

    const request = yield* auth.requestReset({
      flowId: "reset-flow",
      requestId: "reset-request",
      email,
      locale: "en",
    });

    const delivered = deliveries[0];

    if (!delivered) return yield* Effect.die("reset delivery missing");

    const proof = yield* auth.verifyReset({
      flowId: "reset-flow",
      email,
      reference: request.reference,
      secret: Redacted.value(delivered.secret),
    });

    const continuation = [...collector]
      .reverse()
      .find((command) => command._tag === "Issue" && command.slot === "proof-continuation");

    if (continuation?._tag !== "Issue") return yield* Effect.die("private continuation missing");

    const resetInput = {
      flowId: "reset-flow",
      email,
      commandId: "reset-command",
      newPassword: resetPassword,
      continuationId: proof.continuation.continuationId,
      credential: Redacted.value(continuation.credential),
    };

    yield* auth.completeReset(resetInput);
    const replay = yield* auth.completeReset(resetInput).pipe(Effect.result);

    if (replay._tag !== "Failure") return yield* Effect.die("reset replay accepted");
    const recovered = yield* auth.signIn({ email, password: resetPassword });

    if (recovered._tag !== "Authenticated") return yield* Effect.die("recovery login failed");

    const fresh = {
      ...caller,
      assurance: recovered.session.assurance,
      sessionId: recovered.session.sessionId,
    };

    const asFresh = Effect.provideService(AuthRequest, { ...call, invocation: fresh });

    yield* model.requireMfaFixture(email);
    const mfaLogin = yield* auth.signIn({ email, password: resetPassword }).pipe(Effect.result);

    if (mfaLogin._tag !== "Failure")
      return yield* Effect.die("primary password bypassed MFA without a pending capability");
    yield* model.failNextMutationFixture;

    const mfaChange = {
      commandId: "mfa-change",
      currentPassword: resetPassword,
      newPassword: "Another manager generated passphrase",
      actionProof: "fixture-factor:one-use",
    };

    const failed = yield* auth.changePassword(mfaChange).pipe(asFresh, Effect.result);
    const factorReplay = yield* auth.changePassword(mfaChange).pipe(asFresh, Effect.result);

    if (
      failed._tag !== "Failure" ||
      factorReplay._tag !== "Failure" ||
      factorReplay.failure._tag !== "PasswordActionRequired"
    )
      return yield* Effect.die("failed mutation refunded factor proof");
    // A genuinely fresh independent proof is checked against this call's newly salted intent.
    yield* auth
      .changePassword({
        ...mfaChange,
        commandId: "mfa-change-fresh",
        actionProof: "fixture-factor:fresh",
      })
      .pipe(asFresh);
    const addedSubject = yield* model.addSubjectFixture("external@example.invalid");
    const addedCaller = { ...fresh, subjectId: addedSubject };
    const asAdded = Effect.provideService(AuthRequest, { ...call, invocation: addedCaller });

    yield* auth
      .addPassword({
        commandId: "add",
        newPassword: "A new external account passphrase",
        actionProof: "fixture-factor:add",
      })
      .pipe(asAdded);
    const status = yield* auth.passwordStatus().pipe(asAdded);

    if (!status.hasPassword) return yield* Effect.die("password add failed");
    yield* Effect.log({
      registration: registration._tag,
      claims: recovered.session.claims,
      resetReplay: replay.failure._tag,
      independentFactorReplay: factorReplay.failure._tag,
      invalidation: changedResult.invalidation,
      completedAt: DateTime.toEpochMillis(yield* DateTime.now),
    });
  }).pipe(
    Effect.scoped,
    Effect.provideService(AuthRequest, { ...call, invocation: guest }),
    Effect.provide(
      Layer.mergeAll(sessionHandlers, model.layer, strategy, completion, delivery, screening),
    ),
  );
}).pipe(Effect.provide(base));

BunRuntime.runMain(program);
