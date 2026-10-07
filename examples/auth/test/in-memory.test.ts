import { it } from "@effect/vitest";
import type { Operations } from "@yielded/auth";
import { Auth, Password, Sessions } from "@yielded/auth";
import * as Testing from "@yielded/auth-persistence/Testing";
import * as KdfAdmission from "@yielded/crypto/KdfAdmission";
import * as Portable from "@yielded/crypto/Portable";
import { layerCryptoWeb } from "@yielded/crypto/WebCrypto";
import { Crypto, Effect, Layer, Random, Redacted, Schema } from "effect";
import { TestClock } from "effect/testing";
import { expect } from "vite-plus/test";

// Requested public-import consumer test: exercise the helper through Auth, including
// acquisition isolation and Effect clock expiry, which adapter tests cannot prove.
const App = Auth.make("in-memory-example", {
  claims: Schema.Struct({ role: Schema.Literal("reader") }),
  sessions: Sessions.stateful({ idleTimeout: "10 minutes", maxAge: "1 hour" }),
  strategies: { password: Password.make() },
  defaultStrategy: "password",
});

const options = {
  subjects: [
    {
      subjectId: "reader",
      email: "reader@example.invalid",
      password: Redacted.make("test passphrase"),
    },
  ],
  requirement: Sessions.AuthenticationRequirement.make({
    alternatives: [
      {
        factors: ["knowledge"],
        minimumCredentials: 1,
        userVerified: false,
        phishingResistant: false,
      },
    ],
    maximumAgeMillis: 60_000,
  }),
};

// Deterministic entropy is supplied explicitly; digests and password hashing stay real.
// This seeded randomness is only suitable for tests.
const entropy = Layer.effect(
  Crypto.Crypto,
  Effect.gen(function* () {
    const native = yield* Crypto.Crypto;
    const random = yield* Random.Random;

    return Crypto.make({
      randomBytes: (size) => Uint8Array.from({ length: size }, () => random.nextIntUnsafe() & 255),
      digest: (algorithm, data) => native.digest(algorithm, data),
    });
  }),
).pipe(Layer.provide(layerCryptoWeb));

const hashing = Password.PasswordHashing.layer().pipe(
  Layer.provide(
    Portable.layer(globalThis.crypto.subtle).pipe(Layer.provideMerge(KdfAdmission.layer())),
  ),
);

const memory = Testing.layer(App, options);

const live = App.layer.pipe(
  Layer.provide(
    Layer.succeed(App.strategies.password.SessionClaims, {
      resolve: () => Effect.succeed({ role: "reader" as const }),
    }),
  ),
  Layer.provideMerge(memory),
  Layer.provide(hashing),
  Layer.provide(entropy),
);

it.effect("signs in, rotates, revokes and expires sessions in isolated acquisitions", () =>
  Effect.gen(function* () {
    let credential: Redacted.Redacted<string> | undefined;

    const call = (session?: Redacted.Redacted<string>) => ({
      credentials: session === undefined ? {} : { session },
      credentialCommandSink: (commands: readonly Operations.AuthCredentialCommand[]) =>
        Effect.sync(() => {
          for (const command of commands) {
            if (command._tag === "Issue" && command.slot === "session")
              credential = command.credential;
          }
        }),
    });

    const signIn = { email: "reader@example.invalid", password: "test passphrase" };

    const first = yield* Effect.gen(function* () {
      const auth = yield* App;

      expect((yield* auth.signIn({ ...signIn, password: "wrong" }).pipe(Effect.flip))._tag).toBe(
        "PasswordRejected",
      );
      expect(credential).toBeUndefined();
      const result = yield* auth.signIn(signIn);

      expect(result).toMatchObject({
        _tag: "Authenticated",
        session: { subjectId: "reader", claims: { role: "reader" } },
      });
      expect(result).not.toHaveProperty("credentialCommands");
      const original = credential;

      if (original === undefined) return yield* Effect.die("Missing private session credential");
      expect((yield* auth.verifySession(original)).subjectId).toBe("reader");

      yield* TestClock.adjust("5 minutes");
      yield* auth.renewSession().pipe(Effect.provideService(Auth.AuthRequest, call(original)));
      expect((yield* auth.verifySession(original).pipe(Effect.flip))._tag).toBe("SessionInvalid");
      expect(
        (yield* auth
          .renewSession()
          .pipe(Effect.provideService(Auth.AuthRequest, call(original)), Effect.flip))._tag,
      ).toBe("SessionInvalid");
      const renewed = credential;

      if (renewed === undefined) return yield* Effect.die("Missing renewed credential");
      expect(
        yield* auth.signOut().pipe(Effect.provideService(Auth.AuthRequest, call(renewed))),
      ).toMatchObject({ invalidation: "revoked" });
      expect((yield* auth.verifySession(renewed).pipe(Effect.flip))._tag).toBe("SessionInvalid");

      yield* auth.signIn(signIn);
      if (credential === undefined) return yield* Effect.die("Missing new credential");

      return credential;
    }).pipe(Effect.provideService(Auth.AuthRequest, call()), Effect.provide(live));

    // Reusing the same Layer value in a separate acquisition creates an empty session store.
    yield* Effect.gen(function* () {
      const auth = yield* App;

      expect((yield* auth.verifySession(first).pipe(Effect.flip))._tag).toBe("SessionInvalid");
      yield* auth.signIn(signIn);
      if (credential === undefined) return yield* Effect.die("Missing isolated credential");
      yield* TestClock.adjust("11 minutes");
      expect((yield* auth.verifySession(credential).pipe(Effect.flip))._tag).toBe("SessionInvalid");
    }).pipe(Effect.provideService(Auth.AuthRequest, call()), Effect.provide(live));
  }).pipe(Random.withSeed("in-memory-example")),
);

it.effect("rejects unsupported session modes at acquisition", () => {
  const signed = Auth.make("unsupported-memory-example", {
    claims: Schema.Struct({}),
    sessions: Sessions.stateless(),
    strategies: { password: Password.make() },
  });

  return Effect.gen(function* () {
    const error = yield* Effect.void.pipe(
      Effect.provide(
        Testing.layer(signed, options).pipe(Layer.provide(hashing), Layer.provide(entropy)),
      ),
      Effect.flip,
    );

    expect(error._tag).toBe("PersistenceConfigurationError");
  });
});
