import { it as effectIt } from "@effect/vitest";
import { AuthSession } from "@yielded/auth/AuthSession";
import { AuthTokenCodec } from "@yielded/auth/AuthTokenCodec";
import { InvalidSession } from "@yielded/auth/Errors";
import { AuthPolicy, defaultAuthPolicy } from "@yielded/auth/Policy";
import { SubjectId } from "@yielded/auth/Schema";
import { Cause, Effect, Exit, Layer, Redacted, Schema } from "effect";
import { describe, expect } from "vite-plus/test";

import { layerCryptoDeterministic } from "../src/testing/crypto";
import { layerKeyringTest } from "../src/testing/keyring";

const audienceSubject = Schema.decodeSync(SubjectId)("actor-session-audience-regression");

const sessionLayer = (audience: string) =>
  AuthSession.layer.pipe(
    Layer.provide(AuthTokenCodec.layerWebCrypto),
    Layer.provide(layerKeyringTest),
    Layer.provide(layerCryptoDeterministic()),
    Layer.provide(
      Layer.succeed(AuthPolicy)({
        ...defaultAuthPolicy,
        issuer: "kommunikasie",
        audience,
      }),
    ),
    Layer.orDie,
  );

const issue = (audience: string) =>
  Effect.flatMap(AuthSession, (sessions) => sessions.issue(audienceSubject)).pipe(
    Effect.provide(sessionLayer(audience)),
  );

const verify = (token: string, audience: string) =>
  Effect.flatMap(AuthSession, (sessions) => sessions.verify(Redacted.make(token))).pipe(
    Effect.provide(sessionLayer(audience)),
  );

const expectRejected = (outcome: Exit.Exit<unknown, unknown>) => {
  expect(Exit.isFailure(outcome)).toBe(true);

  if (Exit.isFailure(outcome)) {
    expect(Schema.is(InvalidSession)(Cause.squash(outcome.cause))).toBe(true);
  }
};

describe("session audience isolation", () => {
  // Shared keys isolate the audience check from signature rejection.
  effectIt.effect("rejects another audience even when the signing key is shared", () =>
    Effect.gen(function* () {
      const productionAudience = "kommunikasie";
      const previewAAudience = "kommunikasie-preview:pr-101";
      const production = yield* issue(productionAudience);

      expect((yield* verify(production.token, productionAudience)).sub).toBe(audienceSubject);

      expectRejected(yield* Effect.exit(verify(production.token, previewAAudience)));
    }),
  );
});
