import { it as effectIt } from "@effect/vitest";
import { AuthSession } from "@yielded/auth/AuthSession";
import { AuthTokenCodec } from "@yielded/auth/AuthTokenCodec";
import { InvalidSession } from "@yielded/auth/Errors";
import { AuthPolicy, defaultAuthPolicy } from "@yielded/auth/Policy";
import { Email, SubjectId } from "@yielded/auth/Schema";
import { layerCryptoWeb } from "@yielded/auth/WebCrypto";
import { Cause, DateTime, Effect, Exit, Layer, Option, Redacted, Schema } from "effect";
import { describe, expect } from "vite-plus/test";

import { layerCryptoDeterministic } from "../src/testing/crypto";
import { layerKeyringTest } from "../src/testing/keyring";

const extensionSubject = Schema.decodeSync(SubjectId)("opaque-extension-subject");
const email = Schema.decodeSync(Email)("typed-session@example.com");

const AuthSessionLive = AuthSession.layer.pipe(
  Layer.provide(AuthTokenCodec.layer),
  Layer.provide(layerKeyringTest),
  Layer.provide(layerCryptoWeb),
  Layer.orDie,
);

class TestSessionExt extends Schema.Class<TestSessionExt>("effect-auth/test/TestSessionExt")({
  issuedAt: Schema.DateTimeUtcFromString,
}) {}

class TestSession extends AuthSession.WithExt<TestSession>()("effect-auth/test/TestSession", {
  ext: TestSessionExt,
  build: Effect.fn("TestSession.buildExt")(function* () {
    return TestSessionExt.make({ issuedAt: yield* DateTime.now });
  }),
}) {}

class AutomaticTestSessionExt extends Schema.Class<AutomaticTestSessionExt>(
  "effect-auth/test/AutomaticTestSessionExt",
)({
  email: Email,
}) {}

class AutomaticTestSession extends AuthSession.WithExt<AutomaticTestSession>()(
  "effect-auth/test/AutomaticTestSession",
  AutomaticTestSessionExt,
) {}

const TestSessionLive = TestSession.layer.pipe(Layer.provide(AuthSessionLive));
const AutomaticTestSessionLive = AutomaticTestSession.layer.pipe(Layer.provide(AuthSessionLive));

describe("AuthSession app extension", () => {
  effectIt.live("keeps app-defined claims optional and opaque", () =>
    Effect.gen(function* () {
      const sessions = yield* AuthSession;
      const withoutExt = yield* sessions.issue(extensionSubject);

      const withExt = yield* sessions.issue(extensionSubject, {
        ext: { productClaim: "app-owned" },
      });

      const defaultClaims = yield* sessions.verify(Redacted.make(withoutExt.token));
      const extendedClaims = yield* sessions.verify(Redacted.make(withExt.token));

      expect(defaultClaims.ext).toBeUndefined();
      expect(extendedClaims.ext).toEqual({ productClaim: "app-owned" });
    }).pipe(Effect.provide(AuthSessionLive)),
  );

  effectIt.live("derives a typed service that schema-encodes and rollout-decodes extensions", () =>
    Effect.gen(function* () {
      const core = yield* AuthSession;
      const sessions = yield* TestSession;
      const automaticSessions = yield* AutomaticTestSession;

      const issuedAt = yield* Schema.decodeEffect(Schema.DateTimeUtcFromString)(
        "2026-08-13T12:34:56Z",
      );

      const issued = yield* sessions.issue(extensionSubject, TestSessionExt.make({ issuedAt }));
      const rawClaims = yield* core.verify(Redacted.make(issued.token));
      const verified = yield* sessions.verify(Redacted.make(issued.token));

      const issuedFromContext = yield* automaticSessions.issueFromContext({
        subjectId: extensionSubject,
        email,
      });

      const verifiedFromContext = yield* automaticSessions.verify(
        Redacted.make(issuedFromContext.token),
      );

      const legacy = yield* core.issue(extensionSubject);
      const verifiedLegacy = yield* sessions.verify(Redacted.make(legacy.token));

      expect(rawClaims.ext).toEqual({ issuedAt: DateTime.formatIso(issuedAt) });
      expect(Option.map(verified.ext, (ext) => DateTime.formatIso(ext.issuedAt))).toEqual(
        Option.some(DateTime.formatIso(issuedAt)),
      );
      expect(Option.map(verifiedFromContext.ext, (ext) => ext.email)).toEqual(Option.some(email));
      expect(verifiedLegacy.ext).toEqual(Option.none());
    }).pipe(
      Effect.provide(Layer.mergeAll(TestSessionLive, AutomaticTestSessionLive, AuthSessionLive)),
    ),
  );
});

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
  // All three runtimes deliberately share the same signing key in this test.
  // The audience — rather than the preview's additional key isolation — must
  // therefore be what rejects every cross-deployment replay.
  effectIt.effect("rejects production↔preview and preview↔preview token replay", () =>
    Effect.gen(function* () {
      const productionAudience = "kommunikasie";
      const previewAAudience = "kommunikasie-preview:pr-101";
      const previewBAudience = "kommunikasie-preview:pr-202";
      const production = yield* issue(productionAudience);
      const previewA = yield* issue(previewAAudience);

      expect((yield* verify(production.token, productionAudience)).sub).toBe(audienceSubject);
      expect((yield* verify(previewA.token, previewAAudience)).sub).toBe(audienceSubject);

      expectRejected(yield* Effect.exit(verify(production.token, previewAAudience)));
      expectRejected(yield* Effect.exit(verify(previewA.token, productionAudience)));
      expectRejected(yield* Effect.exit(verify(previewA.token, previewBAudience)));
    }),
  );
});
