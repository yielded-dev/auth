import * as Cause from "effect/Cause";
import * as Context from "effect/Context";
import * as Digest from "effect/crypto/Digest";
import * as SecureRandom from "effect/crypto/SecureRandom";
import * as Effect from "effect/Effect";
import * as Base64Url from "effect/encoding/Base64Url";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";

import { AuthConfig } from "../auth/AuthConfig";
import { defaultLayer } from "../auth/defaults";
import { markAuthFailureReported, reportAuthFailure } from "../internal/diagnostics";
import { makeSigningCodec, type SigningKeyring } from "../internal/signing-codec";
import { TokenDigest } from "../Schema";
import { SessionConfigurationError, SessionInvalid, SessionUnavailable } from "./errors";

export type SessionSigningKeyring = SigningKeyring;

/** Override the application-secret default to manage signing-key IDs and rotation. */
export class SessionSigningKeys extends Context.Service<
  SessionSigningKeys,
  SessionSigningKeyring
>()("effect-auth/sessions/SessionSigningKeys") {
  static readonly layer = Layer.effect(
    SessionSigningKeys,
    Effect.map(AuthConfig, ({ secret }) => ({
      activeKeyId: "default",
      keys: [{ id: "default", material: Redacted.make(Base64Url.encode(Redacted.value(secret))) }],
    })),
  );
}

export const sessionSigningKeysLayer = defaultLayer(
  SessionSigningKeys,
  SessionSigningKeys.layer.pipe(Layer.provide(defaultLayer(AuthConfig, AuthConfig.layer()))),
);

const opaqueCredential = Schema.String.check(Schema.isPattern(/^[A-Za-z0-9_-]{43}$/));

const textEncoder = new TextEncoder();

const digestMessage = Schema.fromJsonString(
  Schema.Struct({
    namespace: Schema.Literal("effect-auth/session"),
    moduleId: Schema.String,
    purpose: Schema.Literals(["bearer", "pending", "step-up", "step-up-binding"]),
    secret: Schema.String,
  }),
);

/** Observe backend failures once before translating them into the finite session port. */
const sessionDiagnostics =
  (stage: "session-crypto" | "session-cache") =>
  <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(
      Effect.catchCause((cause) =>
        reportAuthFailure(stage, cause).pipe(
          Effect.andThen(Effect.failCause(markAuthFailureReported(cause))),
        ),
      ),
    );

export const makeSessionSecrets = Effect.fn("makeSessionSecrets")(function* (moduleId: string) {
  const crypto = yield* SecureRandom.SecureRandom;
  const digests = yield* Digest.Digest;

  return {
    generate: Effect.fn("SessionSecrets.generate")(function* () {
      const bytes = yield* crypto.randomBytes(32).pipe(
        sessionDiagnostics("session-crypto"),
        Effect.catchCause((cause) =>
          Effect.failCause(Cause.map(cause, () => SessionUnavailable.make({}))),
        ),
      );

      return Redacted.make(Base64Url.encode(bytes));
    }),
    digest: Effect.fn("SessionSecrets.digest")(function* (
      token: Redacted.Redacted<string>,
      purpose: "bearer" | "pending" | "step-up" | "step-up-binding",
    ) {
      yield* Schema.decodeEffect(opaqueCredential)(Redacted.value(token)).pipe(
        Effect.mapError(() => SessionInvalid.make({})),
      );

      const message = yield* Schema.encodeEffect(digestMessage)({
        namespace: "effect-auth/session",
        moduleId,
        purpose,
        secret: Redacted.value(token),
      }).pipe(Effect.orDie);

      const digest = yield* digests.digest(Digest.sha256, textEncoder.encode(message)).pipe(
        sessionDiagnostics("session-crypto"),
        Effect.catchCause((cause) =>
          Effect.failCause(Cause.map(cause, () => SessionUnavailable.make({}))),
        ),
      );

      return TokenDigest.make(Base64Url.encode(digest));
    }),
  };
});

/** Scoped key snapshot: retirement is effective only after every runtime installs it. */
export const makeSessionSigningCodec = Effect.fn("makeSessionSigningCodec")(function* <
  S extends Schema.Top,
>(
  schema: S,
  configuration: SessionSigningKeyring,
  maximumTokenBytes: number,
  purpose: "session" | "session-cache" = "session",
) {
  const codec = yield* makeSigningCodec(schema, configuration, {
    version: purpose === "session-cache" ? "eac1" : "eas1",
    maximumTokenBytes,
    ...(purpose === "session-cache" ? { deriveKeyDomain: "effect-auth/session-cache/key/v1" } : {}),
    onConfigError: () => SessionConfigurationError.make({ reason: "keyring" }),
    onInvalid: () => SessionInvalid.make({}),
    onUnavailable: () => SessionUnavailable.make({}),
    observeFailure: (stage) =>
      sessionDiagnostics(
        stage === "payload" && purpose === "session-cache" ? "session-cache" : "session-crypto",
      ),
  });

  return {
    encode: Effect.fn("SessionSigningCodec.encode")(function* (claims: S["Type"]) {
      return yield* codec.encode(claims);
    }),
    decode: Effect.fn("SessionSigningCodec.decode")(function* (
      credential: Redacted.Redacted<string>,
    ) {
      return yield* codec.decode(credential);
    }),
  };
});
