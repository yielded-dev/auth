import * as Cause from "effect/Cause";
import * as Mac from "effect/crypto/Mac";
import type * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Base64Url from "effect/encoding/Base64Url";
import * as Exit from "effect/Exit";
import * as Fiber from "effect/Fiber";
import * as Redacted from "effect/Redacted";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";

import { ConfigurationError, InvalidToken, Unavailable, type SigningKeyring } from "./models";

export class ReportedFailure extends Schema.TaggedError<ReportedFailure>()(
  "OAuthServerReportedFailure",
  {},
) {
  override get message() {
    return "OAuth server operation failed";
  }
}

/** Cooperative cancellation still joins the child. Retain cleanup failures that
 * Effect's timeout race can otherwise replace with only the deadline result. */
export const timeoutOrElseWithCause =
  <E2, R2>(options: {
    readonly duration: Duration.Input;
    readonly orElse: () => Effect.Effect<never, E2, R2>;
  }) =>
  <A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, E | E2, R | R2> =>
    Effect.uninterruptibleMask((restore) =>
      Effect.gen(function* () {
        let original: Cause.Cause<E> | undefined;
        let timedOut = false;

        const exit = yield* Effect.exit(
          restore(
            effect.pipe(
              Effect.onExit((exit) =>
                Effect.sync(() => {
                  if (Exit.isFailure(exit) && !Cause.hasInterruptsOnly(exit.cause))
                    original = exit.cause;
                }),
              ),
              Effect.timeoutOrElse({
                duration: options.duration,
                orElse: () =>
                  Effect.suspend(() => {
                    timedOut = true;

                    return options.orElse();
                  }),
              }),
            ),
          ),
        );

        if (Exit.isSuccess(exit)) return exit.value;
        if (!timedOut && !Cause.hasInterruptsOnly(exit.cause)) return yield* exit;

        const missing =
          original?.reasons.filter((reason) => !exit.cause.reasons.includes(reason)) ?? [];

        return yield* Effect.failCause(
          missing.length === 0
            ? exit.cause
            : Cause.fromReasons<E | E2>([...exit.cause.reasons, ...missing]),
        );
      }),
    );

export const timeoutWithCause = (duration: Duration.Input) =>
  timeoutOrElseWithCause({ duration, orElse: () => Effect.fail(new Cause.TimeoutError()) });

/** Capture the factory Scope once and join each operation before returning to its caller. */
const makeScopedOperation = Effect.fnUntraced(function* <Closed>(unavailable: () => Closed) {
  const scope = yield* Effect.scope;

  return <A, E, R>(work: Effect.Effect<A, E, R>): Effect.Effect<A, E | Closed, R> =>
    Effect.suspend(() => {
      let delivered = false;

      return Effect.acquireUseRelease(
        Effect.suspend(() =>
          scope.state._tag === "Closed"
            ? Effect.fail(unavailable())
            : Effect.forkIn(work, scope, { uninterruptible: false }),
        ),
        (fiber) =>
          Effect.uninterruptibleMask((restore) =>
            Effect.gen(function* () {
              const exit = yield* restore(Fiber.await(fiber));

              delivered = true;
              if (
                scope.state._tag === "Closed" &&
                (Exit.isSuccess(exit) || Cause.hasInterruptsOnly(exit.cause))
              )
                return yield* Effect.fail(unavailable());
              if (Exit.isFailure(exit)) return yield* exit;

              return exit.value;
            }),
          ),
        (fiber) =>
          Effect.gen(function* () {
            yield* Fiber.interrupt(fiber);
            const exit = yield* Fiber.await(fiber);

            if (!delivered && Exit.isFailure(exit) && !Cause.hasInterruptsOnly(exit.cause))
              return yield* Effect.failCause(exit.cause);
          }),
      );
    });
});

const keyIdSchema = Schema.String.check(Schema.isPattern(/^[A-Za-z0-9_-]{1,64}$/));

const Keyring = Schema.Struct({
  activeKeyId: keyIdSchema,
  keys: Schema.Array(
    Schema.Struct({ id: keyIdSchema, material: Schema.Redacted(Schema.String) }),
  ).check(Schema.isMinLength(1)),
});

const tokenFormat = Schema.String.check(
  Schema.isPattern(/^eas1\.[A-Za-z0-9_-]{1,64}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/),
);

const textEncoder = new TextEncoder();

/** Scoped HMAC-SHA256 codec for server-issued opaque credentials. */
export const makeSigningCodec = Effect.fnUntraced(function* <
  S extends Schema.Codec<unknown, unknown, never, never>,
>(schema: S, configuration: SigningKeyring, maximumTokenBytes: number) {
  const checked = yield* Schema.decodeEffect(Keyring)(configuration, { reportInput: false }).pipe(
    Effect.mapError(() => ConfigurationError.make({})),
  );

  const hmac = yield* Mac.Mac;
  const run = yield* makeScopedOperation(() => Unavailable.make({}));
  const keys = new Map<string, Mac.Key>();

  for (const entry of checked.keys) {
    const material = Result.getOrUndefined(Base64Url.decode(Redacted.value(entry.material)));

    if (keys.has(entry.id) || material === undefined || material.length < 32)
      return yield* ConfigurationError.make({});

    const key = yield* Mac.key(Mac.hmacSha256, material).pipe(
      Effect.catchCause((cause) =>
        Effect.failCause(Cause.map(cause, () => ConfigurationError.make({}))),
      ),
      Effect.ensuring(Effect.sync(() => material.fill(0))),
    );

    keys.set(entry.id, key);
  }

  const activeKeyId = checked.activeKeyId;
  const activeKey = keys.get(activeKeyId);

  if (activeKey === undefined) return yield* ConfigurationError.make({});
  const codec = Schema.fromJsonString(Schema.toCodecJson(schema));
  const encodePayload = Schema.encodeEffect(codec);
  const decodePayload = Schema.decodeEffect(codec);

  return {
    encode: Effect.fnUntraced(function* (claims: S["Type"]) {
      const json = yield* encodePayload(claims).pipe(
        Effect.catchCause((cause) =>
          Effect.failCause(Cause.map(cause, () => Unavailable.make({}))),
        ),
      );

      const message = `eas1.${activeKeyId}.${Base64Url.encode(json)}`;

      const signature = yield* hmac
        .sign(activeKey, textEncoder.encode(message))
        .pipe(
          Effect.catchCause((cause) =>
            Effect.failCause(Cause.map(cause, () => Unavailable.make({}))),
          ),
        );

      const token = `${message}.${Base64Url.encode(signature)}`;

      if (token.length > maximumTokenBytes) return yield* Unavailable.make({});

      return Redacted.make(token);
    }, run),
    decode: Effect.fnUntraced(function* (credential: Redacted.Redacted<string>) {
      const token = Redacted.value(credential);

      if (token.length > maximumTokenBytes || !Schema.is(tokenFormat)(token))
        return yield* InvalidToken.make({});

      const [version, keyId, payload, signatureText] = token.split(".");
      const key = keys.get(keyId);
      const signature = Result.getOrUndefined(Base64Url.decode(signatureText));

      if (key === undefined || signature === undefined || signature.length !== 32)
        return yield* InvalidToken.make({});

      const valid = yield* hmac
        .verify(key, signature, textEncoder.encode(`${version}.${keyId}.${payload}`))
        .pipe(
          Effect.catchCause((cause) =>
            Effect.failCause(Cause.map(cause, () => Unavailable.make({}))),
          ),
        );

      if (!valid) return yield* InvalidToken.make({});
      const json = Result.getOrUndefined(Base64Url.decodeString(payload));

      if (json === undefined) return yield* InvalidToken.make({});

      return yield* decodePayload(json).pipe(
        Effect.catchCause((cause) =>
          Effect.failCause(Cause.map(cause, () => InvalidToken.make({}))),
        ),
      );
    }, run),
  };
});
