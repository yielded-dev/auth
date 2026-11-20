import * as Cause from "effect/Cause";
import * as Mac from "effect/crypto/Mac";
import * as Effect from "effect/Effect";
import * as Base64Url from "effect/encoding/Base64Url";
import * as Redacted from "effect/Redacted";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";

import { makeScopedOperation } from "./scoped-operation";
import { withoutObservability } from "./without-observability";

export interface SigningKeyring {
  readonly activeKeyId: string;
  /** At least 32 cryptographically random bytes per key, encoded as base64url. */
  readonly keys: ReadonlyArray<{
    readonly id: string;
    readonly material: Redacted.Redacted<string>;
  }>;
}

export interface SigningCodecOptions<ConfigError, InvalidError, UnavailableError> {
  readonly version: "eas1" | "eac1";
  readonly maximumTokenBytes: number;
  readonly deriveKeyDomain?: string | undefined;
  readonly onConfigError: () => ConfigError;
  readonly onInvalid: () => InvalidError;
  readonly onUnavailable: () => UnavailableError;
  readonly observeFailure?: (
    stage: "crypto" | "payload",
  ) => <A, E, R>(effect: Effect.Effect<A, E, R>) => Effect.Effect<A, E, R>;
}

const keyIdSchema = Schema.String.check(Schema.isPattern(/^[A-Za-z0-9_-]{1,64}$/));

const Keyring = Schema.Struct({
  activeKeyId: keyIdSchema,
  keys: Schema.Array(
    Schema.Struct({ id: keyIdSchema, material: Schema.Redacted(Schema.String) }),
  ).check(Schema.isMinLength(1)),
});

const textEncoder = new TextEncoder();

const identityEffect = <A, E, R>(effect: Effect.Effect<A, E, R>) => effect;

/** Scoped HMAC-SHA256 signing codec shared across session and OAuth server tokens. */
export const makeSigningCodec = Effect.fnUntraced(function* <
  S extends Schema.Top,
  ConfigError,
  InvalidError,
  UnavailableError,
>(
  schema: S,
  configuration: SigningKeyring,
  options: SigningCodecOptions<ConfigError, InvalidError, UnavailableError>,
) {
  const checked = yield* Schema.decodeEffect(Keyring)(configuration, { reportInput: false }).pipe(
    Effect.mapError(() => options.onConfigError()),
  );

  const hmac = yield* Mac.Mac;
  const run = yield* makeScopedOperation(options.onUnavailable);

  const services = (yield* Effect.context<S["DecodingServices"] | S["EncodingServices"]>()).pipe(
    withoutObservability,
  );

  const observe = (stage: "crypto" | "payload") =>
    options.observeFailure === undefined ? identityEffect : options.observeFailure(stage);

  const keys = new Map<string, Mac.Key>();
  const { version, maximumTokenBytes } = options;

  const tokenFormat = Schema.String.check(
    Schema.isPattern(
      version === "eac1"
        ? /^eac1\.[A-Za-z0-9_-]{1,64}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/
        : /^eas1\.[A-Za-z0-9_-]{1,64}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
    ),
  );

  const importKey = (material: Uint8Array) =>
    Mac.key(Mac.hmacSha256, material).pipe(
      observe("crypto"),
      Effect.catchCause((cause) =>
        Effect.failCause(Cause.map(cause, () => options.onConfigError())),
      ),
      Effect.ensuring(Effect.sync(() => material.fill(0))),
    );

  for (const entry of checked.keys) {
    const material = Result.getOrUndefined(Base64Url.decode(Redacted.value(entry.material)));

    if (keys.has(entry.id) || material === undefined || material.length < 32)
      return yield* Effect.fail(options.onConfigError());

    const root = yield* importKey(material);

    const key =
      options.deriveKeyDomain !== undefined
        ? yield* hmac.sign(root, textEncoder.encode(options.deriveKeyDomain)).pipe(
            observe("crypto"),
            Effect.catchCause((cause) =>
              Effect.failCause(Cause.map(cause, () => options.onConfigError())),
            ),
            Effect.flatMap(importKey),
          )
        : root;

    keys.set(entry.id, key);
  }

  const activeKeyId = checked.activeKeyId;
  const activeKey = keys.get(activeKeyId);

  if (activeKey === undefined) return yield* Effect.fail(options.onConfigError());
  const codec = Schema.fromJsonString(Schema.toCodecJson(schema));
  const encodePayload = Schema.encodeEffect(codec);
  const decodePayload = Schema.decodeEffect(codec);

  return {
    encode: Effect.fnUntraced(function* (claims: S["Type"]) {
      const json = yield* encodePayload(claims).pipe(
        Effect.provide(services),
        observe("payload"),
        Effect.catchCause((cause) =>
          Effect.failCause(Cause.map(cause, () => options.onUnavailable())),
        ),
      );

      const message = `${version}.${activeKeyId}.${Base64Url.encode(json)}`;

      const signature = yield* hmac.sign(activeKey, textEncoder.encode(message)).pipe(
        observe("crypto"),
        Effect.catchCause((cause) =>
          Effect.failCause(Cause.map(cause, () => options.onUnavailable())),
        ),
      );

      const token = `${message}.${Base64Url.encode(signature)}`;

      if (token.length > maximumTokenBytes)
        return yield* Effect.fail(options.onUnavailable()).pipe(observe("payload"));

      return Redacted.make(token);
    }, run),
    decode: Effect.fnUntraced(function* (credential: Redacted.Redacted<string>) {
      const token = Redacted.value(credential);

      if (token.length > maximumTokenBytes) return yield* Effect.fail(options.onInvalid());
      yield* Schema.decodeEffect(tokenFormat)(token).pipe(
        Effect.mapError(() => options.onInvalid()),
      );
      const [tokenVersion, keyId, payload, signatureText] = token.split(".");
      const key = keys.get(keyId);
      const signature = Result.getOrUndefined(Base64Url.decode(signatureText));

      if (key === undefined || signature === undefined || signature.length !== 32)
        return yield* Effect.fail(options.onInvalid());

      const valid = yield* hmac
        .verify(key, signature, textEncoder.encode(`${tokenVersion}.${keyId}.${payload}`))
        .pipe(
          observe("crypto"),
          Effect.catchCause((cause) =>
            Effect.failCause(Cause.map(cause, () => options.onUnavailable())),
          ),
        );

      if (!valid) return yield* Effect.fail(options.onInvalid());
      const json = Result.getOrUndefined(Base64Url.decodeString(payload));

      if (json === undefined) return yield* Effect.fail(options.onInvalid());

      return yield* decodePayload(json).pipe(
        Effect.provide(services),
        Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, () => options.onInvalid()))),
      );
    }, run),
  };
});
