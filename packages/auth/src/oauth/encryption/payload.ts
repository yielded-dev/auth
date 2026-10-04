import { Aead } from "@yielded/crypto/Aead";
import { Crypto, Effect, Redacted, Result, Schema } from "effect";
import { Base64Url } from "effect/encoding";

import { OAuthConfigurationError, OAuthUnavailable } from "../signInErrors";
import { OAuthEncryptionKeyId } from "../signInModels";
import { snapshotOAuthSync } from "../signInSnapshot";
import type { OAuthTransactionKeyring } from "../transactionKeyring";

const keyringSchema = Schema.Struct({
  activeKeyId: OAuthEncryptionKeyId,
  keys: Schema.Array(
    Schema.Struct({
      id: OAuthEncryptionKeyId,
      material: Schema.Redacted(Schema.String.check(Schema.isPattern(/^[A-Za-z0-9_-]{43}$/))),
    }),
  ).check(Schema.isMinLength(1), Schema.isMaxLength(8)),
});

const encoder = new TextEncoder();
const fail = () => OAuthUnavailable.make({});

export const decodeBase64 = (value: string, maximum: number, exact?: number) => {
  if (
    value.length > Math.ceil((maximum * 4) / 3) ||
    value.length % 4 === 1 ||
    !/^[A-Za-z0-9_-]+$/.test(value)
  )
    throw fail();
  const bytes = Result.getOrUndefined(Base64Url.decode(value));

  if (
    !bytes ||
    bytes.length > maximum ||
    (exact !== undefined && bytes.length !== exact) ||
    Base64Url.encode(bytes) !== value
  ) {
    bytes?.fill(0);
    throw fail();
  }

  return bytes;
};

type Envelope = {
  readonly format: string;
  readonly keyId: string;
  readonly nonce: string;
  readonly ciphertext: Redacted.Redacted<string>;
};

/** Serialization belongs to Auth; the owned AEAD service sees only bytes. */
export const payloadEncryption = <C, P, S extends Envelope>(
  options: {
    readonly context: Schema.Codec<C, unknown, never, never>;
    readonly plaintext: Schema.Codec<P, unknown, never, never>;
    readonly envelope: Schema.Codec<S, unknown, never, never>;
    readonly format: S["format"];
    readonly maximumPlaintextBytes: number;
    readonly aad: (context: C, keyId: string) => Uint8Array;
    readonly validate: (context: C, plaintext: P) => P;
  },
  keyring: OAuthTransactionKeyring,
) => {
  let captured: typeof keyringSchema.Type | undefined;

  try {
    captured = snapshotOAuthSync(keyringSchema, keyring);
  } catch {
    /* Layer validates. */
  }
  const codec = Schema.fromJsonString(options.plaintext);

  return Effect.gen(function* () {
    if (!captured) return yield* OAuthConfigurationError.make({ reason: "keyring" });
    const configuration = captured;
    const crypto = yield* Crypto.Crypto;
    const aead = yield* Aead;

    const keys = yield* Effect.try({
      try: () => {
        const map = new Map<string, Uint8Array>();

        try {
          for (const entry of configuration.keys) {
            if (map.has(entry.id)) throw fail();
            map.set(entry.id, decodeBase64(Redacted.value(entry.material), 32, 32));
          }
          if (!map.has(configuration.activeKeyId)) throw fail();

          return map;
        } catch (error) {
          for (const bytes of map.values()) bytes.fill(0);
          throw error;
        }
      },
      catch: () => OAuthConfigurationError.make({ reason: "keyring" }),
    });

    yield* Effect.addFinalizer(() =>
      Effect.sync(() => {
        for (const bytes of keys.values()) bytes.fill(0);
        keys.clear();
      }),
    );

    return {
      seal: (context: C, value: P) =>
        Effect.suspend(() => {
          const allocated: Uint8Array[] = [];

          const retain = (bytes: Uint8Array) => {
            allocated.push(bytes);

            return bytes;
          };

          return Effect.gen(function* () {
            const input = yield* Effect.try({
              try: () => {
                const detached = snapshotOAuthSync(options.context, context);

                const plaintext = options.validate(
                  detached,
                  snapshotOAuthSync(options.plaintext, value),
                );

                const bytes = retain(encoder.encode(Schema.encodeSync(codec)(plaintext)));
                const additionalData = retain(options.aad(detached, configuration.activeKeyId));

                if (bytes.length > options.maximumPlaintextBytes) throw fail();
                const key = keys.get(configuration.activeKeyId);

                if (!key) throw fail();

                return { bytes, additionalData, key: Redacted.make(key) };
              },
              catch: fail,
            });

            const nonce = retain(yield* crypto.randomBytes(24).pipe(Effect.mapError(fail)));

            const ciphertext = retain(
              yield* aead
                .encrypt({
                  algorithm: "XChaCha20-Poly1305",
                  key: input.key,
                  nonce,
                  additionalData: input.additionalData,
                  plaintext: Redacted.make(input.bytes),
                })
                .pipe(Effect.mapError(fail)),
            );

            return yield* Effect.try({
              try: () =>
                snapshotOAuthSync(
                  options.envelope,
                  Schema.decodeUnknownSync(Schema.toType(options.envelope))({
                    format: options.format,
                    keyId: configuration.activeKeyId,
                    nonce: Base64Url.encode(nonce),
                    ciphertext: Redacted.make(Base64Url.encode(ciphertext)),
                  }),
                ),
              catch: fail,
            });
          }).pipe(
            Effect.ensuring(
              Effect.sync(() => {
                for (const bytes of allocated) bytes.fill(0);
              }),
            ),
          );
        }),
      open: (context: C, envelope: S) =>
        Effect.suspend(() => {
          const allocated: Uint8Array[] = [];

          const retain = (bytes: Uint8Array) => {
            allocated.push(bytes);

            return bytes;
          };

          return Effect.gen(function* () {
            const input = yield* Effect.try({
              try: () => {
                const detached = snapshotOAuthSync(options.context, context);
                const sealed = snapshotOAuthSync(options.envelope, envelope);
                const key = keys.get(sealed.keyId);

                if (!key) throw fail();

                return {
                  context: detached,
                  key: Redacted.make(key),
                  nonce: retain(decodeBase64(sealed.nonce, 24, 24)),
                  ciphertext: retain(
                    decodeBase64(
                      Redacted.value(sealed.ciphertext),
                      options.maximumPlaintextBytes + 16,
                    ),
                  ),
                  additionalData: retain(options.aad(detached, sealed.keyId)),
                };
              },
              catch: fail,
            });

            const plaintext = retain(
              Redacted.value(
                yield* aead
                  .decrypt({ algorithm: "XChaCha20-Poly1305", ...input })
                  .pipe(Effect.mapError(fail)),
              ),
            );

            return yield* Effect.try({
              try: () => {
                if (plaintext.length > options.maximumPlaintextBytes) throw fail();
                const json = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
                const value = Schema.decodeSync(codec)(json);

                if (Schema.encodeSync(codec)(value) !== json) throw fail();

                return options.validate(input.context, value);
              },
              catch: fail,
            });
          }).pipe(
            Effect.ensuring(
              Effect.sync(() => {
                for (const bytes of allocated) bytes.fill(0);
              }),
            ),
          );
        }),
    };
  });
};
