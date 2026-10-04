import { Effect, Redacted, Schema } from "effect";

import { Aead, DecryptInput, EncryptInput } from "../Aead";
import { AuthenticationFailed, type OperationError, UnsupportedAlgorithm } from "../Errors";
import { copy, decode, importError, nativeError, nativeErrorName, withSecret } from "./common";

interface CipherInput {
  readonly key: Uint8Array<ArrayBuffer>;
  readonly nonce: Uint8Array<ArrayBuffer>;
  readonly additionalData: Uint8Array<ArrayBuffer>;
  readonly data: Uint8Array<ArrayBuffer>;
}

export interface XChaCha {
  readonly encrypt: (input: CipherInput) => Effect.Effect<Uint8Array, OperationError>;
  readonly decrypt: (
    input: CipherInput,
  ) => Effect.Effect<Uint8Array, OperationError | AuthenticationFailed>;
}

const keyBytes = Schema.Uint8Array.check(Schema.isBetweenLength(32, 32));

export const makeAead = (subtle: SubtleCrypto, xchacha?: XChaCha): Aead["Service"] =>
  Aead.of({
    encrypt: Effect.fnUntraced(function* (input) {
      const value = yield* decode(EncryptInput, input, "data");
      const nonceLength = value.algorithm === "AES-256-GCM" ? 12 : 24;

      yield* decode(keyBytes, Redacted.value(value.key), "key");
      yield* decode(
        Schema.Uint8Array.check(Schema.isBetweenLength(nonceLength, nonceLength)),
        value.nonce,
        "nonce",
      );
      if (value.algorithm === "XChaCha20-Poly1305" && xchacha === undefined)
        return yield* UnsupportedAlgorithm.make({});
      const nonce = yield* copy(value.nonce);
      const additionalData = yield* copy(value.additionalData ?? new Uint8Array());

      return yield* withSecret(value.key, (key) =>
        withSecret(value.plaintext, (data) => {
          if (value.algorithm === "XChaCha20-Poly1305") {
            return xchacha === undefined
              ? Effect.fail(UnsupportedAlgorithm.make({}))
              : xchacha.encrypt({ key, nonce, additionalData, data });
          }

          return Effect.gen(function* () {
            const imported = yield* Effect.tryPromise({
              try: () => subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]),
              catch: importError,
            });

            const encrypted = yield* Effect.tryPromise({
              try: () =>
                subtle.encrypt(
                  { name: "AES-GCM", iv: nonce, additionalData, tagLength: 128 },
                  imported,
                  data,
                ),
              catch: nativeError,
            });

            return new Uint8Array(encrypted);
          });
        }),
      );
    }),
    decrypt: Effect.fnUntraced(function* (input) {
      const value = yield* decode(DecryptInput, input, "data");
      const nonceLength = value.algorithm === "AES-256-GCM" ? 12 : 24;

      yield* decode(keyBytes, Redacted.value(value.key), "key");
      yield* decode(
        Schema.Uint8Array.check(Schema.isBetweenLength(nonceLength, nonceLength)),
        value.nonce,
        "nonce",
      );
      if (value.algorithm === "XChaCha20-Poly1305" && xchacha === undefined)
        return yield* UnsupportedAlgorithm.make({});
      if (value.ciphertext.length < 16) return yield* AuthenticationFailed.make({});
      const nonce = yield* copy(value.nonce);
      const additionalData = yield* copy(value.additionalData ?? new Uint8Array());
      const data = yield* copy(value.ciphertext);

      const plaintext = yield* withSecret(value.key, (key) => {
        if (value.algorithm === "XChaCha20-Poly1305") {
          return xchacha === undefined
            ? Effect.fail(UnsupportedAlgorithm.make({}))
            : xchacha.decrypt({ key, nonce, additionalData, data });
        }

        return Effect.gen(function* () {
          const imported = yield* Effect.tryPromise({
            try: () => subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]),
            catch: importError,
          });

          const decrypted = yield* Effect.tryPromise({
            try: () =>
              subtle.decrypt(
                { name: "AES-GCM", iv: nonce, additionalData, tagLength: 128 },
                imported,
                data,
              ),
            // WebCrypto specifies OperationError for a rejected GCM tag.
            catch: (cause) =>
              nativeErrorName(cause) === "OperationError"
                ? AuthenticationFailed.make({})
                : nativeError(cause),
          });

          return new Uint8Array(decrypted);
        });
      });

      return Redacted.make(plaintext);
    }),
  });
