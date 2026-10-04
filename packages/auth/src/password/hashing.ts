import { Kdf } from "@yielded/crypto/Kdf";
import { Crypto, Effect, Redacted, Schema } from "effect";

import { equalBytes } from "../internal/equalBytes";
import {
  defaultPasswordHashingConfig,
  validatePasswordHashingConfig,
  type PasswordHashingConfig,
} from "./configuration";
import { PasswordHashingUnavailable, PasswordInputInvalid, PasswordKdfBusy } from "./errors";
import { EncodedPasswordHash } from "./models";
import { parsePasswordHash, phcBase64 } from "./password-encoding";
import { PasswordKdfAdmission } from "./PasswordKdfAdmission";

const encoder = new TextEncoder();

export const make = (input: PasswordHashingConfig = defaultPasswordHashingConfig) => {
  const snapshot = { ...input };

  return Effect.gen(function* () {
    const config = yield* validatePasswordHashingConfig(snapshot);
    const admission = yield* PasswordKdfAdmission;
    const kdf = yield* Kdf;
    const crypto = yield* Crypto.Crypto;

    const passwordBytes = Effect.fn("PasswordHashing.passwordBytes")(function* (
      password: Redacted.Redacted<string>,
    ) {
      const value = Redacted.value(password);

      yield* Schema.decodeEffect(
        Schema.String.check(Schema.isMaxLength(config.maximumPasswordBytes)),
      )(value).pipe(Effect.mapError(() => PasswordInputInvalid.make({ reason: "too-long" })));
      const buffer = new Uint8Array(config.maximumPasswordBytes);
      const encoded = encoder.encodeInto(value, buffer);

      if (encoded.read !== value.length) {
        buffer.fill(0);

        return yield* PasswordInputInvalid.make({ reason: "too-long" });
      }

      return buffer.subarray(0, encoded.written);
    });

    const derive = (
      password: Uint8Array,
      salt: Uint8Array,
      memoryKiB: number,
      passes: number,
      parallelism: number,
      length: number,
    ) =>
      kdf
        .argon2id({
          password: Redacted.make(password),
          salt,
          memoryKiB,
          passes,
          parallelism,
          length,
        })
        .pipe(
          Effect.map(Redacted.value),
          Effect.mapError((error) =>
            error._tag === "CryptoKdfBusy"
              ? PasswordKdfBusy.make({})
              : PasswordHashingUnavailable.make({}),
          ),
        );

    const withPassword = <A, E, P, E2>(
      password: Redacted.Redacted<string>,
      prepare: Effect.Effect<P, E2>,
      body: (bytes: Uint8Array, prepared: P) => Effect.Effect<A, E>,
      dispose: (prepared: P) => void = () => undefined,
    ) =>
      admission.run(
        Effect.acquireUseRelease(
          prepare,
          (prepared) =>
            Effect.acquireUseRelease(
              passwordBytes(password),
              (bytes) => body(bytes, prepared),
              (bytes) => Effect.sync(() => bytes.fill(0)),
            ),
          (prepared) => Effect.sync(() => dispose(prepared)),
        ),
      );

    return {
      hash: (password: Redacted.Redacted<string>) =>
        withPassword(password, Effect.void, (bytes) =>
          Effect.acquireUseRelease(
            crypto.randomBytes(16).pipe(Effect.mapError(() => PasswordHashingUnavailable.make({}))),
            (salt) =>
              Effect.acquireUseRelease(
                derive(bytes, salt, config.memoryKiB, config.passes, config.parallelism, 32),
                (output) =>
                  Effect.sync(() =>
                    Redacted.make(
                      EncodedPasswordHash.make(
                        `$argon2id$v=19$m=${config.memoryKiB},t=${config.passes},p=${config.parallelism}$${phcBase64(salt)}$${phcBase64(output)}`,
                      ),
                    ),
                  ),
                (output) => Effect.sync(() => output.fill(0)),
              ),
            (salt) => Effect.sync(() => salt.fill(0)),
          ),
        ),
      verify: (
        password: Redacted.Redacted<string>,
        verifier: Redacted.Redacted<EncodedPasswordHash>,
      ) =>
        withPassword(
          password,
          parsePasswordHash(Redacted.value(verifier), config),
          (bytes, parsed) =>
            Effect.gen(function* () {
              const output = yield* parsed._tag === "Argon2id"
                ? derive(
                    bytes,
                    parsed.salt,
                    parsed.memoryKiB,
                    parsed.passes,
                    parsed.parallelism,
                    parsed.expected.length,
                  )
                : kdf
                    .pbkdf2({
                      password: Redacted.make(bytes),
                      salt: parsed.salt,
                      iterations: parsed.iterations,
                      length: 32,
                    })
                    .pipe(
                      Effect.map(Redacted.value),
                      Effect.mapError((error) =>
                        error._tag === "CryptoKdfBusy"
                          ? PasswordKdfBusy.make({})
                          : PasswordHashingUnavailable.make({}),
                      ),
                    );

              try {
                // Maintained fixed-length byte comparison; JavaScript/JIT gives no hard timing guarantee.
                const matches = equalBytes(output, parsed.expected);

                // Parallelism is a scheduling profile, not compensation for weak memory/passes.
                const upgrade =
                  parsed._tag === "LegacyPbkdf2" ||
                  parsed.memoryKiB < config.memoryKiB ||
                  parsed.passes < config.passes ||
                  parsed.salt.length < 16 ||
                  parsed.expected.length < 32;

                return { matches, needsRehash: matches && upgrade };
              } finally {
                output.fill(0);
              }
            }),
          (parsed) => {
            parsed.expected.fill(0);
            parsed.salt.fill(0);
          },
        ),
      dummy: (password: Redacted.Redacted<string>) =>
        withPassword(password, Effect.void, (bytes) =>
          derive(
            bytes,
            new Uint8Array(16),
            config.memoryKiB,
            config.passes,
            config.parallelism,
            32,
          ).pipe(
            Effect.flatMap((output) =>
              Effect.sync(() => {
                output.fill(0);
              }),
            ),
          ),
        ),
    };
  });
};
