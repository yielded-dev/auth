/* eslint-disable import/extensions -- Noble exposes these package subpaths only with the .js suffix. */
import { equalBytes } from "@noble/ciphers/utils.js";
import { argon2idAsync } from "@noble/hashes/argon2.js";
import { pbkdf2Async } from "@noble/hashes/pbkdf2.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { Context, Crypto, Effect, Layer, Redacted, Schema } from "effect";

import {
  defaultPasswordHashingConfig,
  validatePasswordHashingConfig,
  type PasswordHashingConfig,
} from "./configuration";
import { parsePasswordHash, phcBase64 } from "./encoding";
import {
  PasswordHashingUnavailable,
  PasswordInputInvalid,
  type PasswordKdfBusy,
  type PasswordVerifierInvalid,
} from "./errors";
import { EncodedPasswordHash, type PasswordVerification } from "./models";
import { PasswordKdfAdmission } from "./PasswordKdfAdmission";

const encoder = new TextEncoder();

type HashFailure = PasswordHashingUnavailable | PasswordInputInvalid | PasswordKdfBusy;

/** Byte-preserving KDF capability. Text normalization belongs to trusted credential
 * provenance, never the algorithm identifier. Rehash legacy passwords with mode none.
 * Replacements must retain admission until actual work completion, including native
 * callbacks. Portable async KDFs yield microtasks; they are not off-thread workers.
 */
export class PasswordHashing extends Context.Service<
  PasswordHashing,
  {
    readonly hash: (
      password: Redacted.Redacted<string>,
    ) => Effect.Effect<Redacted.Redacted<EncodedPasswordHash>, HashFailure>;
    readonly verify: (
      password: Redacted.Redacted<string>,
      verifier: Redacted.Redacted<EncodedPasswordHash>,
    ) => Effect.Effect<PasswordVerification, HashFailure | PasswordVerifierInvalid>;
    /** One current-cost derivation, including on the first unknown-identifier attempt. */
    readonly dummy: (password: Redacted.Redacted<string>) => Effect.Effect<void, HashFailure>;
  }
>()("effect-auth/PasswordHashing") {
  static readonly portableLayer = (input: PasswordHashingConfig = defaultPasswordHashingConfig) => {
    const snapshot = { ...input };

    return Layer.effect(
      this,
      Effect.gen(function* () {
        const config = yield* validatePasswordHashingConfig(snapshot);
        const admission = yield* PasswordKdfAdmission;
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
          Effect.tryPromise({
            try: () =>
              argon2idAsync(password, salt, {
                m: memoryKiB,
                t: passes,
                p: parallelism,
                version: 19,
                dkLen: length,
                maxmem: config.maximumMemoryKiB * 1024,
                asyncTick: 10,
              }),
            catch: () => PasswordHashingUnavailable.make({}),
          });

        const withPassword = <A, E, P, E2>(
          password: Redacted.Redacted<string>,
          prepare: Effect.Effect<P, E2>,
          body: (bytes: Uint8Array, prepared: P) => Effect.Effect<A, E>,
        ) =>
          admission.run(
            Effect.gen(function* () {
              const prepared = yield* prepare;
              const bytes = yield* passwordBytes(password);

              return yield* body(bytes, prepared).pipe(
                Effect.ensuring(Effect.sync(() => bytes.fill(0))),
              );
            }),
          );

        return PasswordHashing.of({
          hash: (password) =>
            withPassword(password, Effect.void, (bytes) =>
              Effect.gen(function* () {
                const salt = yield* crypto
                  .randomBytes(16)
                  .pipe(Effect.mapError(() => PasswordHashingUnavailable.make({})));

                const output = yield* derive(
                  bytes,
                  salt,
                  config.memoryKiB,
                  config.passes,
                  config.parallelism,
                  32,
                );

                try {
                  return Redacted.make(
                    EncodedPasswordHash.make(
                      `$argon2id$v=19$m=${config.memoryKiB},t=${config.passes},p=${config.parallelism}$${phcBase64(salt)}$${phcBase64(output)}`,
                    ),
                  );
                } finally {
                  output.fill(0);
                  salt.fill(0);
                }
              }),
            ),
          verify: (password, verifier) =>
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
                    : Effect.tryPromise({
                        try: () =>
                          pbkdf2Async(sha256, bytes, parsed.salt, {
                            c: parsed.iterations,
                            dkLen: 32,
                            asyncTick: 10,
                          }),
                        catch: () => PasswordHashingUnavailable.make({}),
                      });

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
                    parsed.expected.fill(0);
                    parsed.salt.fill(0);
                  }
                }),
            ),
          dummy: (password) =>
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
        });
      }),
    );
  };
}
