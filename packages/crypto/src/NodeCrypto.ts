import * as crypto from "node:crypto";

import { Effect } from "effect";

import { CryptoUnavailable, UnsupportedAlgorithm } from "./Errors";
import type { Argon2, Argon2Parameters } from "./internal/kdf";
import { makeLayer } from "./internal/layer";
import { xchacha } from "./internal/xchacha";
import type { Limits } from "./Kdf";

const argon2: Argon2 = Effect.fnUntraced(function* (input: Argon2Parameters) {
  // Namespace import keeps this module loadable on Node versions without Argon2.
  if (typeof crypto.argon2 !== "function") return yield* UnsupportedAlgorithm.make({});

  return yield* Effect.tryPromise({
    try: () =>
      new Promise<Uint8Array>((resolve, reject) => {
        crypto.argon2(
          "argon2id",
          {
            message: input.password,
            nonce: input.salt,
            parallelism: input.parallelism,
            memory: input.memoryKiB,
            passes: input.passes,
            tagLength: input.length,
            secret: input.secret,
            associatedData: input.associatedData,
          },
          (error, key) => (error === null ? resolve(key) : reject(error)),
        );
      }),
    catch: () => CryptoUnavailable.make({}),
  });
});

/** Node native WebCrypto/Argon2id with the portable XChaCha20-Poly1305 extension. */
export const layer = (limits: Partial<Limits> = {}) =>
  // Node's declarations include additional key usages absent from lib.dom. The
  // standard operations used here share the WebCrypto ABI; no payload is cast.
  makeLayer(crypto.webcrypto.subtle as SubtleCrypto, limits, { argon2, xchacha });
