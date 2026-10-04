// oxlint-disable-next-line import/extensions -- Noble's public ESM subpath.
import { argon2idAsync } from "@noble/hashes/argon2.js";
import { Effect } from "effect";

import { CryptoUnavailable } from "../Errors";
import type { Argon2 } from "./kdf";

/** Portable asynchronous work yields; it does not move computation off-thread. */
export const argon2: Argon2 = (input) =>
  Effect.tryPromise({
    try: () =>
      argon2idAsync(input.password, input.salt, {
        version: 19,
        m: input.memoryKiB,
        t: input.passes,
        p: input.parallelism,
        dkLen: input.length,
        key: input.secret,
        personalization: input.associatedData,
        maxmem: input.memoryKiB * 1024,
        asyncTick: 10,
      }),
    catch: () => CryptoUnavailable.make({}),
  });
