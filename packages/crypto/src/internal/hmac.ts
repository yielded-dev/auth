import { Effect, Redacted, Schema } from "effect";

import { Hmac, Input, VerifyInput } from "../Hmac";
import { copy, decode, importError, nativeError, withSecret } from "./common";

const keyBytes = Schema.Uint8Array.check(Schema.isMinLength(1));

export const makeHmac = (subtle: SubtleCrypto): Hmac["Service"] =>
  Hmac.of({
    sign: Effect.fnUntraced(function* (input) {
      const value = yield* decode(Input, input, "data");

      yield* decode(keyBytes, Redacted.value(value.key), "key");
      const data = yield* copy(value.data);

      return yield* withSecret(value.key, (material) =>
        Effect.gen(function* () {
          const key = yield* Effect.tryPromise({
            try: () =>
              subtle.importKey("raw", material, { name: "HMAC", hash: value.algorithm }, false, [
                "sign",
              ]),
            catch: importError,
          });

          const result = yield* Effect.tryPromise({
            try: () => subtle.sign("HMAC", key, data),
            catch: nativeError,
          });

          return new Uint8Array(result);
        }),
      );
    }),
    verify: Effect.fnUntraced(function* (input) {
      const value = yield* decode(VerifyInput, input, "data");

      yield* decode(keyBytes, Redacted.value(value.key), "key");
      const data = yield* copy(value.data);
      const tag = yield* copy(value.tag);

      return yield* withSecret(value.key, (material) =>
        Effect.gen(function* () {
          const key = yield* Effect.tryPromise({
            try: () =>
              subtle.importKey("raw", material, { name: "HMAC", hash: value.algorithm }, false, [
                "verify",
              ]),
            catch: importError,
          });

          return yield* Effect.tryPromise({
            try: () => subtle.verify("HMAC", key, tag, data),
            catch: nativeError,
          });
        }),
      );
    }),
  });
