import { Effect } from "effect";

import { AuthenticationFailed, CryptoUnavailable, InvalidInput } from "../Errors";
import type { XChaCha } from "./aead";
import { decrypt, encrypt } from "./xchacha-core";

// Counter zero derives the MAC key; payload blocks use the remaining uint32 values.
const maximumPlaintextBytes = 0xffffffff * 64;

export const xchacha: XChaCha = {
  encrypt: ({ key, nonce, additionalData, data }) =>
    data.length > maximumPlaintextBytes
      ? Effect.fail(InvalidInput.make({ reason: "data" }))
      : Effect.try({
          try: () => encrypt(key, nonce, additionalData, data),
          catch: () => CryptoUnavailable.make({}),
        }),
  decrypt: Effect.fnUntraced(function* ({ key, nonce, additionalData, data }) {
    if (data.length - 16 > maximumPlaintextBytes)
      return yield* InvalidInput.make({ reason: "data" });

    const plaintext = yield* Effect.try({
      try: () => decrypt(key, nonce, additionalData, data),
      catch: () => CryptoUnavailable.make({}),
    });

    if (plaintext === undefined) return yield* AuthenticationFailed.make({});

    return plaintext;
  }),
};
