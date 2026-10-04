// oxlint-disable-next-line import/extensions -- Noble's public ESM subpath.
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { Effect, Predicate } from "effect";

import { AuthenticationFailed, CryptoUnavailable } from "../Errors";
import type { XChaCha } from "./aead";

export const xchacha: XChaCha = {
  encrypt: ({ key, nonce, additionalData, data }) =>
    Effect.try({
      try: () => xchacha20poly1305(key, nonce, additionalData).encrypt(data),
      catch: () => CryptoUnavailable.make({}),
    }),
  decrypt: ({ key, nonce, additionalData, data }) =>
    Effect.try({
      try: () => xchacha20poly1305(key, nonce, additionalData).decrypt(data),
      // Noble has no tagged authentication error. Match its pinned, fixed marker
      // only; allocation/runtime failures must not become invalid credentials.
      catch: (cause) =>
        Predicate.isError(cause) && cause.message === "invalid tag"
          ? AuthenticationFailed.make({})
          : CryptoUnavailable.make({}),
    }),
};
