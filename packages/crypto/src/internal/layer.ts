import { Context, Effect, Layer } from "effect";

import { Aead } from "../Aead";
import { Hmac } from "../Hmac";
import { defaultLimits, Kdf, Limits } from "../Kdf";
import { Signature } from "../Signature";
import { makeAead, type XChaCha } from "./aead";
import { decode } from "./common";
import { makeHmac } from "./hmac";
import { type Argon2, makeKdf } from "./kdf";
import { makeSignature } from "./signature";

export const makeLayer = (
  subtle: SubtleCrypto,
  input: Partial<Limits>,
  extensions: { readonly argon2?: Argon2; readonly xchacha?: XChaCha } = {},
) => {
  const snapshot = { ...defaultLimits, ...input };

  return Layer.effectContext(
    Effect.gen(function* () {
      const limits = yield* decode(Limits, snapshot, "parameters");
      const kdf = yield* makeKdf(subtle, limits, extensions.argon2);

      return Context.make(Aead, makeAead(subtle, extensions.xchacha)).pipe(
        Context.add(Hmac, makeHmac(subtle)),
        Context.add(Kdf, kdf),
        Context.add(Signature, makeSignature(subtle)),
      );
    }),
  );
};
