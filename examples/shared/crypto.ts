import { Password } from "@yielded/auth";
import * as Portable from "@yielded/crypto/Portable";
import * as WebCrypto from "@yielded/crypto/WebCrypto";
import { Layer } from "effect";

// One admission instance protects each complete password operation and its nested
// KDF work. This example host chooses WebCrypto and the portable Argon2id backend.
const admission = Password.PasswordKdfAdmission.layer();

export const CryptoLive = Layer.merge(
  WebCrypto.layerCryptoWeb,
  Portable.layer(globalThis.crypto.subtle).pipe(Layer.provideMerge(admission)),
);
