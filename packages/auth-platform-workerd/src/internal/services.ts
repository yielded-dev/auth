import {
  KdfAdmission,
  PasswordHashing,
  type PasswordHashingConfig,
  type PasswordConfigurationError,
  type Scrypt,
} from "@yielded/auth/Password";
import * as PasswordScrypt from "@yielded/auth/PasswordScrypt";
import * as Aead from "effect/crypto/Aead";
import * as Digest from "effect/crypto/Digest";
import type * as Kdf from "effect/crypto/Kdf";
import * as Mac from "effect/crypto/Mac";
import * as SecureRandom from "effect/crypto/SecureRandom";
import * as Signature from "effect/crypto/Signature";
import * as FetchHttpClient from "effect/http/FetchHttpClient";
import type * as HttpClient from "effect/http/HttpClient";
import * as Layer from "effect/Layer";

import { makeArgon2 } from "./argon2-wasm";
import module from "./argon2.wasm";
import { makeLayer } from "./kdf";

/** Runtime services for Auth on Cloudflare Workers. Application-owned storage,
 * keys, account policy, delivery, and protocol adapters remain separate.
 */
export type Services =
  | SecureRandom.SecureRandom
  | Digest.Digest
  | Mac.Mac
  | Aead.Aead
  | Signature.Signature
  | HttpClient.HttpClient
  | Kdf.Kdf
  | Scrypt
  | KdfAdmission
  | PasswordHashing;

export interface Options {
  readonly passwordHashing?: PasswordHashingConfig;
  readonly kdfAdmission?: Parameters<typeof KdfAdmission.layer>[0];
}

/** Configure password costs and shared admission through preparation, derivation, and cleanup.
 */
export const layerWith = (options: Options): Layer.Layer<Services, PasswordConfigurationError> => {
  const platform = Layer.mergeAll(
    Digest.layerWebCrypto,
    Mac.layerWebCrypto,
    Aead.layerWebCrypto,
    Signature.layerWebCrypto,
    FetchHttpClient.layer,
    makeLayer(makeArgon2(module)),
    PasswordScrypt.layer,
    KdfAdmission.layer(options.kdfAdmission),
  ).pipe(Layer.provideMerge(SecureRandom.layerWebCrypto));

  return PasswordHashing.layer(options.passwordHashing).pipe(Layer.provideMerge(platform));
};

/** Provide once to the application Layer. Includes entropy/digests, crypto,
 * Argon2id password hashing, bounded KDF admission, and a Fetch HttpClient.
 * Bundle with Wrangler and enable nodejs_compat.
 *
 * Admission is shared within the built Layer's lifetime. To bound concurrent
 * requests in an isolate, retain the built services at that lifetime and supply
 * them to request-scoped auth/database Layers; rebuilding per request creates
 * independent admission services. This is not a distributed rate limiter.
 */
export const layer: Layer.Layer<Services, PasswordConfigurationError> = layerWith({});
