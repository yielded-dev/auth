import type * as Kdf from "effect/crypto/Kdf";
import * as Layer from "effect/Layer";

import type { PasswordHashingConfig } from "./password/configuration";
import { makeArgon2 } from "./password/crypto/argon2-wasm";
import module from "./password/crypto/argon2.wasm";
import { makeLayer } from "./password/crypto/kdf";
import type { PasswordConfigurationError } from "./password/errors";
import * as KdfAdmission from "./password/KdfAdmission";
import { PasswordHashing } from "./password/PasswordHashing";
import type { Scrypt } from "./password/Scrypt";
import * as PasswordScrypt from "./PasswordScrypt";
import * as WorkerdPasswordlessServices from "./WorkerdPasswordlessServices";

/** Runtime services for Auth on Cloudflare Workers. Application-owned storage,
 * keys, account policy, delivery, and protocol adapters remain separate.
 */
export type WorkerdServices =
  | WorkerdPasswordlessServices.WorkerdPasswordlessServices
  | Kdf.Kdf
  | Scrypt
  | KdfAdmission.KdfAdmission
  | PasswordHashing;

export interface Options {
  readonly passwordHashing?: PasswordHashingConfig;
  readonly kdfAdmission?: KdfAdmission.Options;
}

/** Configure password costs and shared admission through preparation, derivation, and cleanup.
 */
export const layerWith = (
  options: Options,
): Layer.Layer<WorkerdServices, PasswordConfigurationError> => {
  const platform = Layer.merge(
    WorkerdPasswordlessServices.layer,
    Layer.mergeAll(
      makeLayer(makeArgon2(module)),
      PasswordScrypt.layer,
      KdfAdmission.layer(options.kdfAdmission),
    ),
  );

  return PasswordHashing.layer(options.passwordHashing).pipe(Layer.provideMerge(platform));
};

/** Provide once to the application Layer. Includes entropy/digests, crypto,
 * Argon2id password hashing, bounded KDF admission, and a Fetch HttpClient.
 * Use WorkerdPasswordlessServices for applications without password hashing.
 * Bundle with Wrangler and enable nodejs_compat. This direct entrypoint is not
 * exported from the browser-safe package root.
 *
 * Admission is shared within the built Layer's lifetime. To bound concurrent
 * requests in an isolate, retain the built services at that lifetime and supply
 * them to request-scoped auth/database Layers; rebuilding per request creates
 * independent admission services. This is not a distributed rate limiter.
 */
export const layer: Layer.Layer<WorkerdServices, PasswordConfigurationError> = layerWith({});
