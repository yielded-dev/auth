import { Layer } from "effect";

import { makeArgon2 } from "./internal/argon2-wasm";
import module from "./internal/argon2.wasm";
import { makeLayer } from "./internal/layer";
import * as Scrypt from "./internal/scrypt";
import { xchacha } from "./internal/xchacha";
import type { Limits } from "./Kdf";

/** Workers WebCrypto, Wasm Argon2id and native scrypt.
 * Bundle with Wrangler and enable Node.js compatibility.
 */
export const layer = (subtle: SubtleCrypto, limits: Partial<Limits> = {}) =>
  makeLayer(subtle, limits, { argon2: makeArgon2(module), xchacha }).pipe(
    Layer.provide(Scrypt.layer),
  );
