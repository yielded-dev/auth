import { makeArgon2 } from "./internal/argon2-wasm";
import module from "./internal/argon2.wasm";
import { makeLayer } from "./internal/layer";
import { xchacha } from "./internal/xchacha";
import type { Limits } from "./Kdf";

/**
 * WebCrypto with Wasm SIMD Argon2id and portable XChaCha20-Poly1305.
 * Requires workerd's precompiled `.wasm` module imports (supported by Wrangler).
 * Derivations retain the portable backend's limits, scheduling and interruption.
 */
export const layer = (subtle: SubtleCrypto, limits: Partial<Limits> = {}) =>
  makeLayer(subtle, limits, { argon2: makeArgon2(module), xchacha });
