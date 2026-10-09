import { argon2 } from "./internal/argon2";
import { makeLayer } from "./internal/layer";
import { scrypt } from "./internal/scrypt";
import { xchacha } from "./internal/xchacha";
import type { Limits } from "./Kdf";

/** Workers WebCrypto and native scrypt, with portable Argon2id for existing hashes.
 * Requires Node.js compatibility. This backend ships ordinary JavaScript.
 */
export const layer = (subtle: SubtleCrypto, limits: Partial<Limits> = {}) =>
  makeLayer(subtle, limits, { argon2, scrypt, xchacha });
