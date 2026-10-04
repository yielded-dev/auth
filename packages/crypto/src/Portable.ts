import { argon2 } from "./internal/argon2";
import { makeLayer } from "./internal/layer";
import { xchacha } from "./internal/xchacha";
import type { Limits } from "./Kdf";

/** WebCrypto with explicit Noble Argon2id and XChaCha20-Poly1305 extensions. */
export const layer = (subtle: SubtleCrypto, limits: Partial<Limits> = {}) =>
  makeLayer(subtle, limits, { argon2, xchacha });
