import { makeLayer } from "./internal/layer";
import type { Limits } from "./Kdf";

/** Supply the host capability explicitly; no implicit global backend selection. */
export const layer = (subtle: SubtleCrypto, limits: Partial<Limits> = {}) =>
  makeLayer(subtle, limits);
