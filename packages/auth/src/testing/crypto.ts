import { Crypto, Effect, Layer } from "effect";

/**
 * Seeded, reproducible `Crypto.Crypto` for tests. The digest is deterministic
 * and collision-poor but NOT cryptographic; never use this layer outside
 * tests.
 */
export const layerCryptoDeterministic = (seed = 1): Layer.Layer<Crypto.Crypto> =>
  Layer.sync(Crypto.Crypto)(() => {
    let state = seed >>> 0;

    // mulberry32
    const next = () => {
      state = (state + 0x6d2b79f5) | 0;
      let t = Math.imul(state ^ (state >>> 15), 1 | state);

      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;

      return (t ^ (t >>> 14)) >>> 0;
    };

    return Crypto.make({
      randomBytes: (size) => {
        const bytes = new Uint8Array(size);

        for (let index = 0; index < size; index++) {
          bytes[index] = next() & 0xff;
        }

        return bytes;
      },
      digest: (algorithm, data) => Effect.sync(() => fnvDigest(algorithm, data)),
    });
  });

const fnvDigest = (algorithm: string, data: Uint8Array): Uint8Array => {
  const output = new Uint8Array(32);

  for (let word = 0; word < 8; word++) {
    let hash = (0x811c9dc5 ^ Math.imul(word + 1, 0x9e3779b1)) >>> 0;

    for (let index = 0; index < algorithm.length; index++) {
      hash = Math.imul(hash ^ algorithm.charCodeAt(index), 0x01000193) >>> 0;
    }
    for (let index = 0; index < data.length; index++) {
      hash = Math.imul(hash ^ (data[index] ?? 0), 0x01000193) >>> 0;
    }
    output[word * 4] = hash & 0xff;
    output[word * 4 + 1] = (hash >>> 8) & 0xff;
    output[word * 4 + 2] = (hash >>> 16) & 0xff;
    output[word * 4 + 3] = (hash >>> 24) & 0xff;
  }

  return output;
};
