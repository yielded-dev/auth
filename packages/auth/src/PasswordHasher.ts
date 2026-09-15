import { Context, Crypto, Effect, Encoding, Layer, Redacted, Result, Schema } from "effect";

import { AuthTokenError } from "./Errors";
import { AuthPolicy } from "./Policy";
import { PasswordHash, timingSafeStringEqual } from "./Schema";
import { SubtleCrypto } from "./WebCrypto";

const passwordHashAlgorithm = "pbkdf2-sha256";
const saltLength = 16;
const derivedKeyBits = 256;
const textEncoder = new TextEncoder();

const passwordHashFromString = Schema.decodeEffect(PasswordHash);

interface PasswordHashParams {
  readonly iterations: number;
  readonly salt: Uint8Array;
  readonly digest: string;
}

// Verification derives with the parameters recorded on the stored hash, not
// the current policy, so old hashes keep verifying after a policy change.
const parsePasswordHash = (hash: string): PasswordHashParams | undefined => {
  const [algorithm, iterationsPart, saltPart, digestPart, ...rest] = hash.split("$");

  if (
    algorithm !== passwordHashAlgorithm ||
    iterationsPart === undefined ||
    saltPart === undefined ||
    digestPart === undefined ||
    digestPart === "" ||
    rest.length > 0 ||
    !/^[1-9]\d{0,8}$/.test(iterationsPart)
  ) {
    return undefined;
  }
  const salt = Result.getOrUndefined(Encoding.decodeBase64Url(saltPart));

  if (salt === undefined || salt.length === 0) {
    return undefined;
  }

  return { iterations: Number(iterationsPart), salt, digest: digestPart };
};

/**
 * Default PBKDF2-HMAC-SHA-256 hasher on WebCrypto. Iterations come from
 * `AuthPolicy`; salts come from `Crypto.Crypto` so tests can seed them, and
 * key derivation goes through the `SubtleCrypto` service.
 */
const makeWebCryptoHasher: Effect.Effect<
  PasswordHasher["Service"],
  never,
  Crypto.Crypto | SubtleCrypto
> = Effect.gen(function* () {
  const policy = yield* AuthPolicy;
  const crypto = yield* Crypto.Crypto;
  const subtle = yield* SubtleCrypto;

  const derive = (password: Redacted.Redacted<string>, salt: Uint8Array, iterations: number) =>
    Effect.tryPromise({
      try: async () => {
        const key = await subtle.importKey(
          "raw",
          textEncoder.encode(Redacted.value(password)),
          "PBKDF2",
          false,
          ["deriveBits"],
        );

        const bits = await subtle.deriveBits(
          { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations },
          key,
          derivedKeyBits,
        );

        return new Uint8Array(bits);
      },
      catch: () => AuthTokenError.make({ message: "Password key derivation failed" }),
    });

  return PasswordHasher.of({
    hash: Effect.fn("PasswordHasher.hash")(function* (password) {
      const salt = yield* crypto
        .randomBytes(saltLength)
        .pipe(
          Effect.mapError(() => AuthTokenError.make({ message: "Secure randomness unavailable" })),
        );

      const derived = yield* derive(password, salt, policy.passwordIterations);

      const encoded =
        `${passwordHashAlgorithm}$${policy.passwordIterations}` +
        `$${Encoding.encodeBase64Url(salt)}$${Encoding.encodeBase64Url(derived)}`;

      return yield* passwordHashFromString(encoded).pipe(
        Effect.mapError(() => AuthTokenError.make({ message: "Password hash failed to encode" })),
      );
    }),

    verify: Effect.fn("PasswordHasher.verify")(function* (password, hash) {
      const params = parsePasswordHash(hash);

      // A malformed stored hash degrades to a plain mismatch, never a
      // distinguishable auth response.
      if (params === undefined) {
        return false;
      }
      const derived = yield* derive(password, params.salt, params.iterations);

      return timingSafeStringEqual(Encoding.encodeBase64Url(derived), params.digest);
    }),
  });
});

/**
 * One-way password hashing and verification. The PHC-style `PasswordHash`
 * format is this service's private concern; stores persist it opaquely.
 */
export class PasswordHasher extends Context.Service<
  PasswordHasher,
  {
    /** Derives a fresh salted hash for the password at the configured cost. */
    readonly hash: (
      password: Redacted.Redacted<string>,
    ) => Effect.Effect<PasswordHash, AuthTokenError>;
    /**
     * Verifies the password against a stored hash using the parameters
     * recorded on the hash, comparing digests in constant time. A malformed
     * hash yields `false`, never a distinguishable failure.
     */
    readonly verify: (
      password: Redacted.Redacted<string>,
      hash: PasswordHash,
    ) => Effect.Effect<boolean, AuthTokenError>;
  }
>()("effect-auth/PasswordHasher") {
  /**
   * Default PBKDF2 implementation backed by WebCrypto. The consumer may
   * replace it with its own hasher service, or satisfy `SubtleCrypto` with
   * `SubtleCrypto.layerWeb`.
   */
  static readonly layerWebCrypto: Layer.Layer<PasswordHasher, never, Crypto.Crypto | SubtleCrypto> =
    Layer.effect(PasswordHasher)(makeWebCryptoHasher);

  static readonly layer = PasswordHasher.layerWebCrypto;
}
