import { Effect, Schema } from "effect";

import { InvalidInput } from "../Errors";
import { type Algorithm, SignInput, Signature, VerifyInput } from "../Signature";
import { copy, decode, importError, nativeError, withSecret } from "./common";

const derBytes = Schema.Uint8Array.check(Schema.isMinLength(1), Schema.isMaxLength(16384));

const RsaAlgorithm = Schema.Struct({
  modulusLength: Schema.Int.check(Schema.isGreaterThanOrEqualTo(2048)),
});

const importAlgorithm = (algorithm: Algorithm) => {
  switch (algorithm) {
    case "ECDSA-P256-SHA256":
      return { name: "ECDSA", namedCurve: "P-256" };
    case "RSA-PSS-SHA256":
      return { name: "RSA-PSS", hash: "SHA-256" };
    case "RSASSA-PKCS1-v1_5-SHA256":
      return { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
    case "Ed25519":
      return { name: "Ed25519" };
  }
};

const operationAlgorithm = (algorithm: Algorithm) => {
  switch (algorithm) {
    case "ECDSA-P256-SHA256":
      return { name: "ECDSA", hash: "SHA-256" };
    case "RSA-PSS-SHA256":
      return { name: "RSA-PSS", saltLength: 32 };
    case "RSASSA-PKCS1-v1_5-SHA256":
      return { name: "RSASSA-PKCS1-v1_5" };
    case "Ed25519":
      return { name: "Ed25519" };
  }
};

export const makeSignature = (subtle: SubtleCrypto): Signature["Service"] => {
  const importKey = Effect.fnUntraced(function* (
    algorithm: Algorithm,
    format: "pkcs8" | "spki",
    material: Uint8Array<ArrayBuffer>,
  ) {
    yield* decode(derBytes, material, "key");

    const key = yield* Effect.tryPromise({
      try: () =>
        subtle.importKey(format, material, importAlgorithm(algorithm), false, [
          format === "pkcs8" ? "sign" : "verify",
        ]),
      catch: importError,
    });

    if (algorithm === "RSA-PSS-SHA256" || algorithm === "RSASSA-PKCS1-v1_5-SHA256") {
      // The platform parsed this DER key. Validate its actual modulus, not caller metadata.
      yield* Schema.decodeUnknownEffect(RsaAlgorithm)(key.algorithm).pipe(
        Effect.mapError(() => InvalidInput.make({ reason: "key" })),
      );
    }

    return key;
  });

  return Signature.of({
    sign: Effect.fnUntraced(function* (input) {
      const value = yield* decode(SignInput, input, "data");
      const data = yield* copy(value.data);

      return yield* withSecret(value.privateKey, (material) =>
        Effect.gen(function* () {
          const key = yield* importKey(value.algorithm, "pkcs8", material);

          const result = yield* Effect.tryPromise({
            try: () => subtle.sign(operationAlgorithm(value.algorithm), key, data),
            catch: nativeError,
          });

          return new Uint8Array(result);
        }),
      );
    }),
    verify: Effect.fnUntraced(function* (input) {
      const value = yield* decode(VerifyInput, input, "data");
      const material = yield* copy(value.publicKey);
      const data = yield* copy(value.data);
      const signature = yield* copy(value.signature);
      const key = yield* importKey(value.algorithm, "spki", material);

      if (
        (value.algorithm === "ECDSA-P256-SHA256" || value.algorithm === "Ed25519") &&
        signature.length !== 64
      )
        return false;

      return yield* Effect.tryPromise({
        try: () => subtle.verify(operationAlgorithm(value.algorithm), key, signature, data),
        catch: nativeError,
      });
    }),
  });
};
