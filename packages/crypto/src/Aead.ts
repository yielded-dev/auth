import { Context, type Effect, type Redacted, Schema } from "effect";

import type { AuthenticationFailed, OperationError } from "./Errors";

export const Algorithm = Schema.Literals(["AES-256-GCM", "XChaCha20-Poly1305"]);
export type Algorithm = typeof Algorithm.Type;

const context = {
  algorithm: Algorithm,
  key: Schema.Redacted(Schema.Uint8Array, { disallowJsonEncode: true }),
  nonce: Schema.Uint8Array,
  additionalData: Schema.optionalKey(Schema.Uint8Array),
};

export const EncryptInput = Schema.Struct({
  ...context,
  plaintext: Schema.Redacted(Schema.Uint8Array, { disallowJsonEncode: true }),
});

export type EncryptInput = typeof EncryptInput.Type;

export const DecryptInput = Schema.Struct({ ...context, ciphertext: Schema.Uint8Array });
export type DecryptInput = typeof DecryptInput.Type;

/**
 * Both algorithms use a 32-byte key and append a 16-byte tag to ciphertext.
 * AES-GCM uses a 12-byte nonce; XChaCha uses 24. The caller MUST supply a unique
 * nonce for each encryption with a key. Obtain entropy from Effect Crypto.
 * Envelope serialization and key selection belong to the caller.
 */
export class Aead extends Context.Service<
  Aead,
  {
    readonly encrypt: (input: EncryptInput) => Effect.Effect<Uint8Array, OperationError>;
    readonly decrypt: (
      input: DecryptInput,
    ) => Effect.Effect<Redacted.Redacted<Uint8Array>, OperationError | AuthenticationFailed>;
  }
>()("@yielded/crypto/Aead") {}
