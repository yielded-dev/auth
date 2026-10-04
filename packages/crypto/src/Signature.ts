import { Context, type Effect, Schema } from "effect";

import type { OperationError } from "./Errors";

export const Algorithm = Schema.Literals([
  "ECDSA-P256-SHA256",
  "RSASSA-PKCS1-v1_5-SHA256",
  "RSA-PSS-SHA256",
  "Ed25519",
]);

export type Algorithm = typeof Algorithm.Type;

export const SignInput = Schema.Struct({
  algorithm: Algorithm,
  privateKey: Schema.Redacted(Schema.Uint8Array, { disallowJsonEncode: true }),
  data: Schema.Uint8Array,
});

export type SignInput = typeof SignInput.Type;

export const VerifyInput = Schema.Struct({
  algorithm: Algorithm,
  publicKey: Schema.Uint8Array,
  data: Schema.Uint8Array,
  signature: Schema.Uint8Array,
});

export type VerifyInput = typeof VerifyInput.Type;

/**
 * Private keys are PKCS8 DER; public keys are SPKI DER. ECDSA signatures are
 * 64-byte IEEE P1363 (r || s), not ASN.1 DER. RSA requires at least 2048 bits;
 * PSS uses a 32-byte salt. Key serialization/selection and JOSE policy stay outside.
 */
export class Signature extends Context.Service<
  Signature,
  {
    readonly sign: (input: SignInput) => Effect.Effect<Uint8Array, OperationError>;
    readonly verify: (input: VerifyInput) => Effect.Effect<boolean, OperationError>;
  }
>()("@yielded/crypto/Signature") {}
