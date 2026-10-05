import { Context, type Effect, type Redacted, Schema } from "effect";

import type { OperationError } from "./Errors";

export const Algorithm = Schema.Literals([
  "ECDSA-P256-SHA256",
  "RSASSA-PKCS1-v1_5-SHA256",
  "RSA-PSS-SHA256",
  "Ed25519",
]);

export type Algorithm = typeof Algorithm.Type;

const coordinate = Schema.Uint8Array.check(Schema.isMinLength(32), Schema.isMaxLength(32));
const integer = Schema.Uint8Array.check(Schema.isMinLength(1), Schema.isMaxLength(1024));
const ec = { algorithm: Schema.Literal("ECDSA-P256-SHA256"), x: coordinate, y: coordinate };
const ed = { algorithm: Schema.Literal("Ed25519"), x: coordinate };

const rsa = {
  algorithm: Schema.Literals(["RSASSA-PKCS1-v1_5-SHA256", "RSA-PSS-SHA256"]),
  n: integer,
  e: integer,
};

/**
 * Unsigned big-endian components: 32-byte curve values and RSA components up to
 * 1024 bytes. Native import validates the actual key, including RSA's minimum.
 */
export const PublicKeyParameters = Schema.Union([
  Schema.Struct(ec),
  Schema.Struct(ed),
  Schema.Struct(rsa),
]);

export type PublicKeyParameters = typeof PublicKeyParameters.Type;

export const PrivateKeyParameters = Schema.Union([
  Schema.Struct({ ...ec, d: coordinate }),
  Schema.Struct({ ...ed, d: coordinate }),
  Schema.Struct({
    ...rsa,
    d: integer,
    p: integer,
    q: integer,
    dp: integer,
    dq: integer,
    qi: integer,
  }),
]);

export type PrivateKeyParameters = typeof PrivateKeyParameters.Type;

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
    readonly encodePublicKey: (
      input: PublicKeyParameters,
    ) => Effect.Effect<Uint8Array, OperationError>;
    readonly encodePrivateKey: (
      input: Redacted.Redacted<PrivateKeyParameters>,
    ) => Effect.Effect<Redacted.Redacted<Uint8Array>, OperationError>;
    readonly sign: (input: SignInput) => Effect.Effect<Uint8Array, OperationError>;
    readonly verify: (input: VerifyInput) => Effect.Effect<boolean, OperationError>;
  }
>()("@yielded/crypto/Signature") {}
