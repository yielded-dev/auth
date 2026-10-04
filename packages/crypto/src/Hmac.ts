import { Context, type Effect, Schema } from "effect";

import type { OperationError } from "./Errors";

/** SHA-1 exists for interoperability with TOTP, not new signature designs. */
export const Algorithm = Schema.Literals(["SHA-1", "SHA-256", "SHA-384", "SHA-512"]);
export type Algorithm = typeof Algorithm.Type;

export const Input = Schema.Struct({
  algorithm: Algorithm,
  key: Schema.Redacted(Schema.Uint8Array, { disallowJsonEncode: true }),
  data: Schema.Uint8Array,
});

export type Input = typeof Input.Type;

export const VerifyInput = Schema.Struct({ ...Input.fields, tag: Schema.Uint8Array });
export type VerifyInput = typeof VerifyInput.Type;

export class Hmac extends Context.Service<
  Hmac,
  {
    readonly sign: (input: Input) => Effect.Effect<Uint8Array, OperationError>;
    /** A wrong tag is false; a key or backend failure stays in the error channel. */
    readonly verify: (input: VerifyInput) => Effect.Effect<boolean, OperationError>;
  }
>()("@yielded/crypto/Hmac") {}
