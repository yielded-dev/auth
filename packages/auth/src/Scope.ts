import { Schema } from "effect";

const validScope = Schema.isPattern(/^[\x21\x23-\x5B\x5D-\x7E]{1,128}$/);
const brand = Schema.brand("effect-auth/Scope");

/** A validated OAuth scope. Wire values remain strings. */
export const Scope = Schema.String.check(validScope).pipe(brand);

export type Scope<Name extends string = string> = Name & typeof Scope.Type;

/** Declare a scope while preserving its literal name and nominal type. */
export const make = <const Name extends string>(name: Name): Scope<Name> =>
  Schema.Literal(name).check(validScope).pipe(brand).make(name);
