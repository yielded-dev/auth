import { Schema } from "effect";

import { PasskeyProfile } from "../models";

export const SimpleWebAuthnPasskeyProtocolOptions = Schema.Struct({
  profiles: Schema.NonEmptyArray(PasskeyProfile).check(Schema.isMaxLength(64)),
});

export type SimpleWebAuthnPasskeyProtocolOptions = typeof SimpleWebAuthnPasskeyProtocolOptions.Type;
