import { Context, type Effect, type Schema, type Types } from "effect";

import type { PhoneCredentialSnapshot, PhoneOtpUnavailable } from "./models";

/** Shared by sign-in and explicitly selected lifecycle operations in the same namespace. */
export const makePhoneClaims = <
  const Id extends string,
  Claims extends Schema.Codec<unknown, unknown, unknown, unknown>,
>(
  moduleId: Id,
) =>
  Context.Service<
    {
      readonly moduleId: Id;
      readonly kind: "phone-claims";
      readonly claims: Types.Invariant<Claims["Type"]>;
    },
    {
      readonly resolve: (
        credential: PhoneCredentialSnapshot,
      ) => Effect.Effect<Claims["Type"], PhoneOtpUnavailable>;
    }
  >(`effect-auth/ClaimsForPhone/${moduleId.length}:${moduleId}`);
