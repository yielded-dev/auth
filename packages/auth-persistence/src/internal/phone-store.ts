import type {
  PhoneAdmission,
  PhoneCredentialSnapshot,
  PhoneOtpUnavailable,
  PhoneSignInTargets,
  PhoneAdmissionPolicy,
} from "@yielded/auth/PhoneOtp";
import type { Effect, Option, PlatformError, Schema } from "effect";

import type { PersistenceStoreError } from "./persistence-owner";

export type PhoneStoreError =
  | PersistenceStoreError
  | PhoneOtpUnavailable
  | PlatformError.PlatformError
  | Schema.SchemaError;

/** Complete native operations retain their state preimages and assert their
 * final state before returning to the transaction owner. */
export interface PhoneStore {
  readonly admit: (
    input: Parameters<PhoneAdmission["Service"]["admit"]>[0],
  ) => Effect.Effect<boolean, PhoneStoreError>;
  readonly cleanup: (
    input: Parameters<PhoneAdmission["Service"]["cleanup"]>[0],
  ) => Effect.Effect<
    { readonly deleted: number; readonly nextCursor: string | null },
    PhoneStoreError
  >;
  readonly lookup: (
    input: Parameters<PhoneSignInTargets["Service"]["lookup"]>[0],
  ) => Effect.Effect<Option.Option<PhoneCredentialSnapshot>, PhoneStoreError>;
}

export const composedPhoneAdmission: PhoneAdmissionPolicy = {
  windowMillis: 60_000,
  networkRequests: 10,
  networkAttempts: 100,
  maximumMessages: 10,
  requestRetentionMillis: 86_400_000,
};
