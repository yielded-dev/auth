import { Context, type Effect } from "effect";

import type { ConsumeDecision } from "../auth/ConsumeDecision";
import type { EmailOtpRejectionReason } from "../AuthStore";
import type { AuthStoreError } from "../Errors";
import type { ConsumeChallenge, ConsumeRegistration, VerifiedEmail } from "../Schema";

export type ChallengeConsumeDecision =
  | { readonly _tag: "accepted"; readonly value: VerifiedEmail }
  | { readonly _tag: "rejected"; readonly reason: typeof EmailOtpRejectionReason.Type };

/** Translate rejected decisions only after the transaction commits. */
export class AuthStoreDecisions extends Context.Service<
  AuthStoreDecisions,
  {
    readonly consumeChallenge: (
      input: ConsumeChallenge,
    ) => Effect.Effect<ChallengeConsumeDecision, AuthStoreError>;
    readonly consumeRegistration: (
      input: ConsumeRegistration,
    ) => Effect.Effect<ConsumeDecision<void>, AuthStoreError>;
  }
>()("effect-auth/AuthStoreDecisions") {}
