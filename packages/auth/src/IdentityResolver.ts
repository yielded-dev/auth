import { type Effect, type Option, Context } from "effect";

import type { IdentityResolutionError } from "./Errors";
import type { Email, SubjectId } from "./Schema";

/**
 * Read-only mapping from a verified canonical email to an existing subject.
 * Must not auto-provision: account creation stays a separate, application-owned
 * operation.
 */
export class IdentityResolver extends Context.Service<
  IdentityResolver,
  {
    readonly findByVerifiedEmail: (
      email: Email,
    ) => Effect.Effect<Option.Option<SubjectId>, IdentityResolutionError>;
  }
>()("effect-auth/IdentityResolver") {}
