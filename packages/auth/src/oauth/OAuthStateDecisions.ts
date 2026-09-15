import { Context, type Effect } from "effect";

import type { ConsumeDecision } from "../auth/ConsumeDecision";
import type { AuthStoreError } from "../Errors";
import type { TokenDigest } from "../Schema";
import type { OAuthState } from "./schema";

/** Transaction-scoped consume; translate rejection only after the owner commits. */
export class OAuthStateDecisions extends Context.Service<
  OAuthStateDecisions,
  {
    readonly consumeOAuthState: (
      digest: TokenDigest,
    ) => Effect.Effect<ConsumeDecision<OAuthState>, AuthStoreError>;
  }
>()("effect-auth/OAuthStateDecisions") {}
