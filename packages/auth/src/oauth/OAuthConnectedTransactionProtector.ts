import { Context, type Effect } from "effect";

import type { OAuthConnectedTransactionContext } from "./connectedModels";
import type { OAuthUnavailable } from "./signInErrors";
import type { OAuthTransactionSecrets, OAuthSealedTransaction } from "./signInModels";

/** Separate connected purpose. Key retention includes original claim horizons. */
export class OAuthConnectedTransactionProtector extends Context.Service<
  OAuthConnectedTransactionProtector,
  {
    readonly seal: (input: {
      readonly context: OAuthConnectedTransactionContext;
      readonly secrets: OAuthTransactionSecrets;
    }) => Effect.Effect<OAuthSealedTransaction, OAuthUnavailable>;
    readonly open: (input: {
      readonly context: OAuthConnectedTransactionContext;
      readonly sealed: OAuthSealedTransaction;
    }) => Effect.Effect<OAuthTransactionSecrets, OAuthUnavailable>;
  }
>()("effect-auth/OAuthConnectedTransactionProtector") {}
