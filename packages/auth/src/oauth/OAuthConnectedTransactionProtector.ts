import { Context, type Effect } from "effect";

import type {
  OAuthConnectedTransactionContext,
  OAuthConnectedTransactionSecrets,
} from "./connectedModels";
import type { OAuthUnavailable } from "./signInErrors";
import type { OAuthSealedTransaction } from "./signInModels";

/** Separate connected purpose. Key retention includes original claim horizons. */
export class OAuthConnectedTransactionProtector extends Context.Service<
  OAuthConnectedTransactionProtector,
  {
    readonly seal: (input: {
      readonly context: OAuthConnectedTransactionContext;
      readonly secrets: OAuthConnectedTransactionSecrets;
    }) => Effect.Effect<OAuthSealedTransaction, OAuthUnavailable>;
    readonly open: (input: {
      readonly context: OAuthConnectedTransactionContext;
      readonly sealed: OAuthSealedTransaction;
    }) => Effect.Effect<OAuthConnectedTransactionSecrets, OAuthUnavailable>;
  }
>()("effect-auth/OAuthConnectedTransactionProtector") {}
