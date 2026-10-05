import { Context, type Effect, Layer } from "effect";

import type {
  OAuthConnectedTransactionContext,
  OAuthConnectedTransactionSecrets,
  OAuthConnectedSealedTransaction,
} from "./connectedModels";
import { make } from "./encryption/OAuthConnectedTransactionProtector";
import type { OAuthUnavailable } from "./signInErrors";
import type { OAuthTransactionKeyring } from "./transactionKeyring";

/** Separate connected purpose. Key retention includes original claim horizons.
 * Layer teardown cancels and joins active operations before wiping keys;
 * later calls fail with OAuthUnavailable. */
export class OAuthConnectedTransactionProtector extends Context.Service<
  OAuthConnectedTransactionProtector,
  {
    readonly seal: (input: {
      readonly context: OAuthConnectedTransactionContext;
      readonly secrets: OAuthConnectedTransactionSecrets;
    }) => Effect.Effect<OAuthConnectedSealedTransaction, OAuthUnavailable>;
    readonly open: (input: {
      readonly context: OAuthConnectedTransactionContext;
      readonly sealed: OAuthConnectedSealedTransaction;
    }) => Effect.Effect<OAuthConnectedTransactionSecrets, OAuthUnavailable>;
  }
>()("effect-auth/OAuthConnectedTransactionProtector") {
  static readonly layer = (keyring: OAuthTransactionKeyring) => Layer.effect(this, make(keyring));
}
