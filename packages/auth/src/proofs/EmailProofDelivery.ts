import { Context, type Effect } from "effect";

import {
  type ProofDelivery,
  type ProofDeliveryMessage,
  type ProofVendorPolicy,
  proofDeliveryLayer,
} from "./delivery";
import type { ProofDeliveryOutcome } from "./models";

/** Consumer-selected email renderer/vendor. No core import of a vendor SDK or application config. */
export class EmailProofDelivery extends Context.Service<EmailProofDelivery, ProofDelivery>()(
  "effect-auth/EmailProofDelivery",
) {
  static readonly layer = <E, R>(
    vendor: ProofVendorPolicy,
    send: (message: ProofDeliveryMessage) => Effect.Effect<ProofDeliveryOutcome, E, R>,
  ) => proofDeliveryLayer(this, vendor, send);
}
