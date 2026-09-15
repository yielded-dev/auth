import * as Auth from "@yielded/auth/Auth";
import * as Totp from "@yielded/auth/Totp";
import { Schema } from "effect";

import { policy } from "./totp-sqlite-consumer";

/** Compose with the application's primary strategies. Their AuthenticationAuthority
 * reads the same subject factor policy, so password/link/OAuth/phone completions
 * all enter restricted pending authentication when TOTP is required. */
export class AuthenticatorAuth extends Auth.Service<AuthenticatorAuth>()(
  "example/AuthenticatorAuth",
  {
    claims: Schema.Struct({ role: Schema.Literal("member") }),
    strategies: { authenticator: Totp.make({ ...policy, namespace: "example/totp" }) },
    defaultStrategy: "authenticator",
  },
) {}

export const authenticator = AuthenticatorAuth.strategies.authenticator;
export const sessions = AuthenticatorAuth.sessions;

// Provide native TotpPersistence, consumer TotpSecretKeys/TotpActionEvidence, and
// the common session strategy/completion/step-up Layers to AuthenticatorAuth.layer.
// AuthRequest supplies request-local credential and finite reveal collectors.
// These same operation contracts also compose into the remote RPC boundary.
export const authenticatorRpcGroup = authenticator.group;
export const authenticatorHandlers = authenticator.handlersLayer;
