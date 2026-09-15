import { Layer } from "effect";

import { AuthSession } from "./AuthSession";
import { EmailOtp } from "./EmailOtp";
import { PasswordAuth } from "./PasswordAuth";

/** The three core auth workflows, retaining their adapter requirements. */
export const layerAuthWorkflows = Layer.mergeAll(
  EmailOtp.layer,
  AuthSession.layer,
  PasswordAuth.layer,
);
