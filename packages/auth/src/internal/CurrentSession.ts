import { Context } from "effect";

import type { SessionClaims } from "../Schema";

/** Authenticated session claims shared by HTTP and RPC transport middleware. */
export class CurrentSession extends Context.Service<CurrentSession, SessionClaims>()(
  "effect-auth/http/CurrentSession",
) {}
