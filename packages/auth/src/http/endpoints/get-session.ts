import { HttpApiEndpoint } from "effect/unstable/httpapi";

import { AuthUnavailable } from "../../Errors";
import { SessionState } from "../models";

export const GetSessionEndpoint = HttpApiEndpoint.get("getSession", "/auth/session", {
  success: SessionState,
  error: AuthUnavailable,
});
