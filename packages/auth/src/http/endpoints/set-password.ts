import { HttpApiEndpoint, HttpApiSchema } from "effect/unstable/httpapi";

import {
  AuthRateLimited,
  AuthUnavailable,
  InvalidAuthRequest,
  InvalidCredentials,
} from "../../Errors";
import { SetPasswordPayload } from "../models";
import { SessionMiddleware } from "../security";

export const SetPasswordEndpoint = HttpApiEndpoint.post("setPassword", "/auth/password", {
  payload: SetPasswordPayload,
  success: HttpApiSchema.NoContent,
  // Wrong current passwords share the sign-in failure accounting, so a
  // locked credential answers 429 here as well.
  error: [InvalidAuthRequest, InvalidCredentials, AuthRateLimited, AuthUnavailable],
}).middleware(SessionMiddleware);
