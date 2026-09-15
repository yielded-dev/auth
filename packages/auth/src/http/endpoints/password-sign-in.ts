import { HttpApiEndpoint } from "effect/unstable/httpapi";

import {
  AuthRateLimited,
  AuthUnavailable,
  InvalidAuthRequest,
  InvalidCredentials,
} from "../../Errors";
import { PasswordSignInPayload, SessionStateAuthenticated } from "../models";

export const PasswordSignInEndpoint = HttpApiEndpoint.post(
  "passwordSignIn",
  "/auth/password/sign-in",
  {
    payload: PasswordSignInPayload,
    success: SessionStateAuthenticated,
    error: [InvalidAuthRequest, InvalidCredentials, AuthRateLimited, AuthUnavailable],
  },
);
