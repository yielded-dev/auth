import { HttpApiEndpoint, HttpApiSchema } from "effect/unstable/httpapi";

import { AuthRateLimited, AuthUnavailable, InvalidAuthRequest } from "../../Errors";
import { RequestEmailOtpPayload } from "../models";

export const RequestEmailOtpEndpoint = HttpApiEndpoint.post("requestEmailOtp", "/auth/email-otp", {
  payload: RequestEmailOtpPayload,
  success: HttpApiSchema.Empty(202),
  error: [InvalidAuthRequest, AuthRateLimited, AuthUnavailable],
});
