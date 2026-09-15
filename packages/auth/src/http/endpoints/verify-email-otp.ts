import { HttpApiEndpoint } from "effect/unstable/httpapi";

import { AuthUnavailable, InvalidAuthRequest, InvalidEmailOtp } from "../../Errors";
import { VerifyEmailOtpPayload, VerifyEmailOtpResult } from "../models";
import { ChallengeMiddleware } from "../security";

export const VerifyEmailOtpEndpoint = HttpApiEndpoint.post(
  "verifyEmailOtp",
  "/auth/email-otp/verify",
  {
    payload: VerifyEmailOtpPayload,
    success: VerifyEmailOtpResult,
    error: [InvalidAuthRequest, InvalidEmailOtp, AuthUnavailable],
  },
).middleware(ChallengeMiddleware);
