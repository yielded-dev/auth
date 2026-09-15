import { HttpApiGroup } from "effect/unstable/httpapi";

import { GetSessionEndpoint } from "./endpoints/get-session";
import { PasswordSignInEndpoint } from "./endpoints/password-sign-in";
import { RequestEmailOtpEndpoint } from "./endpoints/request-email-otp";
import { SetPasswordEndpoint } from "./endpoints/set-password";
import { SignOutEndpoint } from "./endpoints/sign-out";
import { VerifyEmailOtpEndpoint } from "./endpoints/verify-email-otp";

export const AuthApi = HttpApiGroup.make("auth").add(
  RequestEmailOtpEndpoint,
  VerifyEmailOtpEndpoint,
  PasswordSignInEndpoint,
  SetPasswordEndpoint,
  GetSessionEndpoint,
  SignOutEndpoint,
);
