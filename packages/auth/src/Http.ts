export { layer, make, type AuthHttpOptions } from "./http/auth-http";
export type { OAuthOptions, OAuthCallbackOptions } from "./http/oauth";

export { AuthApi } from "./http/auth-api";

export {
  ChallengeHeaderSecurity,
  ChallengeMiddleware,
  ChallengeSecurity,
  CurrentChallenge,
  CurrentRegistration,
  CurrentSession,
  RegistrationHeaderSecurity,
  RegistrationMiddleware,
  RegistrationSecurity,
  SessionBearerSecurity,
  SessionMiddleware,
  SessionSecurity,
  authChallengeHeaderName,
  authRegistrationHeaderName,
  authTokenHeaderName,
  challengeCookieName,
  challengeHeaderName,
  registrationCookieName,
  registrationHeaderName,
  sessionCookieName,
} from "./http/security";

export {
  ExistingSessionResult,
  PasswordSignInPayload,
  RegistrationRequiredResult,
  RequestEmailOtpPayload,
  SessionState,
  SessionStateAnonymous,
  SessionStateAuthenticated,
  SessionStateRegistrationRequired,
  SetPasswordPayload,
  VerifyEmailOtpPayload,
  VerifyEmailOtpResult,
} from "./http/models";

export { GetSessionEndpoint } from "./http/endpoints/get-session";
export { PasswordSignInEndpoint } from "./http/endpoints/password-sign-in";
export { RequestEmailOtpEndpoint } from "./http/endpoints/request-email-otp";
export { SetPasswordEndpoint } from "./http/endpoints/set-password";
export { SignOutEndpoint } from "./http/endpoints/sign-out";
export { VerifyEmailOtpEndpoint } from "./http/endpoints/verify-email-otp";
