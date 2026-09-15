import { type Redacted, Context } from "effect";
import { HttpApiMiddleware, HttpApiSecurity } from "effect/unstable/httpapi";

import { AuthUnavailable, InvalidEmailOtp, InvalidRegistration, Unauthorized } from "../Errors";
import type { CurrentSession } from "../internal/CurrentSession";
import type { PendingRegistration } from "../Schema";

export { CurrentSession } from "../internal/CurrentSession";

export const challengeCookieName = "__Host-effect-auth-challenge";
export const registrationCookieName = "__Host-effect-auth-registration";
export const sessionCookieName = "__Host-effect-auth-session";

/**
 * Response header mirroring the session token whenever a session cookie is
 * set. Native clients cannot read HttpOnly cookies (and refuse `Secure`
 * cookies over plain http in development), so they store this value and send
 * it back as `Authorization: Bearer <token>`. Same convention as BetterAuth's
 * bearer plugin.
 */
export const authTokenHeaderName = "set-auth-token";
/**
 * Header twins of the challenge and registration cookies, for the same
 * cookie-less clients the bearer transport serves. The sign-in flow spans
 * requests (request code → verify → maybe register), and each hop's
 * intermediate token otherwise rides a SameSite cookie the client never
 * carries. Responses mirror the token in `set-auth-*`; clients echo it back
 * in the matching `x-auth-*` request header.
 */
export const authChallengeHeaderName = "set-auth-challenge";
export const authRegistrationHeaderName = "set-auth-registration";
export const challengeHeaderName = "x-auth-challenge";
export const registrationHeaderName = "x-auth-registration";

export const SessionSecurity = HttpApiSecurity.apiKey({ key: sessionCookieName, in: "cookie" });
/** Bearer transport for the same session token the cookie carries. */
export const SessionBearerSecurity = HttpApiSecurity.bearer;

export const ChallengeSecurity = HttpApiSecurity.apiKey({
  key: challengeCookieName,
  in: "cookie",
});

export const ChallengeHeaderSecurity = HttpApiSecurity.apiKey({
  key: challengeHeaderName,
  in: "header",
});

export const RegistrationSecurity = HttpApiSecurity.apiKey({
  key: registrationCookieName,
  in: "cookie",
});

export const RegistrationHeaderSecurity = HttpApiSecurity.apiKey({
  key: registrationHeaderName,
  in: "header",
});

export class CurrentRegistration extends Context.Service<
  CurrentRegistration,
  {
    readonly registration: PendingRegistration;
    readonly token: Redacted.Redacted<string>;
  }
>()("effect-auth/http/CurrentRegistration") {}

export class CurrentChallenge extends Context.Service<
  CurrentChallenge,
  Redacted.Redacted<string>
>()("effect-auth/http/CurrentChallenge") {}

// These cookies are HttpOnly browser credentials, so generated clients do not
// inject them. The transport layer carries them with same-origin requests.
// Sessions additionally accept the same token as an `Authorization: Bearer`
// header for clients without a usable cookie store; the securities are tried
// in record order and the first one whose handler succeeds wins.
export class SessionMiddleware extends HttpApiMiddleware.Service<
  SessionMiddleware,
  { provides: CurrentSession }
>()("effect-auth/http/SessionMiddleware", {
  security: { session: SessionSecurity, sessionBearer: SessionBearerSecurity },
  error: [Unauthorized, AuthUnavailable],
}) {}

export class RegistrationMiddleware extends HttpApiMiddleware.Service<
  RegistrationMiddleware,
  { provides: CurrentRegistration }
>()("effect-auth/http/RegistrationMiddleware", {
  security: {
    registration: RegistrationSecurity,
    registrationHeader: RegistrationHeaderSecurity,
  },
  error: [InvalidRegistration, AuthUnavailable],
}) {}

export class ChallengeMiddleware extends HttpApiMiddleware.Service<
  ChallengeMiddleware,
  { provides: CurrentChallenge }
>()("effect-auth/http/ChallengeMiddleware", {
  security: { challenge: ChallengeSecurity, challengeHeader: ChallengeHeaderSecurity },
  error: [InvalidEmailOtp],
}) {}
