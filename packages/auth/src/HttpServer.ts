import { type Types, DateTime, Effect, Layer, Option, Redacted, Schema } from "effect";
import { type Cookies, HttpEffect, HttpServerResponse } from "effect/unstable/http";
import {
  type HttpApi,
  HttpApiBuilder,
  type HttpApiEndpoint,
  type HttpApiGroup,
  type HttpApiSecurity,
} from "effect/unstable/httpapi";

import {
  type AuthSessionWithExtClass,
  type AuthSessionWithExtService,
  type IssuedSession,
  type SessionExtContext,
  AuthSession,
} from "./AuthSession";
import { EmailOtp } from "./EmailOtp";
import {
  AuthUnavailable,
  InvalidAuthRequest,
  InvalidEmailOtp,
  InvalidRegistration,
  Unauthorized,
} from "./Errors";
import { type AuthApi } from "./http/auth-api";
import {
  ExistingSessionResult,
  RegistrationRequiredResult,
  SessionStateAnonymous,
  SessionStateAuthenticated,
  SessionStateRegistrationRequired,
} from "./http/models";
import {
  authChallengeHeaderName,
  authRegistrationHeaderName,
  authTokenHeaderName,
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
} from "./http/security";
import { PasswordAuth } from "./PasswordAuth";
import { Email, SessionSummary } from "./Schema";

const decodeEmail = Schema.decodeEffect(Email);

const issueSession = Effect.fn("effect-auth/issueSession")(function* <A>(
  sessions: AuthSession["Service"],
  context: SessionExtContext,
  sessionExt?: AuthSessionWithExtService<A>,
) {
  if (sessionExt === undefined) {
    return yield* sessions.issue(context.subjectId);
  }

  return yield* sessionExt.issueFromContext(context);
});

// --- Cookie helpers ----------------------------------------------------------
//
// Handlers never build `Set-Cookie` headers or parse `Cookie` headers; cookies
// go through the Effect security helpers and pre-response combinators.

const baseCookieOptions = {
  path: "/",
  sameSite: "lax",
  secure: true,
  httpOnly: true,
} satisfies Cookies.Cookie["options"];

const cookieOptionsUntil = (expiresAt: DateTime.Utc): Cookies.Cookie["options"] => ({
  ...baseCookieOptions,
  expires: DateTime.toDateUtc(expiresAt),
});

/** Registers a pre-response handler that expires one of the auth cookies. */
export const expireSecurityCookie = (security: HttpApiSecurity.ApiKey) =>
  HttpEffect.appendPreResponseHandler((_request, response) =>
    Effect.orDie(HttpServerResponse.expireCookie(response, security.key, baseCookieOptions)),
  );

/**
 * Bearer-transport counterpart of {@link expireSecurityCookie}: an empty
 * `set-auth-token` header tells cookie-less clients to drop their stored
 * session token. Without it, sign-out only expires the cookie and a bearer
 * client races its own token cleanup against the session refetch — the
 * stateless token keeps verifying and the client re-authenticates itself
 * straight back into the session it just revoked.
 */
export const expireAuthTokenHeader = HttpEffect.appendPreResponseHandler((_request, response) =>
  Effect.succeed(HttpServerResponse.setHeader(response, authTokenHeaderName, "")),
);

/** Auth responses must never be cached. */
const noStore = HttpEffect.appendPreResponseHandler((_request, response) =>
  Effect.succeed(HttpServerResponse.setHeader(response, "cache-control", "no-store")),
);

/**
 * Applies the session to a concrete response for both transports. This is the
 * raw-handler counterpart to {@link registerSession}; keeping both here makes
 * the cookie and bearer-header contract a single source of truth.
 */
export const setSessionOnResponse = (
  response: HttpServerResponse.HttpServerResponse,
  issued: IssuedSession,
): HttpServerResponse.HttpServerResponse =>
  response.pipe(
    HttpServerResponse.setCookieUnsafe(
      SessionSecurity.key,
      issued.token,
      cookieOptionsUntil(issued.summary.expiresAt),
    ),
    HttpServerResponse.setHeader(authTokenHeaderName, issued.token),
  );

/**
 * Registers the session on the response for both transports: the HttpOnly
 * cookie for browsers, and the `set-auth-token` header for clients that
 * cannot read the cookie and echo the token back as `Authorization: Bearer`.
 * Every place that issues a session must go through this so the two
 * transports never drift — including application-owned handlers that issue
 * sessions outside this module's workflows.
 */
export const registerSession = (issued: IssuedSession) =>
  HttpEffect.appendPreResponseHandler((_request, response) =>
    Effect.succeed(setSessionOnResponse(response, issued)),
  );

/**
 * Mirrors a flow-intermediate token (challenge, registration) on a response
 * header, the same dual-transport rule as {@link registerSession}: the
 * SameSite cookie serves browsers, the header serves clients whose cookie
 * store never carries it, which echo it back as the matching `x-auth-*`
 * request header.
 */
const mirrorTokenHeader = (headerName: string, token: Redacted.Redacted<string>) =>
  HttpEffect.appendPreResponseHandler((_request, response) =>
    Effect.succeed(HttpServerResponse.setHeader(response, headerName, Redacted.value(token))),
  );

// `AuthUnavailable` is all the caller should learn from a failed auth
// operation, but collapsing distinct faults into one status leaves a 503 with
// nothing to diagnose. Name the fault on the way past. Expected outcomes such
// as rate limiting or invalid credentials are deliberately never logged.
const failUnavailable = Effect.fn("failUnavailable")(function* (
  operation: string,
  fault: string,
  detail: string,
): Effect.fn.Return<never, AuthUnavailable> {
  yield* Effect.logError(`${operation} failed`).pipe(Effect.annotateLogs({ fault, detail }));

  return yield* AuthUnavailable.make();
});

/**
 * Resolves the request's optional session and pending-registration credentials.
 * Browser credentials prefer cookies; native clients can supply the same tokens
 * through their corresponding headers.
 * Invalid or expired credentials degrade to the next public state; failures
 * in the token codec or auth store remain an explicit availability error.
 */
export const resolveSessionState = Effect.gen(function* () {
  const sessions = yield* AuthSession;
  const emailOtp = yield* EmailOtp;
  const cookieCredential = yield* HttpApiBuilder.securityDecode(SessionSecurity);

  const sessionCredential =
    Redacted.value(cookieCredential) !== ""
      ? cookieCredential
      : yield* HttpApiBuilder.securityDecode(SessionBearerSecurity);

  if (Redacted.value(sessionCredential) !== "") {
    const authenticated = yield* sessions.verifyAndRenew(sessionCredential).pipe(
      Effect.flatMap((verified) =>
        Effect.gen(function* () {
          if (Option.isSome(verified.renewal)) {
            yield* registerSession(verified.renewal.value);
          }

          return Option.some(
            SessionStateAuthenticated.make({
              session: SessionSummary.make({
                subjectId: verified.claims.sub,
                expiresAt: Option.match(verified.renewal, {
                  onNone: () => verified.claims.exp,
                  onSome: (renewal) => renewal.summary.expiresAt,
                }),
              }),
            }),
          );
        }),
      ),
      Effect.catchTags({
        InvalidSession: () => Effect.succeed(Option.none<SessionStateAuthenticated>()),
        AuthTokenError: () => AuthUnavailable.make(),
        IdentityResolutionError: () => AuthUnavailable.make(),
      }),
    );

    if (Option.isSome(authenticated)) {
      return authenticated.value;
    }
  }
  const registrationCookieCredential = yield* HttpApiBuilder.securityDecode(RegistrationSecurity);

  const registrationCredential =
    Redacted.value(registrationCookieCredential) !== ""
      ? registrationCookieCredential
      : yield* HttpApiBuilder.securityDecode(RegistrationHeaderSecurity);

  if (Redacted.value(registrationCredential) !== "") {
    const pending = yield* emailOtp.inspectRegistration(registrationCredential).pipe(
      Effect.map((registration) =>
        Option.some(
          SessionStateRegistrationRequired.make({
            email: registration.email,
            registrationExpiresAt: registration.expiresAt,
          }),
        ),
      ),
      Effect.catchTags({
        InvalidRegistration: () => Effect.succeed(Option.none<SessionStateRegistrationRequired>()),
        AuthStoreError: () => AuthUnavailable.make(),
        AuthTokenError: () => AuthUnavailable.make(),
      }),
    );

    if (Option.isSome(pending)) {
      return pending.value;
    }
  }

  return SessionStateAnonymous.make();
}).pipe(Effect.withSpan("effect-auth.resolveSessionState"));

// --- Middleware implementations ------------------------------------------------

export const SessionMiddlewareLayer: Layer.Layer<SessionMiddleware, never, AuthSession> =
  Layer.effect(SessionMiddleware)(
    Effect.map(AuthSession, (sessions) => {
      // Cookie and bearer carry the same session token, so both securities
      // verify identically; failing on an absent credential is what lets the
      // security dispatch fall through to the other transport.
      const verifySession = Effect.fn("SessionMiddleware.session")(function* (
        httpEffect: Effect.Effect<
          HttpServerResponse.HttpServerResponse,
          Types.unhandled,
          CurrentSession
        >,
        { credential }: { readonly credential: Redacted.Redacted<string> },
      ) {
        // An empty bearer fallback must not replace a cookie infrastructure
        // failure with Unauthorized after security dispatch tries both.
        const sessionCredential =
          Redacted.value(credential) === ""
            ? yield* HttpApiBuilder.securityDecode(SessionSecurity)
            : credential;

        if (Redacted.value(sessionCredential) === "") {
          return yield* Unauthorized.make();
        }

        const verified = yield* sessions.verifyAndRenew(sessionCredential).pipe(
          Effect.catchTags({
            InvalidSession: () => Unauthorized.make(),
            AuthTokenError: () => AuthUnavailable.make(),
            IdentityResolutionError: () => AuthUnavailable.make(),
          }),
        );

        const response = yield* Effect.provideService(httpEffect, CurrentSession, verified.claims);

        if (Option.isSome(verified.renewal)) {
          yield* registerSession(verified.renewal.value);
        }

        return response;
      });

      return SessionMiddleware.of({
        session: verifySession,
        sessionBearer: verifySession,
      });
    }),
  );

export const RegistrationMiddlewareLayer: Layer.Layer<RegistrationMiddleware, never, EmailOtp> =
  Layer.effect(RegistrationMiddleware)(
    Effect.map(EmailOtp, (emailOtp) => {
      // Cookie and header carry the same registration token; failing on an
      // absent credential lets the security dispatch fall through to the
      // other transport, same as SessionMiddleware.
      const verifyRegistration = Effect.fn("RegistrationMiddleware.registration")(function* (
        httpEffect: Effect.Effect<
          HttpServerResponse.HttpServerResponse,
          Types.unhandled,
          CurrentRegistration
        >,
        { credential }: { readonly credential: Redacted.Redacted<string> },
      ) {
        if (Redacted.value(credential) === "") {
          return yield* InvalidRegistration.make();
        }

        const registration = yield* emailOtp.inspectRegistration(credential).pipe(
          Effect.catchTags({
            AuthStoreError: () => AuthUnavailable.make(),
            AuthTokenError: () => AuthUnavailable.make(),
          }),
        );

        return yield* Effect.provideService(httpEffect, CurrentRegistration, {
          registration,
          token: credential,
        });
      });

      return RegistrationMiddleware.of({
        registration: verifyRegistration,
        registrationHeader: verifyRegistration,
      });
    }),
  );

const provideChallenge = (
  httpEffect: Effect.Effect<
    HttpServerResponse.HttpServerResponse,
    Types.unhandled,
    CurrentChallenge
  >,
  { credential }: { readonly credential: Redacted.Redacted<string> },
) =>
  Redacted.value(credential) === ""
    ? Effect.fail(InvalidEmailOtp.make())
    : Effect.provideService(httpEffect, CurrentChallenge, credential);

const provideChallengeHeader = (
  httpEffect: Effect.Effect<
    HttpServerResponse.HttpServerResponse,
    Types.unhandled,
    CurrentChallenge
  >,
  input: { readonly credential: Redacted.Redacted<string> },
) =>
  Redacted.value(input.credential) === ""
    ? Effect.logInfo("Email OTP verification rejected").pipe(
        Effect.annotateLogs({
          "auth.method": "email_otp",
          "auth.outcome": "rejected",
          "auth.reason": "missing_challenge_credential",
        }),
        Effect.andThen(InvalidEmailOtp.make()),
      )
    : provideChallenge(httpEffect, input);

export const ChallengeMiddlewareLayer: Layer.Layer<ChallengeMiddleware> = Layer.succeed(
  ChallengeMiddleware,
)(
  ChallengeMiddleware.of({
    challenge: provideChallenge,
    challengeHeader: provideChallengeHeader,
  }),
);

// --- Handlers -------------------------------------------------------------------

/**
 * Gate for the handler-layer factories: the consumer's API must contain an
 * `auth` group with every canonical endpoint. API prefixes and middleware may
 * wrap endpoint path and requirement types, so the check allows those two
 * differences while preserving every transport schema.
 */
type AuthGroup<Groups> = Extract<Groups, { readonly identifier: "auth" }>;
type AuthGroupEndpoints<Groups> =
  AuthGroup<Groups> extends {
    readonly endpoints: infer Endpoints;
  }
    ? Endpoints
    : never;
type CanonicalAuthEndpoints = (typeof AuthApi)["endpoints"];
type AuthEndpoint<Groups, Name> = Name extends keyof AuthGroupEndpoints<Groups>
  ? AuthGroupEndpoints<Groups>[Name]
  : never;
type EndpointContract<Endpoint> =
  Endpoint extends HttpApiEndpoint.HttpApiEndpoint<
    infer Identifier,
    infer Method,
    infer _Path,
    infer Params,
    infer Query,
    infer Payload,
    infer Headers,
    infer Success,
    infer Error,
    infer _Middleware,
    infer _MiddlewareRequirements
  >
    ? [Identifier, Method, Params, Query, Payload, Headers, Success, Error]
    : never;
type EndpointPath<Endpoint> = Endpoint extends { readonly path: infer Path extends string }
  ? Path
  : never;
type Equal<Left, Right> = [Left, Right] extends [Right, Left] ? true : false;
type CompatibleEndpoint<Candidate, Canonical> =
  Equal<EndpointContract<Candidate>, EndpointContract<Canonical>> extends true
    ? EndpointPath<Candidate> extends `${string}${EndpointPath<Canonical>}`
      ? true
      : false
    : false;
type IncompatibleAuthEndpoints<Groups> = {
  [Name in keyof CanonicalAuthEndpoints]: CompatibleEndpoint<
    AuthEndpoint<Groups, Name>,
    CanonicalAuthEndpoints[Name]
  > extends true
    ? never
    : Name;
}[keyof CanonicalAuthEndpoints];
type RequiresAuthGroup<Groups> = [AuthGroup<Groups>] extends [never]
  ? { readonly "~effect-auth": "the consumer HttpApi must include the AuthApi group" }
  : [IncompatibleAuthEndpoints<Groups>] extends [never]
    ? unknown
    : {
        readonly "~effect-auth": "the consumer auth group must preserve every AuthApi endpoint contract";
      };

/**
 * Builds the handler layer for the `auth` group of a consumer `HttpApi` that
 * includes {@link AuthApi}. The internal assertion re-anchors the builder on
 * the canonical group so endpoint handlers type against it.
 */
export const layerAuthHandlers = <
  ApiId extends string,
  Groups extends HttpApiGroup.Constraint,
  Self = never,
  Id extends string = string,
  A = never,
>(
  api: HttpApi.HttpApi<ApiId, Groups> & NoInfer<RequiresAuthGroup<Groups>>,
  sessionExt?: AuthSessionWithExtClass<Self, Id, A>,
) =>
  HttpApiBuilder.group(
    api as unknown as HttpApi.HttpApi<ApiId, typeof AuthApi>,
    "auth",
    (handlers) =>
      Effect.gen(function* () {
        const emailOtp = yield* EmailOtp;
        const sessions = yield* AuthSession;
        const sessionsWithExt = sessionExt === undefined ? undefined : yield* sessionExt;
        const passwords = yield* PasswordAuth;

        const currentSessionState = resolveSessionState.pipe(
          Effect.provideService(EmailOtp, emailOtp),
          Effect.provideService(AuthSession, sessions),
        );

        return handlers
          .handle("requestEmailOtp", ({ payload }) =>
            Effect.gen(function* () {
              yield* noStore;

              const email = yield* decodeEmail(payload.email).pipe(
                Effect.mapError(() =>
                  InvalidAuthRequest.make({ message: "A valid email address is required" }),
                ),
              );

              const challenge = yield* emailOtp.request(email).pipe(
                Effect.catchTags({
                  AuthStoreError: (error) =>
                    failUnavailable("Email OTP request", "auth store", error.message),
                  AuthTokenError: (error) =>
                    failUnavailable("Email OTP request", "token codec", error.message),
                  EmailDeliveryError: (error) =>
                    failUnavailable("Email OTP request", "email delivery", error.message),
                }),
              );

              yield* HttpApiBuilder.securitySetCookie(
                ChallengeSecurity,
                challenge.challengeToken,
                cookieOptionsUntil(challenge.expiresAt),
              );
              yield* mirrorTokenHeader(authChallengeHeaderName, challenge.challengeToken);
              yield* Effect.logInfo("Sign-in code requested").pipe(
                Effect.annotateLogs({
                  "auth.method": "email_otp",
                  "auth.outcome": "challenge_issued",
                  email,
                  expiresAt: DateTime.formatIso(challenge.expiresAt),
                }),
              );
            }),
          )
          .handle("verifyEmailOtp", ({ payload }) =>
            Effect.gen(function* () {
              yield* noStore;
              const challengeToken = yield* CurrentChallenge;

              const outcome = yield* emailOtp.verify({ challengeToken, code: payload.code }).pipe(
                Effect.catchTags({
                  AuthStoreError: (error) =>
                    failUnavailable("Email OTP verification", "auth store", error.message),
                  AuthTokenError: (error) =>
                    failUnavailable("Email OTP verification", "token codec", error.message),
                  IdentityResolutionError: (error) =>
                    failUnavailable("Email OTP verification", "identity resolution", error.message),
                }),
              );

              yield* expireSecurityCookie(ChallengeSecurity);
              yield* Effect.logInfo("Sign-in code verified").pipe(
                Effect.annotateLogs({
                  "auth.method": "email_otp",
                  "auth.outcome":
                    outcome._tag === "ExistingSubject"
                      ? "existing_subject"
                      : "registration_required",
                }),
              );
              if (outcome._tag === "ExistingSubject") {
                const issued = yield* issueSession(
                  sessions,
                  { subjectId: outcome.subjectId, email: outcome.email },
                  sessionsWithExt,
                ).pipe(
                  Effect.catchTag("AuthTokenError", (error) =>
                    failUnavailable("Session issuance", "token codec", error.message),
                  ),
                );

                yield* registerSession(issued);
                yield* Effect.logInfo("Session issued").pipe(
                  Effect.annotateLogs({
                    "auth.method": "email_otp",
                    "auth.outcome": "session_issued",
                    subjectId: outcome.subjectId,
                    expiresAt: DateTime.formatIso(issued.summary.expiresAt),
                  }),
                );

                return ExistingSessionResult.make({ session: issued.summary });
              }
              yield* HttpApiBuilder.securitySetCookie(
                RegistrationSecurity,
                outcome.registrationToken,
                cookieOptionsUntil(outcome.expiresAt),
              );
              yield* mirrorTokenHeader(authRegistrationHeaderName, outcome.registrationToken);
              yield* Effect.logInfo("Registration required").pipe(
                Effect.annotateLogs({
                  "auth.method": "email_otp",
                  "auth.outcome": "registration_required",
                  email: outcome.email,
                  expiresAt: DateTime.formatIso(outcome.expiresAt),
                }),
              );

              return RegistrationRequiredResult.make({
                email: outcome.email,
                registrationExpiresAt: outcome.expiresAt,
              });
            }),
          )
          .handle("passwordSignIn", ({ payload }) =>
            Effect.gen(function* () {
              yield* noStore;

              const email = yield* decodeEmail(payload.email).pipe(
                Effect.mapError(() =>
                  InvalidAuthRequest.make({ message: "A valid email address is required" }),
                ),
              );

              const subjectId = yield* passwords.signIn(email, payload.password).pipe(
                Effect.catchTags({
                  AuthStoreError: (error) =>
                    failUnavailable("Password sign-in", "credential store", error.message),
                  AuthTokenError: (error) =>
                    failUnavailable("Password sign-in", "password hasher", error.message),
                }),
              );

              const issued = yield* issueSession(
                sessions,
                { subjectId, email },
                sessionsWithExt,
              ).pipe(
                Effect.catchTag("AuthTokenError", (error) =>
                  failUnavailable("Session issuance", "token codec", error.message),
                ),
              );

              yield* registerSession(issued);
              yield* Effect.logInfo("Session issued").pipe(
                Effect.annotateLogs({
                  "auth.method": "password",
                  "auth.outcome": "session_issued",
                  subjectId,
                  expiresAt: DateTime.formatIso(issued.summary.expiresAt),
                }),
              );

              return SessionStateAuthenticated.make({ session: issued.summary });
            }),
          )
          .handle("setPassword", ({ payload }) =>
            Effect.gen(function* () {
              yield* noStore;
              const session = yield* CurrentSession;

              yield* passwords
                .setPassword(session.sub, {
                  currentPassword: Option.fromNullishOr(payload.currentPassword),
                  newPassword: payload.newPassword,
                })
                .pipe(
                  Effect.catchTags({
                    AuthStoreError: (error) =>
                      failUnavailable("Password change", "credential store", error.message),
                    AuthTokenError: (error) =>
                      failUnavailable("Password change", "password hasher", error.message),
                  }),
                );
              yield* Effect.logInfo("Password changed").pipe(
                Effect.annotateLogs({
                  "auth.method": "password",
                  "auth.outcome": "password_changed",
                  subjectId: session.sub,
                }),
              );
            }),
          )
          .handle("getSession", () => noStore.pipe(Effect.andThen(currentSessionState)))
          .handle("signOut", () =>
            Effect.gen(function* () {
              yield* noStore;
              yield* expireSecurityCookie(ChallengeSecurity);
              yield* expireSecurityCookie(RegistrationSecurity);
              yield* expireSecurityCookie(SessionSecurity);
              yield* expireAuthTokenHeader;
              yield* Effect.logInfo("Session signed out").pipe(
                Effect.annotateLogs({ "auth.outcome": "signed_out" }),
              );
            }),
          );
      }),
  );

/**
 * Real onboarding workflow for application-owned, registration-protected
 * account endpoints: consumes the current pending registration, registers the
 * session cookie on the
 * response, and returns the session summary. Call it after the application has
 * idempotently created the account and email mapping.
 */
const establishSessionFromRegistrationWith = Effect.fn(
  "effect-auth/establishSessionFromRegistration",
)(function* <A>(sessionExt?: AuthSessionWithExtService<A>) {
  const { registration, token } = yield* CurrentRegistration;
  const emailOtp = yield* EmailOtp;
  const sessions = yield* AuthSession;
  const subjectId = yield* emailOtp.completeRegistration(token);

  const issued = yield* issueSession(
    sessions,
    { subjectId, email: registration.email },
    sessionExt,
  );

  yield* registerSession(issued);
  yield* expireSecurityCookie(RegistrationSecurity);
  yield* Effect.logInfo("Registration completed; session issued").pipe(
    Effect.annotateLogs({
      "auth.method": "email_otp",
      "auth.outcome": "registration_completed",
      subjectId,
      email: registration.email,
      expiresAt: DateTime.formatIso(issued.summary.expiresAt),
    }),
  );

  return issued.summary;
});

export const establishSessionFromRegistration = establishSessionFromRegistrationWith();

/**
 * Everything the auth group needs at the HTTP boundary: handlers plus the
 * middleware implementations. Requires `EmailOtp`, `PasswordAuth`, and
 * `AuthSession`.
 */
export const layerAuthHttp = <
  ApiId extends string,
  Groups extends HttpApiGroup.Constraint,
  Self = never,
  Id extends string = string,
  A = never,
>(
  api: HttpApi.HttpApi<ApiId, Groups> & NoInfer<RequiresAuthGroup<Groups>>,
  sessionExt?: AuthSessionWithExtClass<Self, Id, A>,
) =>
  layerAuthHandlers(api, sessionExt).pipe(
    Layer.provide(ChallengeMiddlewareLayer),
    Layer.provideMerge(Layer.mergeAll(SessionMiddlewareLayer, RegistrationMiddlewareLayer)),
  );

const withSession = <Self, Id extends string, A>(
  sessionExt: AuthSessionWithExtClass<Self, Id, A>,
) => {
  const layerHandlers = <ApiId extends string, Groups extends HttpApiGroup.Constraint>(
    api: HttpApi.HttpApi<ApiId, Groups> & NoInfer<RequiresAuthGroup<Groups>>,
  ) => layerAuthHandlers(api, sessionExt);

  const layer = <ApiId extends string, Groups extends HttpApiGroup.Constraint>(
    api: HttpApi.HttpApi<ApiId, Groups> & NoInfer<RequiresAuthGroup<Groups>>,
  ) => layerAuthHttp(api, sessionExt);

  const establishSessionFromRegistration = Effect.gen(function* () {
    const sessionsWithExt = yield* sessionExt;

    return yield* establishSessionFromRegistrationWith(sessionsWithExt);
  });

  return { layerHandlers, layer, establishSessionFromRegistration } as const;
};

/**
 * Binds an app-typed session declaration to extension-aware HTTP handlers and
 * registration issuance while retaining runtime services as Effect requirements.
 */
export const AuthHttp = {
  withSession,
} as const;
