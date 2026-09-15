import { it as effectIt } from "@effect/vitest";
import { AuthSession } from "@yielded/auth/AuthSession";
import { AuthTokenCodec } from "@yielded/auth/AuthTokenCodec";
import { EmailOtp } from "@yielded/auth/EmailOtp";
import { AuthUnavailable } from "@yielded/auth/Errors";
import { Email, PendingRegistration, RegistrationId, SubjectId } from "@yielded/auth/Schema";
import { DateTime, Effect, FileSystem, Layer, Path, Redacted, Schema } from "effect";
import { Etag, HttpPlatform, HttpRouter } from "effect/unstable/http";
import { HttpApi, HttpApiBuilder, HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi";
import { afterAll, describe, expect } from "vite-plus/test";

import { SessionState } from "../../src/http/models";
import {
  CurrentSession,
  registrationHeaderName,
  SessionMiddleware,
  sessionCookieName,
} from "../../src/http/security";
import { resolveSessionState, SessionMiddlewareLayer } from "../../src/HttpServer";
import { layerCryptoDeterministic } from "../../src/testing/crypto";
import { layerKeyringTest } from "../../src/testing/keyring";

// Regression guard for the bearer session transport: native clients cannot
// carry the `Secure` session cookie over the plain-http dev API, so
// `SessionMiddleware` must authenticate `Authorization: Bearer <token>` with
// the same token the cookie transports. Before the bearer security was added,
// the bearer request below answered 401.

const subject = Schema.decodeSync(SubjectId)("actor-bearer-regression");
const registrationToken = "header-only-registration-token";

const registration = PendingRegistration.make({
  registrationId: Schema.decodeSync(RegistrationId)("10000000-0000-4000-8000-000000000001"),
  email: Schema.decodeSync(Email)("header-only@effect-auth.test"),
  purpose: "registration",
  issuedAt: DateTime.makeUnsafe("2026-08-11T20:00:00.000Z"),
  expiresAt: DateTime.makeUnsafe("2026-08-11T20:15:00.000Z"),
});

const AuthSessionLive = AuthSession.layer.pipe(
  Layer.provide(AuthTokenCodec.layerWebCrypto),
  Layer.provide(layerKeyringTest),
  Layer.provide(layerCryptoDeterministic()),
);

const EmailOtpLive = Layer.succeed(EmailOtp)({
  request: () => Effect.die("request is not used by this boundary test"),
  verify: () => Effect.die("verify is not used by this boundary test"),
  inspectRegistration: (token) =>
    Redacted.value(token) === registrationToken
      ? Effect.succeed(registration)
      : Effect.die("unexpected registration token"),
  completeRegistration: () => Effect.die("completeRegistration is not used by this boundary test"),
});

const WhoamiEndpoint = HttpApiEndpoint.get("whoami", "/whoami", {
  success: Schema.String,
}).middleware(SessionMiddleware);

const TestApi = HttpApi.make("bearer-regression").add(
  HttpApiGroup.make("secure").add(WhoamiEndpoint),
);

const SessionStateEndpoint = HttpApiEndpoint.get("sessionState", "/session-state", {
  success: SessionState,
  error: AuthUnavailable,
});

const SessionStateApi = HttpApi.make("registration-header-regression").add(
  HttpApiGroup.make("public").add(SessionStateEndpoint),
);

const SecureHandlers = HttpApiBuilder.group(TestApi, "secure", (handlers) =>
  Effect.succeed(
    handlers.handle("whoami", () => Effect.map(CurrentSession, (claims) => claims.sub)),
  ),
);

const SessionStateHandlers = HttpApiBuilder.group(SessionStateApi, "public", (handlers) =>
  Effect.gen(function* () {
    const emailOtp = yield* EmailOtp;
    const sessions = yield* AuthSession;

    const currentSessionState = resolveSessionState.pipe(
      Effect.provideService(EmailOtp, emailOtp),
      Effect.provideService(AuthSession, sessions),
    );

    return handlers.handle("sessionState", () => currentSessionState);
  }),
);

const { dispose, handler } = HttpRouter.toWebHandler(
  HttpApiBuilder.layer(TestApi).pipe(
    Layer.provide(SecureHandlers),
    Layer.provide(SessionMiddlewareLayer),
    Layer.provide(AuthSessionLive),
    Layer.provide(Layer.mergeAll(HttpPlatform.layer, Etag.layerWeak, Path.layer)),
    Layer.provide(FileSystem.layerNoop({})),
  ),
);

const sessionStateApp = HttpRouter.toWebHandler(
  HttpApiBuilder.layer(SessionStateApi).pipe(
    Layer.provide(SessionStateHandlers),
    Layer.provide(AuthSessionLive),
    Layer.provide(EmailOtpLive),
    Layer.provide(Layer.mergeAll(HttpPlatform.layer, Etag.layerWeak, Path.layer)),
    Layer.provide(FileSystem.layerNoop({})),
  ),
);

afterAll(() => {
  dispose();
  sessionStateApp.dispose();
});

const issueSessionToken = Effect.flatMap(AuthSession, (sessions) => sessions.issue(subject)).pipe(
  Effect.provide(AuthSessionLive),
);

describe("bearer session transport", () => {
  effectIt.live("authenticates a session-protected endpoint from the bearer header alone", () =>
    Effect.gen(function* () {
      const issued = yield* issueSessionToken;

      // No cookie jar anywhere in this request: the header is the only credential.
      const response = yield* Effect.promise(() =>
        handler(
          new Request("http://bearer.test/whoami", {
            headers: { authorization: `Bearer ${issued.token}` },
          }),
        ),
      );

      const body = yield* Effect.promise(() => response.json());

      expect(response.status).toBe(200);
      expect(body).toBe(subject);
    }),
  );

  effectIt.live("keeps authenticating the session cookie", () =>
    Effect.gen(function* () {
      const issued = yield* issueSessionToken;

      const response = yield* Effect.promise(() =>
        handler(
          new Request("http://bearer.test/whoami", {
            headers: { cookie: `${sessionCookieName}=${issued.token}` },
          }),
        ),
      );

      expect(response.status).toBe(200);
    }),
  );

  effectIt.live("still rejects requests carrying neither transport", () =>
    Effect.gen(function* () {
      const response = yield* Effect.promise(() =>
        handler(new Request("http://bearer.test/whoami")),
      );

      expect(response.status).toBe(401);
    }),
  );
});

describe("registration header transport", () => {
  effectIt.live("resolves pending registration from the header without a cookie", () =>
    Effect.gen(function* () {
      const response = yield* Effect.promise(() =>
        sessionStateApp.handler(
          new Request("http://registration.test/session-state", {
            headers: { [registrationHeaderName]: registrationToken },
          }),
        ),
      );

      const body = yield* Effect.promise(() => response.json());

      expect(response.status).toBe(200);
      expect(body).toMatchObject({
        _tag: "RegistrationRequired",
        email: registration.email,
      });
    }),
  );
});
