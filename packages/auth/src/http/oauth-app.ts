import { Cause, type Context, DateTime, Duration, Effect, Layer, Redacted, Schema } from "effect";
import { Cookies, HttpRouter, HttpServerRequest, HttpServerResponse } from "effect/unstable/http";

import { reportAuthFailure } from "../internal/diagnostics";
import type { ConnectionReference, SessionVerifier, Workflow } from "../oauth/app/models";
import { OAuthRejected, OAuthUnavailable } from "../oauth/signInErrors";
import { type AuthCredentialCommand, validateCredentialCommands } from "../operations/credentials";

export const binding = <const Id extends string>(id: Id) => ({
  paths: {
    signIn: `/auth/${id}/sign-in`,
    callback: `/auth/${id}/callback`,
    session: `/auth/${id}/session`,
    signOut: `/auth/${id}/sign-out`,
  } as const,
  cookieName: `yielded-${id}-session`,
  bindingName: `yielded-${id}-flow`,
});

const responseHeaders = { "cache-control": "no-store", "referrer-policy": "no-referrer" };

const unavailable = () =>
  new Response("Authentication is temporarily unavailable. Start a new sign-in.", {
    status: 503,
    headers: responseHeaders,
  });

/** Browser delivery belongs here; the workflow only returns private credential commands. */
export const makeHandler = <Session extends ConnectionReference>(
  app: { readonly Session: Schema.Codec<Session, unknown, never, never> },
  workflow: Pick<Workflow<NoInfer<Session>>, "begin" | "complete">,
  sessions: SessionVerifier<NoInfer<Session>>,
  config: ReturnType<typeof binding> & { readonly origin: string },
) => {
  const { paths, cookieName, bindingName } = config;

  const cookie = (name: string, value: string, age: number) =>
    Cookies.serializeCookie(
      Cookies.makeCookieUnsafe(name, value, {
        path: "/",
        httpOnly: true,
        sameSite: "lax",
        secure: config.origin.startsWith("https:"),
        maxAge: Duration.millis(Math.max(0, age)),
      }),
    );

  const deliver = Effect.fn("OAuthApp.deliver")(function* (
    headers: Headers,
    commands: ReadonlyArray<AuthCredentialCommand>,
  ) {
    const checked = yield* validateCredentialCommands(commands);
    const time = DateTime.toEpochMillis(yield* DateTime.now);

    for (const command of checked) {
      if (command.slot !== "session" && command.slot !== "request-binding")
        return yield* OAuthUnavailable.make({});
      headers.append(
        "set-cookie",
        cookie(
          command.slot === "session" ? cookieName : bindingName,
          command._tag === "Issue" ? Redacted.value(command.credential) : "",
          command._tag === "Issue" ? command.expiresAtMillis - time : 0,
        ),
      );
    }
  });

  return Effect.fn("OAuthApp.handle")(
    function* (request: Request) {
      const url = new URL(request.url);
      const cookies = HttpServerRequest.fromWeb(request).cookies;
      const headers = new Headers(responseHeaders);

      if (url.origin !== config.origin) return new Response(null, { status: 400, headers });
      if (request.method === "GET" && url.pathname === paths.signIn) {
        const result = yield* workflow.begin(url.searchParams.get("returnTo") ?? undefined);

        yield* deliver(headers, result.credentialCommands);
        headers.set("location", Redacted.value(result.value.authorizationUrl));

        return new Response(null, { status: 302, headers });
      }
      if (request.method === "GET" && url.pathname === paths.callback) {
        const binding = cookies[bindingName];

        if (binding === undefined) return yield* OAuthRejected.make({});
        const result = yield* workflow.complete(Redacted.make(binding), url.searchParams);

        yield* deliver(headers, result.credentialCommands);
        headers.set("location", `${config.origin}${result.value.returnTarget}`);

        return new Response(null, { status: 302, headers });
      }
      if (request.method === "GET" && url.pathname === paths.session) {
        const credential = cookies[cookieName];

        if (credential === undefined) return new Response(null, { status: 401, headers });
        const session = yield* sessions.verify(Redacted.make(credential));

        const json = yield* Schema.encodeEffect(Schema.fromJsonString(app.Session))(session).pipe(
          Effect.mapError(() => OAuthUnavailable.make({})),
        );

        headers.set("content-type", "application/json");

        return new Response(json, { headers });
      }
      if (request.method === "POST" && url.pathname === paths.signOut) {
        if (request.headers.get("origin") !== config.origin) return yield* OAuthRejected.make({});
        headers.append("set-cookie", cookie(cookieName, "", 0));

        return new Response(null, { status: 204, headers });
      }

      return new Response(null, { status: 404, headers });
    },
    (effect) =>
      effect.pipe(
        Effect.catchTag("SessionInvalid", () =>
          Effect.succeed(new Response(null, { status: 401, headers: responseHeaders })),
        ),
        Effect.catchTag("OAuthUnavailable", () => Effect.succeed(unavailable())),
        Effect.catchCause((cause) => {
          if (Cause.hasInterrupts(cause)) return Effect.interrupt;
          if (Cause.hasDies(cause))
            return reportAuthFailure("http", cause).pipe(Effect.as(unavailable()));

          return Effect.succeed(
            new Response("Authentication could not be completed. Start a new sign-in.", {
              status: 400,
              headers: responseHeaders,
            }),
          );
        }),
      ),
  );
};

export const routes = <I>(
  service: Context.Key<I, { readonly handle: (request: Request) => Effect.Effect<Response> }>,
  paths: ReturnType<typeof binding>["paths"],
) =>
  Layer.unwrap(
    Effect.gen(function* () {
      const app = yield* service;

      const route = (path: `/${string}`) =>
        HttpRouter.add(
          "*",
          path,
          Effect.gen(function* () {
            const request = yield* HttpServerRequest.HttpServerRequest;

            return HttpServerResponse.fromWeb(
              yield* app.handle(yield* HttpServerRequest.toWeb(request)),
            );
          }),
        );

      return Layer.mergeAll(
        route(paths.signIn),
        route(paths.callback),
        route(paths.session),
        route(paths.signOut),
      );
    }),
  );
