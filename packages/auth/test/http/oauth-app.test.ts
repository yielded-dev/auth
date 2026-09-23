import { it } from "@effect/vitest";
import { Cause, Effect, Exit, Logger, Redacted, Schema } from "effect";
import { expect } from "vite-plus/test";

import { binding, makeHandler } from "../../src/http/oauth-app";
import { make } from "../../src/oauth/app/workflow";
import { OAuthRejected } from "../../src/oauth/signInErrors";

it.effect(
  "HTTP defects report safe diagnostics and return 503 while cancellation propagates",
  () => {
    const app = make("http-failure", { claims: Schema.Struct({}), returnTargets: ["/account"] });
    const config = { ...binding("http-failure"), origin: "https://app.example.com" };
    const logs: Array<string> = [];

    const logger = Logger.make((entry) =>
      logs.push(JSON.stringify(Logger.formatStructured.log(entry))),
    );

    // A local faulty provider result exercises delivery after the workflow has succeeded.
    const workflow: (typeof app.Service)["Service"] = {
      begin: () =>
        Effect.succeed({
          value: {
            authorizationUrl: Redacted.make("https://provider.example/\r\nprivate-provider-marker"),
          },
          credentialCommands: [],
        }),
      complete: () => Effect.die("unused fixture operation"),
      withAccessToken: () => Effect.die("unused fixture operation"),
      disconnect: () => Effect.die("unused fixture operation"),
    };

    const sessions: (typeof app.Sessions)["Service"] = {
      verify: () => Effect.die("unused fixture operation"),
    };

    const request = new Request(`${config.origin}${config.paths.signIn}`);

    return Effect.gen(function* () {
      const response = yield* makeHandler(app, workflow, sessions, config)(request);

      expect(response.status).toBe(503);
      expect(response.headers.getSetCookie()).toHaveLength(0);
      expect(logs).toHaveLength(1);
      expect(logs[0]).toContain("Auth http failed");
      expect(logs[0]).not.toContain("private-provider-marker");

      const rejected = makeHandler(
        app,
        { ...workflow, begin: () => Effect.fail(OAuthRejected.make({})) },
        sessions,
        config,
      );

      expect((yield* rejected(request)).status).toBe(400);

      const cancelled = makeHandler(
        app,
        { ...workflow, begin: () => Effect.interrupt },
        sessions,
        config,
      );

      const exit = yield* Effect.exit(cancelled(request));

      expect(Exit.isFailure(exit) && Cause.hasInterruptsOnly(exit.cause)).toBe(true);
      expect(logs).toHaveLength(1);
    }).pipe(Effect.provide(Logger.layer([logger])));
  },
);
