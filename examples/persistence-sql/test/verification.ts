import { BunHttpServer, BunRuntime, BunServices } from "@effect/platform-bun";
import { Client, Http } from "@yielded/auth";
import { CompromisedPasswords } from "@yielded/auth/Password";
import { EmailProofDelivery, type ProofDeliveryMessage } from "@yielded/auth/Proofs";
import { Config, ConfigProvider, Effect, FileSystem, Layer, Redacted } from "effect";
import { HttpRouter } from "effect/unstable/http";

import { AppAuth } from "../../shared/account/auth";
import { AuthApi } from "../../shared/account/contract";
import { DatabaseLive, KeysLive } from "../src/data";
import { AuthLive } from "../src/live";

const assert: (condition: unknown, message: string) => asserts condition = (condition, message) => {
  if (!condition) throw new Error(message);
};

const origin = "http://localhost:4183";

// Exercise the public account flow that needs joined email rows and their column codecs.
const program = Effect.gen(function* () {
  const fs = yield* FileSystem.FileSystem;
  const directory = yield* fs.makeTempDirectoryScoped();

  const dialect = yield* Config.Literals(["sqlite", "pg"], "PERSISTENCE_DIALECT").pipe(
    Config.withDefault("sqlite"),
  );

  const messages: ProofDeliveryMessage[] = [];

  const delivery = EmailProofDelivery.layer({ vendorId: "test", idempotencyMillis: 0 }, (message) =>
    Effect.sync(() => {
      messages.push(message);

      return { _tag: "Accepted" } as const;
    }),
  );

  const application = AuthLive.pipe(
    Layer.provide([
      DatabaseLive,
      KeysLive,
      delivery,
      Layer.succeed(CompromisedPasswords, { check: () => Effect.succeed({ _tag: "Allowed" }) }),
    ]),
    Layer.provide(
      Layer.succeed(
        ConfigProvider.ConfigProvider,
        ConfigProvider.fromUnknown({ AUTH_DATA_DIR: directory, PERSISTENCE_DIALECT: dialect }),
      ),
    ),
    Layer.provide(BunServices.layer),
  );

  const routes = Http.make(AppAuth, {
    origin,
    cookie: { secure: false, prefix: "sql-example-" },
  })
    .routes()
    .pipe(Layer.provide(application), Layer.provide(BunHttpServer.layerHttpServices));

  const web = yield* Effect.acquireRelease(
    Effect.sync(() => HttpRouter.toWebHandler(routes, { disableLogger: true })),
    (server) => Effect.promise(() => server.dispose()),
  );

  const cookies = new Map<string, string>();

  const fetch: typeof globalThis.fetch = async (input, init) => {
    const request = new Request(input, init);
    const headers = new Headers(request.headers);

    headers.set("origin", origin);
    headers.set("cookie", [...cookies].map(([name, value]) => `${name}=${value}`).join("; "));
    const response = await web.handler(new Request(request, { headers }));

    for (const header of response.headers.getSetCookie()) {
      const pair = header.split(";", 1)[0];
      const equals = pair.indexOf("=");
      const name = pair.slice(0, equals);
      const value = pair.slice(equals + 1);

      if (value === "") cookies.delete(name);
      else cookies.set(name, value);
    }

    return response;
  };

  const call = (yield* Client.make(AuthApi, { baseUrl: origin, fetch }).make).auth;
  const email = "reader@example.invalid";
  const password = "violet39";

  yield* call.register({
    requestId: "registration",
    email,
    newPassword: password,
    registration: { displayName: "Reader" },
  });
  const signedIn = yield* call.passwordSignIn({ email, password });

  assert(
    signedIn._tag === "Authenticated" && !signedIn.session.claims.emailVerified,
    "Registration did not create an unverified account",
  );
  const base = { email, flowId: "confirm-email", commandId: "confirm-email" };

  yield* call.beginEmailAddress({ flowId: base.flowId });

  const receipt = yield* call.requestEmailVerification({
    ...base,
    requestId: "verification",
    locale: "en",
  });

  const message = messages.find((value) => value.reference.proofId === receipt.reference.proofId);

  assert(message !== undefined, "Verification did not reach the private delivery service");

  const proof = yield* call.verifyEmailAddress({
    ...base,
    reference: receipt.reference,
    secret: Redacted.value(message.secret),
  });

  const completed = yield* call.completeEmailVerification({
    ...base,
    continuationId: proof.continuation.continuationId,
  });

  const session = yield* call.getSession(undefined);

  assert(
    completed.invalidation === undefined &&
      session?.sessionId === signedIn.session.sessionId &&
      session.securityRevision === signedIn.session.securityRevision &&
      session.claims.emailVerified &&
      session.claims.email === email,
    "SQL email confirmation failed to preserve and update the current session",
  );
  yield* call.signOut(undefined);
  const verified = yield* call.passwordSignIn({ email, password });

  assert(
    verified._tag === "Authenticated" && verified.session.claims.emailVerified,
    "Email confirmation was not durable",
  );
  yield* Effect.log(`Email confirmation and session continuity passed on ${dialect}.`);
});

if (import.meta.main)
  BunRuntime.runMain(program.pipe(Effect.scoped, Effect.provide(BunServices.layer)));
