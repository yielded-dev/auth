import { Auth, OAuth, Operations } from "@yielded/auth";
import { Console, Crypto, Effect, Redacted, Schema } from "effect";
import { HttpClient, HttpClientRequest } from "effect/http";
import { SqlClient } from "effect/sql";

import { DemoActionCodes } from "./oauth-demo-actions";
import { AppAuth, callbackId, profile } from "./oauth-lifecycle-model";

export class DemoFailure extends Schema.TaggedError<DemoFailure>()("DemoFailure", {
  step: Schema.String,
}) {}

const state = (url: Redacted.Redacted<string>) =>
  Schema.decodeUnknownEffect(Schema.NonEmptyString)(
    new URL(Redacted.value(url)).searchParams.get("state"),
  );

const privateDelivery = () => {
  const credentials: Partial<Record<Operations.CredentialSlot, Redacted.Redacted<string>>> = {};

  const sink: Operations.AuthCredentialCommandSink = (commands) =>
    Effect.sync(() => {
      for (const command of commands) {
        if (command._tag === "Issue") credentials[command.slot] = command.credential;
        else delete credentials[command.slot];
      }
    });

  const call = <A, E, R>(
    effect: Effect.Effect<A, E, R>,
    invocation: Operations.AuthInvocation = Operations.guest,
  ) =>
    effect.pipe(
      Effect.provideService(Auth.AuthRequest, {
        invocation,
        credentials: { ...credentials },
        credentialCommandSink: sink,
      }),
    );

  const read = (slot: Operations.CredentialSlot) => {
    const value = credentials[slot];

    return value === undefined
      ? Effect.fail(DemoFailure.make({ step: `missing private ${slot}` }))
      : Effect.succeed(Redacted.value(value));
  };

  return { credentials, call, read };
};

/** Public Auth methods execute all transitions. This native CLI owns private
 * credential delivery; it never serializes request binders, action codes or tokens. */
export const exercise = Effect.gen(function* () {
  const auth = yield* AppAuth;
  const crypto = yield* Crypto.Crypto;
  const sql = yield* SqlClient.SqlClient;
  const actions = yield* DemoActionCodes;
  const delivery = privateDelivery();
  const runId = yield* crypto.randomUUIDv4;

  const start = yield* delivery.call(
    auth.signIn({ provider: profile.provider, callbackId, returnTarget: "/account" }),
  );

  const complete = yield* delivery.call(
    auth.completeSignIn({
      requestBinding: yield* delivery.read("request-binding"),
      flowId: start.flowId,
      provider: profile.provider,
      callbackId,
      response: {
        _tag: "Code",
        code: "123",
        state: yield* state(start.authorizationUrl),
        scope: "activity:read_all",
      },
    }),
  );

  if (
    !("completion" in complete) ||
    complete.completion._tag !== "Authenticated" ||
    complete.connection === undefined
  )
    return yield* DemoFailure.make({ step: "sign-in and retained grant" });
  const connection = complete.connection;
  const session = yield* delivery.call(auth.requireSession());

  const caller = {
    _tag: "Authenticated" as const,
    subjectId: session.subjectId,
    sessionId: session.sessionId,
    assurance: session.assurance,
  };

  const sessionToken = delivery.credentials.session;

  if (sessionToken === undefined)
    return yield* DemoFailure.make({ step: "private session delivery" });
  yield* Console.log(`sign-in: subject=${session.subjectId} grant=${connection.grantId}`);

  const linkedFlow = Operations.RequestBindingFlowId.make(`link-${runId}`);
  const linkedCommand = OAuth.OAuthCommandId.make(`link-${runId}`);

  const begin = yield* delivery.call(
    auth.linkAccount("accounts", {
      flowId: linkedFlow,
      commandId: linkedCommand,
      provider: profile.provider,
      callbackId,
      returnTarget: "/account",
      actionProof: Redacted.value(yield* actions.issue("link-begin", linkedCommand)),
    }),
    caller,
  );

  // A different upstream identity is linked, without changing the original sign-in identity.
  const linked = yield* delivery.call(
    auth.completeAccountLink("accounts", {
      requestBinding: yield* delivery.read("request-binding"),
      flowId: linkedFlow,
      provider: profile.provider,
      callbackId,
      response: {
        _tag: "Code",
        code: "456",
        state: yield* state(begin.authorizationUrl),
        scope: "activity:read_all",
      },
      actionProof: Redacted.value(yield* actions.issue("link-complete", linkedCommand)),
    }),
    caller,
  );

  if (linked._tag !== "Linked") return yield* DemoFailure.make({ step: "link completion" });

  const links =
    yield* sql`SELECT "credentialId" FROM oauth_login WHERE "subjectId" = ${session.subjectId} AND status = 'active'`;

  if (links.length !== 2) return yield* DemoFailure.make({ step: "linked login persisted" });
  yield* Console.log(`link: credential=${linked.credentialId}; active login links=${links.length}`);

  const listed = yield* delivery.call(auth.listAccountConnections({ limit: 20 }), caller);

  if (!listed.items.some((item) => item.grantId === connection.grantId))
    return yield* DemoFailure.make({ step: "retained grant list after linking" });
  yield* Console.log(`listAccountConnections: ${listed.items.length} retained grant(s)`);

  const unlinkCommand = OAuth.OAuthCommandId.make(`unlink-${runId}`);

  const unlinkInput = {
    commandId: unlinkCommand,
    credentialId: linked.credentialId,
    actionProof: Redacted.value(yield* actions.issue("unlink", unlinkCommand)),
  };

  yield* delivery.call(auth.unlinkAccount("accounts", unlinkInput), caller);
  // Exact durable replay reuses the command and does not consume another code.
  yield* delivery.call(auth.unlinkAccount("accounts", unlinkInput), caller);

  const remaining =
    yield* sql`SELECT "credentialId" FROM oauth_login WHERE "subjectId" = ${session.subjectId} AND status = 'active'`;

  if (remaining.length !== 1) return yield* DemoFailure.make({ step: "unlink durable replay" });
  yield* Console.log(
    `unlink: active login links=${remaining.length}; exact command replay accepted`,
  );

  const otherDelivery = privateDelivery();

  const registrationStart = yield* otherDelivery.call(
    auth.signIn("registration", {
      provider: profile.provider,
      callbackId,
      returnTarget: "/account",
    }),
  );

  // Generate an unused numeric provider ID, so repeated runs demonstrate new registration.
  const externalId = String(yield* crypto.randomIntBetween(1_000_000, 2_000_000_000));

  const registrationRequired = yield* otherDelivery.call(
    auth.completeSignIn("registration", {
      requestBinding: yield* otherDelivery.read("request-binding"),
      flowId: registrationStart.flowId,
      provider: profile.provider,
      callbackId,
      response: {
        _tag: "Code",
        code: externalId,
        state: yield* state(registrationStart.authorizationUrl),
        scope: "activity:read_all",
      },
    }),
  );

  if (!("_tag" in registrationRequired) || registrationRequired._tag !== "RegistrationRequired")
    return yield* DemoFailure.make({ step: "registration intent" });

  const registered = yield* otherDelivery.call(
    auth.register("registration", {
      requestBinding: yield* otherDelivery.read("request-binding"),
      credential: yield* otherDelivery.read("registration"),
      flowId: registrationStart.flowId,
      reference: registrationRequired.reference,
      commandId: `registration-${runId}`,
      registration: { displayName: "SQL OAuth demo" },
    }),
  );

  if (registered._tag !== "RegistrationAccepted")
    return yield* DemoFailure.make({ step: "registration" });

  const [registeredOwner] =
    yield* sql`SELECT "subjectId" FROM oauth_identity WHERE "externalSubject" = ${externalId} AND state = 'Owned'`;

  if (registeredOwner === undefined)
    return yield* DemoFailure.make({ step: "registered subject and identity commit" });
  yield* Console.log(
    `registration: subject=${yield* Schema.decodeUnknownEffect(Schema.String)(registeredOwner.subjectId)}`,
  );

  const registeredSignIn = yield* otherDelivery.call(
    auth.signIn("registration", {
      provider: profile.provider,
      callbackId,
      returnTarget: "/account",
    }),
  );

  const registeredSession = yield* otherDelivery.call(
    auth.completeSignIn("registration", {
      flowId: registeredSignIn.flowId,
      provider: profile.provider,
      callbackId,
      requestBinding: yield* otherDelivery.read("request-binding"),
      response: {
        _tag: "Code",
        code: externalId,
        state: yield* state(registeredSignIn.authorizationUrl),
        scope: "activity:read_all",
      },
    }),
  );

  if (!("completion" in registeredSession) || registeredSession.completion._tag !== "Authenticated")
    return yield* DemoFailure.make({ step: "registered user sign-in" });
  yield* Console.log(
    `registered sign-in: subject=${registeredSession.completion.session.subjectId}`,
  );

  return { caller, connection, sessionToken };
});

/** Run after closing and reopening the SQL client, using the privately retained
 * session credential and the original grant ID. No provider code exchange occurs. */
export const reopen = (saved: Effect.Success<typeof exercise>) =>
  Effect.gen(function* () {
    const auth = yield* AppAuth;

    const call: Auth.AuthRequest["Service"] = {
      invocation: Operations.guest,
      credentials: { session: saved.sessionToken },
      credentialCommandSink: () => Effect.void,
    };

    const session = yield* auth
      .requireSession()
      .pipe(Effect.provideService(Auth.AuthRequest, call));

    const caller = { ...saved.caller, subjectId: session.subjectId, assurance: session.assurance };

    const listed = yield* auth
      .listAccountConnections({ limit: 20 })
      .pipe(Effect.provideService(Auth.AuthRequest, { ...call, invocation: caller }));

    if (!listed.items.some((item) => item.grantId === saved.connection.grantId))
      return yield* DemoFailure.make({ step: "grant survived database reopen" });
    const access = yield* AppAuth.strategies.oauth.access.ConnectedAccess;
    const http = yield* HttpClient.HttpClient;

    const id = yield* access.withAccessToken(caller, saved.connection, (token) =>
      http
        .execute(
          HttpClientRequest.get("https://www.strava.com/api/v3/athlete").pipe(
            HttpClientRequest.bearerToken(token),
          ),
        )
        .pipe(
          Effect.flatMap((response) => response.json),
          Effect.flatMap(Schema.decodeUnknownEffect(Schema.Struct({ id: Schema.Int }))),
        ),
    );

    if (id.id !== 123) return yield* DemoFailure.make({ step: "decrypted grant token use" });
    yield* Console.log(
      `reopen: grant=${saved.connection.grantId}; native provider API token use athlete=${id.id}`,
    );
  });
