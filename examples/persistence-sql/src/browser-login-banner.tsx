import { useAtom, useAtomValue } from "@effect/atom-react";
import { BrowserLogin, OperationHttpClient } from "@yielded/auth";
import { Effect, Layer, Redacted, Schema } from "effect";
import { FetchHttpClient } from "effect/http";
import { Atom } from "effect/reactivity";

import { handoff } from "../../shared/account/browser-login-contract";
import type { AccountClient } from "../../shared/account/client";

const runtime = Atom.runtime(
  OperationHttpClient.layer({
    baseUrl: window.location.origin,
    csrfHeader: "x-auth-csrf",
    csrfValue: "operation",
  }).pipe(Layer.provide(FetchHttpClient.layer)),
);

// React dispatches; the Effect owns confirmation and callback navigation.
const authorize = runtime.fn<string>()(
  Effect.fnUntraced(function* (attemptId) {
    const transport = yield* OperationHttpClient.Client;

    const result = yield* transport.call(handoff.routes.authorize, {
      attemptId,
      decision: "continue",
    });

    yield* Effect.sync(() => window.location.assign(Redacted.value(result.callbackUrl)));
  }),
);

export function BrowserLoginBanner({ client }: { readonly client: AccountClient }) {
  const attemptId = new URL(window.location.href).searchParams.get("attempt");
  const session = useAtomValue(client.auth.session);
  const [result, proceed] = useAtom(authorize);

  if (attemptId === null) return null;
  if (!Schema.is(BrowserLogin.Random)(attemptId))
    return <p role="alert">Invalid sign-in attempt. Return to the app and start again.</p>;
  const account = session._tag === "Success" ? session.value : null;

  return (
    <section className="panel sign-in" aria-label="Return to app">
      <h2>Sign in to the Yielded native example</h2>
      <p>
        {account
          ? `Continue as ${account.claims.displayName}, or sign out below to use another account.`
          : "Sign in below, then confirm the account to use in the app."}
      </p>
      {account && (
        <button className="primary" disabled={result.waiting} onClick={() => proceed(attemptId)}>
          Continue to app
        </button>
      )}
      {result._tag === "Failure" && (
        <p role="alert">
          This attempt could not complete. Return to the app to cancel it and start again.
        </p>
      )}
    </section>
  );
}
