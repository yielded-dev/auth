import { RegistryContext, useAtom, useAtomValue } from "@effect/atom-react";
import { Identity, OAuth, Operations } from "@yielded/auth";
import { Cause, Schema } from "effect";
import { AtomRegistry, type AsyncResult } from "effect/reactivity";
import { useState } from "react";
import { createRoot } from "react-dom/client";

import {
  auth,
  begin,
  complete,
  cursor,
  linkedAccounts,
  notice,
  signOut,
  unlink,
} from "./oauth-settings-client";
import { CallbackExpired } from "./oauth-settings-contract";

import "../../shared/account/style.css";

function Failure({ result }: { readonly result: AsyncResult.AsyncResult<unknown, unknown> }) {
  if (result._tag !== "Failure") return null;
  const errors = result.cause.reasons.filter(Cause.isFailReason).map((reason) => reason.error);

  const message = errors.some(Schema.is(Identity.LastSignInMethod))
    ? "Keep at least one sign-in method. Link another account before removing this one."
    : errors.some(Schema.is(Identity.IdentityConflict))
      ? "That provider identity belongs to another account. Choose a different identity at the provider, or sign in to the account that already owns it."
      : errors.some(Schema.is(OAuth.OAuthActionRequired)) ||
          errors.some(Schema.is(Operations.AuthenticationRequired))
        ? "Sign in again to confirm it is you, then retry this account change."
        : errors.some(Schema.is(CallbackExpired)) || errors.some(Schema.is(OAuth.OAuthRejected))
          ? "This attempt is expired, already used, or does not match this browser. Start again; use a linked identity when signing in."
          : "The request could not be confirmed. Check your sign-in methods before starting a new attempt; do not replay the callback.";

  return (
    <p className="notice error" role="alert">
      {message}
    </p>
  );
}

function Settings() {
  const session = useAtomValue(auth.session);
  const [beginResult, start] = useAtom(begin);
  const completion = useAtomValue(complete);
  const [outResult, out] = useAtom(signOut);
  const message = useAtomValue(notice);
  const demo = document.body.dataset.demo === "true";
  const signedIn = session._tag === "Success" ? session.value : null;
  const busy = beginResult.waiting || completion.waiting || outResult.waiting;

  return (
    <main>
      <header>
        <a className="wordmark" href="/oauth-settings">
          <span>y</span>yielded<span className="wordmark-divider">/</span>auth
        </a>
        <span className="local-indicator">
          {demo ? "SIMULATED PROVIDER · LOCAL ONLY" : "STRAVA · ACCOUNT SETTINGS"}
        </span>
      </header>
      <section className="intro">
        <p className="eyebrow">EXAMPLE 03 / OAUTH</p>
        <h1>
          Your ways <span>to sign in.</span>
        </h1>
        <p>Link an identity you control. Keep a way back into your account.</p>
      </section>
      {message && (
        <p className="notice success" role="status">
          {message}
        </p>
      )}
      <Failure result={completion} />
      <Failure result={beginResult} />
      <Failure result={outResult} />
      <div className="workspace">
        <section className="panel sign-in">
          <h2>{signedIn ? "Account settings" : "Sign in"}</h2>
          {session._tag === "Initial" || session.waiting ? (
            <p role="status">Checking your session…</p>
          ) : signedIn ? (
            <>
              <p className="description">Signed in as {signedIn.claims.displayName}.</p>
              <p className="hint">
                Account changes require sign-in within the last five minutes. Linking keeps this
                session; removing a method signs out every session.
              </p>
              <button className="primary" disabled={busy} onClick={() => start("link")}>
                Link another account <span>→</span>
              </button>
              <div className="button-row">
                <button className="secondary" disabled={busy} onClick={() => start("sign-in")}>
                  Sign in again
                </button>
                <button className="secondary" disabled={busy} onClick={() => out()}>
                  Sign out
                </button>
              </div>
            </>
          ) : (
            <>
              <p className="description">Use an identity already linked to this account.</p>
              {demo && (
                <p className="hint">
                  Start with Demo 123. Demo 456 is available to link; Demo 789 belongs to a
                  different account.
                </p>
              )}
              <button className="primary submit" disabled={busy} onClick={() => start("sign-in")}>
                Sign in with Strava <span>→</span>
              </button>
              <Failure result={session} />
            </>
          )}
        </section>
        {signedIn ? (
          <Links />
        ) : (
          <section className="panel welcome">
            <p className="eyebrow">LOGIN IDENTITIES</p>
            <h2>
              One account.
              <br />
              More ways in.
            </h2>
            <p>
              After signing in, see the identities that can open your account, add another, or
              remove one you no longer use.
            </p>
            <p className="hint">
              Provider API grants are separate. This example keeps no provider access tokens.
            </p>
          </section>
        )}
      </div>
      <footer>
        <p>Effect Atom · direct Effect SQL · private HttpOnly credentials</p>
        <p>{demo ? "No external provider validation" : "Provider consent opens at Strava"}</p>
      </footer>
    </main>
  );
}

function Links() {
  const result = useAtomValue(linkedAccounts);
  const [removal, remove] = useAtom(unlink);
  const [page, setPage] = useAtom(cursor);
  const [confirm, setConfirm] = useState<string | null>(null);

  return (
    <section className="panel session-panel">
      <div className="section-heading">
        <h2>Linked sign-in identities</h2>
        <span className="badge active">LOGIN ACCESS</span>
      </div>
      <p className="description">These identities can sign in to your account.</p>
      <Failure result={result} />
      <Failure result={removal} />
      {result.waiting && <p role="status">Loading identities…</p>}
      {result._tag === "Success" && (
        <>
          <ul className="passkey-list">
            {result.value.items.map((item) => (
              <li key={item.credentialId}>
                <strong>
                  {item.provider} · {item.subject}
                </strong>
                <span>{item.issuer}</span>
                {confirm === item.credentialId ? (
                  <>
                    <p>
                      Remove this sign-in method? You will need to sign in with a remaining
                      identity.
                    </p>
                    <div className="button-row">
                      <button
                        className="secondary"
                        disabled={removal.waiting}
                        onClick={() => remove(item.credentialId)}
                      >
                        Confirm removal
                      </button>
                      <button
                        className="text-button"
                        disabled={removal.waiting}
                        onClick={() => setConfirm(null)}
                      >
                        Keep it
                      </button>
                    </div>
                  </>
                ) : (
                  <button
                    className="text-button"
                    disabled={removal.waiting}
                    onClick={() => setConfirm(item.credentialId)}
                  >
                    Remove {item.provider} {item.subject}
                  </button>
                )}
              </li>
            ))}
          </ul>
          {result.value.items.length === 0 && <p className="empty">No identities on this page.</p>}
          <div className="button-row">
            {page !== undefined && (
              <button className="secondary" onClick={() => setPage(undefined)}>
                First page
              </button>
            )}
            {result.value.cursor !== undefined && (
              <button className="secondary" onClick={() => setPage(result.value.cursor)}>
                Next page
              </button>
            )}
          </div>
        </>
      )}
    </section>
  );
}

const registry = AtomRegistry.make();
// Mount once outside React so StrictMode/rerenders cannot repeat code exchange.
const stopCompletion = registry.mount(complete);

registry.set(complete, undefined);
const root = document.getElementById("root");

if (root === null) throw new Error("Missing account settings root");
createRoot(root).render(
  <RegistryContext.Provider value={registry}>
    <Settings />
  </RegistryContext.Provider>,
);
addEventListener("pagehide", () => {
  stopCompletion();
  registry.dispose();
});
