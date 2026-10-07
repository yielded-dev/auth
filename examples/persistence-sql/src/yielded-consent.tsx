import { OAuthServer } from "@yielded/auth";
import { Effect, Layer } from "effect";
import { renderToStaticMarkup } from "react-dom/server";

export const consentLayer = (stylesheet: string, displayName: string) =>
  Layer.succeed(OAuthServer.ConsentRenderer, {
    render: (consent) =>
      Effect.sync(
        () =>
          "<!doctype html>" +
          renderToStaticMarkup(
            <html lang="en">
              <head>
                <meta charSet="utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                <title>{`Continue to ${consent.clientName} · Yielded`}</title>
                <link rel="stylesheet" href={stylesheet} />
              </head>
              <body>
                <main className="login-page">
                  <header>
                    <a className="wordmark" href="/oauth-settings">
                      <picture>
                        <source
                          media="(prefers-color-scheme: dark)"
                          srcSet="/brand/auth-paper.svg"
                        />
                        <img src="/brand/auth-ink.svg" alt="Yielded Auth" width="178" height="28" />
                      </picture>
                    </a>
                    <a className="login-back" href="/oauth-settings">
                      Manage your account ↗
                    </a>
                  </header>
                  <div className="login-content">
                    <section className="panel login-card">
                      <p className="eyebrow">{new URL(consent.redirectUri).host}</p>
                      <h1>Continue to {consent.clientName}</h1>
                      <p className="description">Signed in as {displayName}.</p>
                      <p className="hint">
                        {consent.clientName} is requesting access to your Yielded identity (
                        {consent.scopes.join(", ")}). Your GitHub credentials stay with Auth.
                      </p>
                      {new URL(consent.redirectUri).protocol === "http:" && (
                        <p className="notice">
                          This is a local application. Continue only if you started this sign-in.
                        </p>
                      )}
                      <form method="post" action={consent.action}>
                        <input type="hidden" name="csrf" value={consent.csrf} />
                        <button className="primary" name="decision" value="approve">
                          Continue to {consent.clientName} →
                        </button>
                        <button className="secondary" name="decision" value="deny">
                          Cancel
                        </button>
                      </form>
                      <a
                        className="text-button restart"
                        href={`${consent.loginPath}?select_account=1`}
                      >
                        Use another account
                      </a>
                    </section>
                  </div>
                  <footer>
                    <p>Your Yielded account. Each app keeps its own session.</p>
                  </footer>
                </main>
              </body>
            </html>,
          ),
      ),
  });
