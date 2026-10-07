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
                <title>Continue to {consent.clientName} · Yielded</title>
                <link rel="stylesheet" href={stylesheet} />
              </head>
              <body>
                <main>
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
                    <span className="local-indicator">YIELDED ACCOUNT</span>
                  </header>
                  <section className="intro">
                    <p className="eyebrow">SHARED SIGN-IN</p>
                    <h1>
                      Continue to <span>{consent.clientName}.</span>
                    </h1>
                    <p>One Yielded identity. Each app owns its own access and session.</p>
                  </section>
                  <section className="panel">
                    <h2>Continue as {displayName}</h2>
                    <p className="description">
                      {consent.clientName} will receive your Yielded account ID and display name.
                      Your GitHub credentials stay with Auth.
                    </p>
                    <p className="hint">
                      Account: {consent.subjectId} · Destination:{" "}
                      {new URL(consent.redirectUri).host}
                    </p>
                    {new URL(consent.redirectUri).protocol === "http:" && (
                      <p className="notice">
                        This is a local application. Continue only if you started this sign-in.
                      </p>
                    )}
                    <form method="post" action={consent.action}>
                      <input type="hidden" name="csrf" value={consent.csrf} />
                      <button className="primary submit" name="decision" value="approve">
                        Continue to {consent.clientName} →
                      </button>
                      <div className="button-row">
                        <button className="secondary" name="decision" value="deny">
                          Cancel
                        </button>
                        <a href={consent.loginPath}>Use another account</a>
                      </div>
                    </form>
                  </section>
                  <footer>
                    <p>Yielded Auth · Shared sign-in</p>
                    <a href="/oauth-settings">Manage your account ↗</a>
                  </footer>
                </main>
              </body>
            </html>,
          ),
      ),
  });
