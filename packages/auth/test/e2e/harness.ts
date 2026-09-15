import { BunHttpServer, BunRuntime } from "@effect/platform-bun";
import { AuthKeyring, AuthTokenCodec } from "@yielded/auth/AuthTokenCodec";
import { layerOAuthPolicy } from "@yielded/auth/OAuth";
import { KeyId, SubjectId } from "@yielded/auth/Schema";
import { layerCryptoWeb } from "@yielded/auth/WebCrypto";
import { Duration, Effect, Layer, Option, Redacted, Schema } from "effect";
import {
  FetchHttpClient,
  HttpClient,
  HttpClientResponse,
  HttpRouter,
  HttpServerRequest,
  HttpServerResponse,
} from "effect/unstable/http";

import {
  githubOAuthProviderKey,
  makeGithubOAuthProvider,
} from "../../src/oauth/GithubOAuthProvider";
import { OAuth } from "../../src/oauth/OAuth";
import { OAuthConnectionStore } from "../../src/oauth/OAuthConnectionStore";
import { OAuthProviders } from "../../src/oauth/OAuthProviders";
import { OAuthStateStore } from "../../src/oauth/OAuthStateStore";

/**
 * Browser end-to-end harness for the OAuth workflow: the REAL `OAuth`
 * service, GitHub provider layer, token codec, and stores serve an "app" on
 * one port, while a second port runs a wire-faithful stand-in for GitHub's
 * user-to-server OAuth surface (consent redirect, form-encoded token
 * endpoint with 200-status error payloads, `/user`, and applications-API
 * revocation). Only the two GitHub hostnames are substituted — every
 * redirect, cookie-free callback, exchange, refresh, and revocation runs
 * over real HTTP, driven by a real browser.
 *
 * Run with `vp run --filter './packages/auth' e2e`, then open
 * http://localhost:4600. Access-token lifetime is deliberately a few seconds
 * so a browser session can watch a live refresh.
 */

const appPort = 4600;
const githubPort = 4601;
const appOrigin = `http://localhost:${appPort}`;
const githubOrigin = `http://localhost:${githubPort}`;
const redirectUri = `${appOrigin}/oauth/github/callback`;

const clientId = "Iv1.e2e-harness";
const clientSecret = "e2e-harness-client-secret";

/**
 * The subject stands in for the application session's actor; binding the
 * flow to a real signed-in session is the consuming app's middleware
 * concern, exercised by its own integration tests.
 */
const subject = Schema.decodeSync(SubjectId)("actor-e2e");

/** Seconds a fake access token lives; short enough to watch a refresh live. */
const accessTokenLifetimeSeconds = 8;

// --- Wire-faithful GitHub stand-in ---------------------------------------------

interface IssuedToken {
  readonly login: string;
  readonly id: number;
  readonly expiresAtMs: number;
}

const escapeHtml = (value: string) =>
  value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll('"', "&quot;");

const consentPage = (query: URLSearchParams) => {
  const fields = ["redirect_uri", "state"]
    .map(
      (name) => `<input type="hidden" name="${name}" value="${escapeHtml(query.get(name) ?? "")}">`,
    )
    .join("");

  return `<!doctype html><title>Authorize kommunikasie (stand-in)</title>
    <main style="font-family: system-ui; max-width: 26rem; margin: 4rem auto">
      <h1>Authorize <em>kommunikasie</em></h1>
      <p>GitHub stand-in consent screen for client <code>${escapeHtml(query.get("client_id") ?? "")}</code>.</p>
      <form method="post" action="/login/oauth/decision">${fields}
        <button name="decision" value="approve" id="authorize">Authorize</button>
        <button name="decision" value="deny" id="deny">Cancel</button>
      </form>
    </main>`;
};

const makeFakeGithubRoutes = () => {
  // Deterministic ids keep the evidence log legible; this is a stand-in, so
  // nothing here is secret.
  let sequence = 0;
  const pendingCodes = new Map<string, { readonly redirectUri: string }>();
  const accessTokens = new Map<string, IssuedToken>();
  const refreshTokens = new Map<string, { readonly login: string; readonly id: number }>();
  const user = { login: "octocat", id: 583_231 };

  const issueTokenResponse = () => {
    sequence += 1;
    const accessToken = `ghu_e2e_${sequence}`;
    const refreshToken = `ghr_e2e_${sequence}`;

    accessTokens.set(accessToken, {
      ...user,
      expiresAtMs: Date.now() + accessTokenLifetimeSeconds * 1000,
    });
    refreshTokens.set(refreshToken, user);

    return {
      access_token: accessToken,
      expires_in: accessTokenLifetimeSeconds,
      refresh_token: refreshToken,
      refresh_token_expires_in: 15_811_200,
      token_type: "bearer",
      scope: "",
    };
  };

  const authorize = Effect.gen(function* () {
    const request = yield* HttpServerRequest.HttpServerRequest;
    const query = new URL(request.url, githubOrigin).searchParams;

    yield* Effect.log("github: authorization request", {
      client_id: query.get("client_id"),
      redirect_uri: query.get("redirect_uri"),
      state: `${(query.get("state") ?? "").slice(0, 8)}…`,
    });
    if (query.get("client_id") !== clientId) {
      return HttpServerResponse.text("unknown client_id", { status: 404 });
    }

    return HttpServerResponse.html(consentPage(query));
  });

  const decision = Effect.gen(function* () {
    const request = yield* HttpServerRequest.HttpServerRequest;
    const form = new URLSearchParams(yield* Effect.orDie(request.text));
    const destination = new URL(form.get("redirect_uri") ?? "");
    const state = form.get("state") ?? "";

    destination.searchParams.set("state", state);
    if (form.get("decision") === "approve") {
      sequence += 1;
      const code = `code_e2e_${sequence}`;

      pendingCodes.set(code, { redirectUri: destination.origin + destination.pathname });
      destination.searchParams.set("code", code);
      yield* Effect.log("github: consent approved", { code });
    } else {
      destination.searchParams.set("error", "access_denied");
      destination.searchParams.set(
        "error_description",
        "The user has denied your application access.",
      );
      yield* Effect.log("github: consent denied");
    }

    return HttpServerResponse.redirect(destination.toString());
  });

  const token = Effect.gen(function* () {
    const request = yield* HttpServerRequest.HttpServerRequest;
    const form = new URLSearchParams(yield* Effect.orDie(request.text));
    const grantType = form.get("grant_type");

    if (form.get("client_id") !== clientId || form.get("client_secret") !== clientSecret) {
      yield* Effect.log("github: token request with bad client credentials", { grantType });

      // GitHub answers token-endpoint errors with status 200.
      return HttpServerResponse.jsonUnsafe({ error: "incorrect_client_credentials" });
    }
    if (grantType === "authorization_code") {
      const code = form.get("code") ?? "";
      const pending = pendingCodes.get(code);

      if (pending === undefined || pending.redirectUri !== form.get("redirect_uri")) {
        yield* Effect.log("github: code exchange rejected", { code });

        return HttpServerResponse.jsonUnsafe({ error: "bad_verification_code" });
      }
      pendingCodes.delete(code);
      const issued = issueTokenResponse();

      yield* Effect.log("github: code exchanged", {
        code,
        access_token: issued.access_token,
        refresh_token: issued.refresh_token,
      });

      return HttpServerResponse.jsonUnsafe(issued);
    }
    if (grantType === "refresh_token") {
      const refreshToken = form.get("refresh_token") ?? "";

      if (!refreshTokens.has(refreshToken)) {
        yield* Effect.log("github: refresh rejected", { refreshToken });

        return HttpServerResponse.jsonUnsafe({ error: "bad_refresh_token" });
      }
      refreshTokens.delete(refreshToken);
      const issued = issueTokenResponse();

      yield* Effect.log("github: token refreshed", {
        spent: refreshToken,
        access_token: issued.access_token,
        refresh_token: issued.refresh_token,
      });

      return HttpServerResponse.jsonUnsafe(issued);
    }

    return HttpServerResponse.jsonUnsafe({ error: "unsupported_grant_type" });
  });

  const identity = Effect.gen(function* () {
    const request = yield* HttpServerRequest.HttpServerRequest;
    const bearer = (request.headers.authorization ?? "").replace(/^Bearer /, "");
    const issued = accessTokens.get(bearer);

    if (issued === undefined || Date.now() >= issued.expiresAtMs) {
      yield* Effect.log("github: /user rejected", {
        token: bearer,
        reason: issued === undefined ? "unknown" : "expired",
      });

      return HttpServerResponse.jsonUnsafe({ message: "Bad credentials" }, { status: 401 });
    }
    yield* Effect.log("github: /user served", { token: bearer, login: issued.login });

    return HttpServerResponse.jsonUnsafe({ id: issued.id, login: issued.login, type: "User" });
  });

  const revoke = Effect.gen(function* () {
    const request = yield* HttpServerRequest.HttpServerRequest;
    const expected = `Basic ${btoa(`${clientId}:${clientSecret}`)}`;

    if (request.headers.authorization !== expected) {
      return HttpServerResponse.jsonUnsafe({ message: "Bad credentials" }, { status: 401 });
    }
    const body: unknown = JSON.parse(yield* Effect.orDie(request.text));

    const accessToken =
      typeof body === "object" && body !== null && "access_token" in body
        ? String(body.access_token)
        : "";

    accessTokens.delete(accessToken);
    yield* Effect.log("github: user access token revoked", { token: accessToken });

    return HttpServerResponse.empty({ status: 204 });
  });

  return Layer.mergeAll(
    HttpRouter.add("GET", "/login/oauth/authorize", authorize),
    HttpRouter.add("POST", "/login/oauth/decision", decision),
    HttpRouter.add("POST", "/login/oauth/access_token", token),
    HttpRouter.add("GET", "/user", identity),
    HttpRouter.add("DELETE", `/applications/${clientId}/token`, revoke),
  );
};

// --- The app under test ----------------------------------------------------------

const harnessKeyId = Schema.decodeSync(KeyId)("e2e-harness-key");

const AuthKeyringHarness = Layer.succeed(AuthKeyring)({
  activeKeyId: harnessKeyId,
  keys: [
    {
      keyId: harnessKeyId,
      secret: Redacted.make("effect-auth-e2e-harness-secret-0123456789abcdef"),
    },
  ],
});

/** Short refresh margin so the harness demonstrates both a fresh-token hit and a live refresh. */
const OAuthPolicyHarness = layerOAuthPolicy({
  accessTokenRefreshMargin: Duration.seconds(2),
});

const AppOAuthLive = OAuth.layer.pipe(
  Layer.provide(
    OAuthProviders.layer([
      makeGithubOAuthProvider({
        clientId,
        clientSecret: Redacted.make(clientSecret),
        webBaseUrl: githubOrigin,
        apiBaseUrl: githubOrigin,
      }),
    ]),
  ),
  Layer.provide(OAuthStateStore.layerMemory),
  Layer.provide(OAuthConnectionStore.layerMemory),
  Layer.provide(AuthTokenCodec.layerWebCrypto),
  Layer.provide(AuthKeyringHarness),
  Layer.provide(OAuthPolicyHarness),
  Layer.provideMerge(layerCryptoWeb),
  Layer.provideMerge(FetchHttpClient.layer),
);

const statusPage = Effect.gen(function* () {
  const oauth = yield* OAuth;
  const request = yield* HttpServerRequest.HttpServerRequest;
  const query = new URL(request.url, appOrigin).searchParams;
  const connection = yield* Effect.orDie(oauth.connection(githubOAuthProviderKey, subject));

  const banner = query.get("error")
    ? `<p id="banner" style="color:#b00">Flow failed: <code>${escapeHtml(query.get("error") ?? "")}</code></p>`
    : query.get("linked")
      ? `<p id="banner" style="color:#070">GitHub account linked.</p>`
      : "";

  const body = Option.match(connection, {
    onNone: () =>
      `<p id="status" data-linked="false">Not linked.</p>
       <p><a id="connect" href="/connect">Connect GitHub</a></p>`,
    onSome: (linked) =>
      `<p id="status" data-linked="true">Linked to <strong id="handle">${escapeHtml(
        Option.getOrElse(linked.identity.handle, () => "?"),
      )}</strong> (GitHub user id <span id="account-id">${escapeHtml(
        linked.identity.providerAccountId,
      )}</span>).</p>
       <p><a id="whoami" href="/whoami">Call GitHub /user with my token</a></p>
       <form method="post" action="/disconnect"><button id="disconnect">Disconnect</button></form>`,
  });

  return HttpServerResponse.html(
    `<!doctype html><title>effect-auth OAuth e2e</title>
     <main style="font-family: system-ui; max-width: 30rem; margin: 4rem auto">
       <h1>effect-auth OAuth e2e app</h1>${banner}${body}
     </main>`,
  );
});

const connect = Effect.gen(function* () {
  const oauth = yield* OAuth;

  const authorization = yield* Effect.orDie(
    oauth.begin({ provider: githubOAuthProviderKey, subjectId: subject, redirectUri }),
  );

  yield* Effect.log("app: begin issued state, redirecting to provider");

  return HttpServerResponse.redirect(authorization.url);
});

const callback = Effect.gen(function* () {
  const oauth = yield* OAuth;
  const request = yield* HttpServerRequest.HttpServerRequest;
  const params = Object.fromEntries(new URL(request.url, appOrigin).searchParams);

  return yield* oauth
    .complete({ provider: githubOAuthProviderKey, subjectId: subject, redirectUri, params })
    .pipe(
      Effect.map((connection) => {
        const handle = Option.getOrElse(connection.identity.handle, () => "?");

        return HttpServerResponse.redirect(`/?linked=1&login=${encodeURIComponent(handle)}`);
      }),
      Effect.tap(() => Effect.log("app: callback completed, connection stored")),
      Effect.catch((error) =>
        Effect.as(
          Effect.log("app: callback failed", { error: error._tag }),
          HttpServerResponse.redirect(`/?error=${encodeURIComponent(error._tag)}`),
        ),
      ),
    );
});

const whoami = Effect.gen(function* () {
  const oauth = yield* OAuth;
  const client = yield* HttpClient.HttpClient;

  return yield* oauth.accessToken(githubOAuthProviderKey, subject).pipe(
    Effect.flatMap((token) =>
      client
        .get(`${githubOrigin}/user`, {
          headers: { authorization: `Bearer ${Redacted.value(token)}` },
        })
        .pipe(
          Effect.flatMap(HttpClientResponse.filterStatusOk),
          Effect.flatMap((response) => response.json),
        ),
    ),
    Effect.map((githubUser) => HttpServerResponse.jsonUnsafe({ ok: true, githubUser })),
    Effect.catch((error) =>
      Effect.succeed(
        HttpServerResponse.jsonUnsafe(
          { ok: false, error: "_tag" in error ? error._tag : "UnexpectedError" },
          { status: 502 },
        ),
      ),
    ),
  );
});

const disconnect = Effect.gen(function* () {
  const oauth = yield* OAuth;

  yield* Effect.orDie(oauth.disconnect(githubOAuthProviderKey, subject));
  yield* Effect.log("app: disconnected");

  return HttpServerResponse.redirect("/");
});

const appRoutes = Layer.mergeAll(
  HttpRouter.add("GET", "/", statusPage),
  HttpRouter.add("GET", "/connect", connect),
  HttpRouter.add("GET", "/oauth/github/callback", callback),
  HttpRouter.add("GET", "/whoami", whoami),
  HttpRouter.add("POST", "/disconnect", disconnect),
);

// --- Entrypoint -------------------------------------------------------------------

const FakeGithubServer = HttpRouter.serve(makeFakeGithubRoutes()).pipe(
  Layer.provide(BunHttpServer.layer({ port: githubPort })),
);

const AppServer = HttpRouter.serve(appRoutes).pipe(
  Layer.provide(AppOAuthLive),
  Layer.provide(BunHttpServer.layer({ port: appPort })),
);

export const harness = Layer.mergeAll(FakeGithubServer, AppServer);

BunRuntime.runMain(Layer.launch(harness));
