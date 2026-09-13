import { Auth } from "@yielded/auth";
import * as GitHub from "@yielded/auth/GitHub";
import {
  makeConnectedModule,
  OAuthConnectedProfile,
  OAuthConnectedTokenProtector,
  OAuthConnectedTransactionProtector,
  OAuthPermissionProfileKey,
  OAuthReturnTargets,
  OAuthTransactionProtector,
  OAuthUnavailable,
  type OAuthGrantId,
  type OAuthTransactionKeyring,
} from "@yielded/auth/OAuth";
import type { AuthInvocation } from "@yielded/auth/Operations";
import type { SubjectId } from "@yielded/auth/Schema";
import type { SessionSigningKeyring } from "@yielded/auth/Sessions";
import { OAuth } from "@yielded/auth/strategies";
import { layerWebCrypto } from "@yielded/auth/WebCrypto";
import { Context, Effect, Layer, Schema, Stream } from "effect";
import type { HttpClientResponse } from "effect/unstable/http";
import { FetchHttpClient, HttpClient, HttpClientRequest } from "effect/unstable/http";

// Application authority is local. Neither registration data nor Claims needs email.
const Claims = Schema.Struct({ role: Schema.Literal("member"), displayName: Schema.String });

const Registration = Schema.Struct({
  displayName: Schema.NonEmptyString.check(Schema.isMaxLength(128)),
});

const entryPolicy = {
  generation: 1,
  lifetimeMillis: 60_000,
  claimLifetimeMillis: 30_000,
  retentionMillis: 120_000,
  settlementTimeoutMillis: 5_000,
};

export class GitHubAuth extends Auth.Service<GitHubAuth>()("example/GitHubAuth", {
  claims: Claims,
  sessionNamespace: "example/github-sessions",
  strategies: {
    github: OAuth.makeRegistration({
      namespace: "example/github-login",
      policy: entryPolicy,
      registration: Registration,
      registrationPolicy: {
        lifetimeMillis: 60_000,
        maximumVerificationAgeMillis: 60_000,
        retentionMillis: 120_000,
      },
    }),
  },
  defaultStrategy: "github",
}) {}

export const githubSessions = GitHubAuth.sessions;
export const githubSignIn = GitHubAuth.strategies.github;
export const githubRegistration = githubSignIn.registration;

export class GitHubReferenceAccounts extends Context.Service<
  GitHubReferenceAccounts,
  { readonly claims: (subjectId: SubjectId) => Effect.Effect<typeof Claims.Type, OAuthUnavailable> }
>()("example/GitHubReferenceAccounts") {}

const claimsLayer = Layer.effect(
  githubSignIn.ClaimsForOAuth,
  Effect.gen(function* () {
    const { claims } = yield* GitHubReferenceAccounts;

    return githubSignIn.ClaimsForOAuth.of({
      resolve: (credential, verified) =>
        claims(credential.revision.subjectId).pipe(
          Effect.map((local) => ({
            ...local,
            displayName: verified.profile?.displayName ?? local.displayName,
          })),
        ),
    });
  }),
);

/** The host supplies actual persistence/registration authority, authentication
 * authority, pending-proof persistence and lifecycle hooks to the returned Layer.
 * Registration atomically provisions a new local subject; it never merges email. */
export const githubSignInLayer = (input: {
  readonly registration: GitHub.Registration;
  readonly bindingKeys: SessionSigningKeyring;
  readonly transactionKeys: OAuthTransactionKeyring;
  readonly sessionKeys: SessionSigningKeyring;
}) => {
  const shared = Layer.mergeAll(
    GitHub.layer(input.registration),
    Auth.RequestBindingConfig.layer({
      generation: 1,
      lifetimeMillis: 120_000,
      keyring: input.bindingKeys,
    }),
    OAuthTransactionProtector.xchacha20poly1305(input.transactionKeys),
    OAuthReturnTargets.exactRoutes(["/account"]),
    claimsLayer,
    githubSessions.statelessLayer(
      {
        issuer: "example",
        audience: "example",
        generation: 1,
        idleLifetimeMillis: 60_000,
        absoluteLifetimeMillis: 300_000,
        renewalIntervalMillis: 30_000,
        maximumIssuedAbsoluteLifetimeMillis: 300_000,
        maximumTokenBytes: 16_384,
        requireImmediateInvalidation: false,
      },
      input.sessionKeys,
    ),
  );

  const completion = githubSessions
    .completionLayer({ pendingLifetimeMillis: 60_000, attemptLimit: 3 })
    .pipe(Layer.provide(shared));

  return GitHubAuth.layer.pipe(
    Layer.provide(Layer.merge(shared, completion)),
    Layer.provide(layerWebCrypto),
  );
};

const decodeUserProfile = Schema.decodeEffect(Schema.fromJsonString(GitHub.GitHubUserProfile));

const readUserProfile = Effect.fn("example.GitHub.readUserProfile")(
  function* (response: HttpClientResponse.HttpClientResponse) {
    let bytes = 0;

    const body = yield* response.stream.pipe(
      Stream.mapEffect((chunk) => {
        bytes += chunk.byteLength;

        return bytes > 1024 * 1024 ? Effect.fail(OAuthUnavailable.make({})) : Effect.succeed(chunk);
      }),
      Stream.decodeText(),
      Stream.runFold(
        () => "",
        (text, chunk) => text + chunk,
      ),
    );

    return yield* decodeUserProfile(body);
  },
  Effect.mapError(() => OAuthUnavailable.make({})),
);

/** Optional API connection: a distinct module/binder and independent action
 * verifier. This has no session strategy, Claims resolver or login mutation.
 * Its sole sample capability is GET /user, requiring only read:user. */
export const githubProfileConnection = (input: {
  readonly registration: GitHub.Registration;
  readonly bindingKeys: SessionSigningKeyring;
  readonly transactionKeys: OAuthTransactionKeyring;
  readonly tokenKeys: OAuthTransactionKeyring;
}) => {
  const profile = OAuthConnectedProfile.make({
    key: OAuthPermissionProfileKey.make("github-profile"),
    generation: 1,
    issuance: "active",
    provider: GitHub.gitHubOAuthAppProviderKey,
    clientRegistrationId: input.registration.clientId,
    scopes: ["read:user"],
    resources: [],
    retention: "access-and-refresh",
    maximumAccessLifetimeMillis: 8 * 60 * 60 * 1000,
    maximumRefreshLifetimeMillis: 30 * 24 * 60 * 60 * 1000,
    refreshAheadMillis: 60_000,
    refresh: "rotating",
    revocation: "cohort",
  });

  const connected = makeConnectedModule("example/github-api", {
    ...entryPolicy,
    profiles: [profile],
    maximumEvidenceAgeMillis: 60_000,
    refreshClaimLifetimeMillis: 30_000,
    useAdmissionLifetimeMillis: 5_000,
  });

  const shared = Layer.mergeAll(
    GitHub.layerConnected({ ...input.registration, profiles: [profile] }),
    connected.binding.signedLayer({
      generation: 1,
      lifetimeMillis: 120_000,
      keyring: input.bindingKeys,
    }),
    OAuthConnectedTransactionProtector.xchacha20poly1305(input.transactionKeys),
    OAuthConnectedTokenProtector.xchacha20poly1305(input.tokenKeys),
    OAuthReturnTargets.exactRoutes(["/account/connections"]),
  );

  const methods = Layer.mergeAll(
    connected.layer,
    connected.accessLayer,
    connected.maintenanceLayer,
  ).pipe(Layer.provide(shared), Layer.provide(layerWebCrypto));

  const readMyProfile = Effect.fn("example.GitHub.readMyProfile")(
    function* (caller: AuthInvocation, grantId: typeof OAuthGrantId.Type) {
      const access = yield* connected.ConnectedAccess;
      const http = yield* HttpClient.HttpClient;

      return yield* access.withAccessToken(caller, { grantId, profileKey: profile.key }, (token) =>
        http
          .execute(
            HttpClientRequest.get("https://api.github.com/user", {
              headers: {
                Accept: "application/vnd.github+json",
                "User-Agent": "effect-auth-reference",
                "X-GitHub-Api-Version": "2026-03-10",
              },
            }).pipe(HttpClientRequest.bearerToken(token)),
          )
          .pipe(
            Effect.flatMap((response) =>
              response.status === 200
                ? readUserProfile(response)
                : Effect.fail(OAuthUnavailable.make({})),
            ),
            Effect.timeout(10_000),
            Effect.mapError(() => OAuthUnavailable.make({})),
          ),
      );
    },
    Effect.provide(FetchHttpClient.layer),
    Effect.provideService(FetchHttpClient.RequestInit, { redirect: "manual", credentials: "omit" }),
  );

  return {
    profile,
    connected,
    methods,
    handlers: connected.handlersLayer.pipe(Layer.provide(methods)),
    readMyProfile,
  };
};
