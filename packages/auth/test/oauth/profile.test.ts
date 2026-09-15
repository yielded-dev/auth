import { it } from "@effect/vitest";
import { Auth, OAuth, Sessions } from "@yielded/auth";
import { coordinateCommit, LifecycleHooks } from "@yielded/auth/Hooks";
import { RequestBindingFlowId } from "@yielded/auth/Operations";
import { SubjectId, TokenDigest } from "@yielded/auth/Schema";
import { layerWebCrypto } from "@yielded/auth/WebCrypto";
import { DateTime, Effect, Encoding, Layer, Redacted, Schema } from "effect";
import { describe, expect } from "vite-plus/test";

import { normalizedGithubProfile } from "../fixtures/github-profile";
import { expectTag } from "../helpers/oauth";

const policy = {
  generation: 1,
  lifetimeMillis: 60_000,
  claimLifetimeMillis: 30_000,
  retentionMillis: 120_000,
  settlementTimeoutMillis: 5_000,
};

const registrationPolicy = {
  lifetimeMillis: 60_000,
  maximumVerificationAgeMillis: 60_000,
  retentionMillis: 120_000,
};

const AppAuth = Auth.make("test/ProfileAuth", {
  claims: Schema.Struct({ displayName: Schema.String }),
  sessions: Sessions.stateful(),
  strategies: {
    github: OAuth.makeRegistration({
      namespace: "test/profile",
      policy,
      registrationPolicy,
      registration: Schema.Struct({}),
    }),
  },
  defaultStrategy: "github",
});

const method = AppAuth.strategies.github;

const identity = {
  provider: OAuth.OAuthProviderKey.make("github"),
  issuer: OAuth.OAuthIssuer.make("https://github.com/login/oauth"),
  subject: "42",
};

const verified = { identity, profile: normalizedGithubProfile };
const secret = Redacted.make(Encoding.encodeBase64Url(new Uint8Array(32).fill(7)));
const keys = { activeKeyId: "test", keys: [{ id: "test", material: secret }] };

const committed = <Value, A>(value: Value, prepare: OAuth.PrepareOAuthCommit<Value, A>) =>
  coordinateCommit((journal) => Effect.sync(() => prepare(value, journal)), {
    mode: "synchronous",
  }).pipe(
    Effect.map((result) => result.value),
    Effect.mapError(() => OAuth.OAuthUnavailable.make({})),
    Effect.provide(LifecycleHooks.empty),
  );

const fixture = Effect.fn("test.profile.fixture")(function* (
  mode: "registration" | "signin" | "mismatched-credential",
) {
  let flowJson: string | undefined;
  let claimed = false;
  let storedIntent: string | undefined;
  let claimsCalls = 0;
  let registrations = 0;
  let settlements = 0;
  const flowCodec = Schema.fromJsonString(OAuth.OAuthPendingFlow);
  const intentCodec = Schema.fromJsonString(OAuth.OAuthRegistrationIntent);
  const revision = Sessions.SecurityRevision.make("revision-1");

  const persistence = Layer.succeed(OAuth.OAuthSignInPersistence, {
    issue: (flow, prepare) =>
      Effect.gen(function* () {
        expect(flowJson).toBeUndefined();
        flowJson = yield* Schema.encodeEffect(flowCodec)(flow).pipe(Effect.orDie);

        return yield* committed({ _tag: "Issued", flow }, prepare);
      }),
    claim: (input, prepare) =>
      Effect.gen(function* () {
        expect(claimed).toBe(false);
        const flow = yield* Schema.decodeEffect(flowCodec)(flowJson!).pipe(Effect.orDie);

        expect(input.stateDigest).toBe(flow.context.stateDigest);
        expect(input.requestBindingVerifier).toBe(flow.context.requestBindingVerifier);
        claimed = true;

        return yield* committed(
          {
            _tag: "Claimed",
            claim: {
              flow,
              claimId: input.claimId,
              claimedAtMillis: input.nowMillis,
              claimExpiresAtMillis: input.nowMillis + flow.context.claimLifetimeMillis,
            },
          },
          prepare,
        );
      }),
    settle: () => Effect.die("Registration-aware settlement must own this flow"),
    cleanup: () => Effect.die("Cleanup is outside this profile fixture"),
  });

  const services = Layer.mergeAll(
    persistence,
    LifecycleHooks.empty,
    Layer.succeed(method.registration.RegistrationAuthority, {
      read: (access) =>
        Effect.gen(function* () {
          const intent = yield* Schema.decodeEffect(intentCodec)(storedIntent!).pipe(Effect.orDie);

          expect(access.reference).toBe(intent.reference);
          expect(access.credentialDigest).toBe(intent.credentialDigest);
          expect(access.requestBindingVerifier).toBe(intent.context.requestBindingVerifier);

          return { intent, application: { _tag: "Unbound" as const } };
        }),
      inspect: ({ intent }) =>
        Effect.sync(() => {
          expect(intent.profile).toEqual(normalizedGithubProfile);
          expect(Object.isFrozen(intent.profile?.providerData?.plan)).toBe(true);

          return { fingerprint: TokenDigest.make("empty-registration-v1"), eligible: true };
        }),
      register: (input, prepare) => {
        registrations++;
        expect(input.intent.profile).toEqual(normalizedGithubProfile);
        expect(input.registration).toEqual({});

        return committed({ _tag: "Registered", replayed: false }, prepare);
      },
      cleanup: () => Effect.die("Cleanup is outside this profile fixture"),
    }),
    Layer.succeed(OAuth.OAuthRegistrationIntents, {
      settle: (input, prepare) =>
        Effect.gen(function* () {
          settlements++;
          expect(input.identity).toEqual(verified);
          if (mode === "registration") {
            expect(input.intent?.profile).toEqual(normalizedGithubProfile);
            storedIntent = yield* Schema.encodeEffect(intentCodec)(input.intent!).pipe(
              Effect.orDie,
            );

            const restored = yield* Schema.decodeEffect(intentCodec)(storedIntent).pipe(
              Effect.orDie,
            );

            return yield* committed({ _tag: "RegistrationIssued", intent: restored }, prepare);
          }

          return yield* committed(
            {
              _tag: "Verified",
              credential: {
                moduleId: OAuth.OAuthModuleId.make("test/profile"),
                identity: { ...identity, subject: mode === "mismatched-credential" ? "43" : "42" },
                credentialId: "credential-1",
                credentialRevision: revision,
                revision: {
                  subjectId: SubjectId.make("local-account"),
                  securityRevision: revision,
                  credentials: [{ credentialId: "credential-1", revision }],
                },
              },
            },
            prepare,
          );
        }),
    }),
    Layer.succeed(method.ClaimsForOAuth, {
      resolve: (credential, fresh) =>
        Effect.sync(() => {
          claimsCalls++;
          expect(credential.revision.subjectId).toBe("local-account");
          expect(fresh).toEqual(verified);
          expect(Object.isFrozen(fresh.profile?.providerData?.plan)).toBe(true);
          expect(fresh.profile?.providerData?.plan).not.toBe(
            normalizedGithubProfile.providerData.plan,
          );
          expect(Object.isFrozen(normalizedGithubProfile.providerData.plan)).toBe(false);

          return { displayName: fresh.profile!.displayName! };
        }),
    }),
    Layer.succeed(AppAuth.sessions.AuthenticationCompletion, {
      prepare: ({ claims }) =>
        Effect.gen(function* () {
          expect(claims).toEqual({ displayName: "The Octocat" });

          // The real completion boundary receives only the application's selected claims.
          return yield* committed(
            {
              value: { _tag: "PendingAuthentication" as const, expiresAt: yield* DateTime.now },
              credentialCommands: [],
            },
            (value, journal) => journal.prepare(value),
          ).pipe(Effect.mapError(() => Sessions.SessionUnavailable.make({})));
        }),
      pendingContext: () => Effect.die("Unexpected pending lookup"),
      rejectPendingCredential: () => Effect.die("Unexpected pending rejection"),
      preparePending: () => Effect.die("Unexpected pending completion"),
      rejectPending: () => Effect.die("Unexpected pending rejection"),
    }),
    Layer.succeed(OAuth.OAuthProtocol, {
      prepareAuthorization: (input) =>
        Effect.succeed({
          configuration: {
            ...identity,
            protocol: "oauth" as const,
            configurationGeneration: 1,
            responseIssuerMode: "required" as const,
            callbackId: input.callbackId ?? OAuth.OAuthCallbackId.make("github"),
            redirectUri: OAuth.OAuthRedirectUri.make("https://app.test/callback"),
          },
          authorizationUrl: Redacted.make("https://github.com/login/oauth/authorize"),
          secrets: {
            namespace: "effect-auth/oauth-transaction-secrets/v1" as const,
            state: secret,
            pkceVerifier: secret,
          },
        }),
      exchangeVerifiedIdentity: () => Effect.succeed(verified),
    }),
    method.binding.signedLayer({ generation: 1, lifetimeMillis: 120_000, keyring: keys }),
    OAuth.OAuthTransactionProtector.xchacha20poly1305(keys),
    OAuth.OAuthReturnTargets.exactRoutes(["/account"]),
  ).pipe(Layer.provide(layerWebCrypto));

  const layer = Layer.mergeAll(
    method.registration.signInLayer(policy, registrationPolicy),
    method.registration.layer,
  ).pipe(Layer.provideMerge(services), Layer.provide(layerWebCrypto));

  const result = yield* Effect.gen(function* () {
    const signin = yield* method.SignIn;
    const flowId = RequestBindingFlowId.make("profile-flow");

    const started = yield* signin.begin({
      flowId,
      commandId: OAuth.OAuthCommandId.make("begin"),
      provider: identity.provider,
      callbackId: OAuth.OAuthCallbackId.make("github"),
      returnTarget: "/account",
    });

    const binder = started.credentialCommands[0];

    if (binder?._tag !== "Issue") return yield* Effect.die("Missing binder");

    const complete = signin.complete({
      flowId,
      provider: identity.provider,
      callbackId: OAuth.OAuthCallbackId.make("github"),
      requestBinding: binder.credential,
      response: {
        _tag: "Code",
        state: secret,
        code: Redacted.make("code"),
        issuer: identity.issuer,
      },
    });

    if (mode === "mismatched-credential") {
      yield* expectTag(complete, "OAuthUnavailable");

      return undefined;
    }
    const completed = yield* complete;

    if ("_tag" in completed.value && completed.value._tag === "RegistrationRequired") {
      const bearer = completed.credentialCommands.find(
        (command) => command._tag === "Issue" && command.slot === "registration",
      );

      if (bearer?._tag !== "Issue") return yield* Effect.die("Missing registration bearer");
      const registrations = yield* method.registration.Registrations;

      const plan = yield* registrations.planComplete({
        reference: completed.value.reference,
        flowId,
        requestBinding: binder.credential,
        credential: bearer.credential,
        commandId: OAuth.OAuthCommandId.make("register"),
        registration: {},
      });

      const receipt = yield* plan.commit;

      expect((yield* receipt.read).value).toEqual({ _tag: "RegistrationAccepted" });
    }

    return completed;
  }).pipe(Effect.provide(layer));

  expect(claimsCalls).toBe(mode === "signin" ? 1 : 0);
  expect(registrations).toBe(mode === "registration" ? 1 : 0);
  expect(settlements).toBe(1);
  if (mode === "registration") {
    expect(result?.value).toMatchObject({ _tag: "RegistrationRequired" });
    expect(result?.value).not.toHaveProperty("profile");
    const restored = yield* Schema.decodeEffect(intentCodec)(storedIntent!).pipe(Effect.orDie);

    expect(restored.profile).toEqual(normalizedGithubProfile);
    // Previously persisted intents remain valid and acquire no invented profile.
    const { profile: _profile, ...previous } = restored;

    expect(
      yield* Schema.decodeEffect(OAuth.OAuthRegistrationIntent)(previous).pipe(Effect.orDie),
    ).not.toHaveProperty("profile");
  } else if (mode === "signin") {
    expect(result?.value).toHaveProperty("completion._tag", "PendingAuthentication");
    expect(JSON.stringify(result?.value)).not.toContain("providerData");
  }
});

describe("OAuth application profile boundary", () => {
  it.live("retains the original provider profile in the server registration intent", () =>
    fixture("registration"),
  );
  it.live(
    "passes the fresh profile to claims only after resolving the exact local credential",
    () => fixture("signin"),
  );
  it.live("does not expose a profile to claims when credential identity mismatches", () =>
    fixture("mismatched-credential"),
  );
});
