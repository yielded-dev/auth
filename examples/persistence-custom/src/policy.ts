import { AuthRequest } from "@yielded/auth/Auth";
import { EmailActionEvidence, EmailActionRequired, EmailUnavailable } from "@yielded/auth/Email";
import { LifecycleHooks } from "@yielded/auth/Hooks";
import {
  PasskeyActionEvidence,
  PasskeyActionRequired,
  PasskeyUnavailable,
} from "@yielded/auth/Passkey";
import {
  PasswordActionEvidence,
  PasswordActionRequired,
  PasswordPersistence,
  PasswordUnavailable,
} from "@yielded/auth/Password";
import { AuthenticationAuthority, AuthenticationFlowId } from "@yielded/auth/Sessions";
import { layerWebCrypto } from "@yielded/auth/WebCrypto";
import { DateTime, Effect, Layer, Option, Schema } from "effect";

import {
  AppAuth,
  recoveryRequirement,
  requirement,
  sessionConfiguration,
  sessionRequirement,
} from "./auth";
import { AccountStore } from "./store";

const SessionReader = AppAuth.sessions
  .statefulLayer(sessionConfiguration.policy(AppAuth.sessions.moduleId))
  .pipe(Layer.provide([layerWebCrypto, LifecycleHooks.empty]));

const EmailActions = Layer.effect(
  EmailActionEvidence,
  Effect.gen(function* () {
    const sessions = yield* AppAuth.sessions.SessionStrategy;

    return EmailActionEvidence.of({
      verify: Effect.fn("Customers.authorizeEmailVerification")(
        function* ({ invocation, challenge }) {
          const request = yield* Effect.serviceOption(AuthRequest);
          const token = Option.isSome(request) ? request.value.credentials.session : undefined;

          if (invocation._tag !== "Authenticated" || token === undefined)
            return yield* EmailActionRequired.make({});
          const source = yield* sessions.inspect(token);
          const original = source.provenance.evidence;

          const confirmsRegisteredAddress =
            challenge.action === "verify-address" &&
            challenge.targetIdentifierRevision !== undefined &&
            challenge.target.value === source.session.claims.email;

          if (
            (challenge.action === "verify-address" && !confirmsRegisteredAddress) ||
            source.session.sessionId !== invocation.sessionId ||
            source.session.subjectId !== invocation.subjectId ||
            original.revision.subjectId !== challenge.revision.subjectId ||
            original.revision.securityRevision !== challenge.revision.securityRevision ||
            original.revision.credentials.some(
              (item) =>
                !challenge.revision.credentials.some(
                  (current) =>
                    current.credentialId === item.credentialId &&
                    current.revision === item.revision,
                ),
            )
          )
            return yield* EmailActionRequired.make({});

          // Preserve the original authentication time and factors, including for an older valid session.
          return {
            evidence: {
              ...original,
              revision: challenge.revision,
              flowId: AuthenticationFlowId.make(challenge.commandId),
              bindingDigest: challenge.bindingDigest,
            },
            requirement: confirmsRegisteredAddress ? sessionRequirement : requirement,
          };
        },
        Effect.mapError((error) =>
          Schema.is(EmailActionRequired)(error) ? error : EmailUnavailable.make({}),
        ),
      ),
    });
  }),
).pipe(Layer.provide(SessionReader));

const PasswordActions = Layer.effect(
  PasswordActionEvidence,
  Effect.gen(function* () {
    const passwords = yield* PasswordPersistence;
    const authority = yield* AuthenticationAuthority;
    const store = yield* AccountStore;

    return PasswordActionEvidence.of({
      verify: Effect.fn("Customers.authorizePasswordChange")(
        function* ({ challenge, currentPasswordEvidence, recovery }) {
          if (challenge.action === "change-password" && currentPasswordEvidence !== undefined) {
            return {
              evidence: {
                ...currentPasswordEvidence,
                flowId: AuthenticationFlowId.make(challenge.commandId),
                bindingDigest: challenge.bindingDigest,
              },
              requirement,
            };
          }
          if (
            challenge.action !== "reset-password" ||
            recovery === undefined ||
            recovery.binding._tag !== "Subject" ||
            recovery.moduleId !== `${AppAuth.strategies.password.persistence.moduleId}/reset` ||
            recovery.binding.revision.subjectId !== challenge.revision.subjectId ||
            !(yield* passwords.checkReset(recovery))
          )
            return yield* PasswordActionRequired.make({});

          // This app's single-factor recovery policy requires its independently verified email credential.
          const email = yield* store.read((state) =>
            Effect.sync(
              () =>
                state.customers.find(
                  (account) =>
                    account.id === challenge.revision.subjectId &&
                    account.active &&
                    account.email === recovery.binding.identifier.value &&
                    account.verifiedAtMillis !== undefined,
                )?.emailCredential,
            ),
          );

          if (email === undefined) return yield* PasswordActionRequired.make({});

          const revision = yield* authority.capture(challenge.revision.subjectId, [
            ...challenge.revision.credentials.map((item) => item.credentialId),
            email.id,
          ]);

          if (revision.securityRevision !== challenge.revision.securityRevision)
            return yield* PasswordActionRequired.make({});

          return {
            evidence: {
              revision,
              flowId: AuthenticationFlowId.make(challenge.commandId),
              bindingDigest: challenge.bindingDigest,
              proofs: [
                {
                  method: "email-recovery",
                  credentialId: email.id,
                  factors: ["possession" as const],
                  userVerified: false,
                  phishingResistant: false,
                  verifiedAt: DateTime.makeUnsafe(recovery.nowMillis),
                },
              ] as const,
            },
            requirement: recoveryRequirement,
          };
        },
        Effect.mapError((error) =>
          Schema.is(PasswordActionRequired)(error) ? error : PasswordUnavailable.make({}),
        ),
      ),
    });
  }),
);

const PasskeyActions = Layer.effect(
  PasskeyActionEvidence,
  Effect.gen(function* () {
    const sessions = yield* AppAuth.sessions.SessionStrategy;

    return PasskeyActionEvidence.of({
      verify: Effect.fn("Customers.authorizePasskey")(
        function* ({ invocation, challenge }) {
          const request = yield* Effect.serviceOption(AuthRequest);
          const token = Option.isSome(request) ? request.value.credentials.session : undefined;

          if (invocation._tag !== "Authenticated" || token === undefined)
            return yield* PasskeyActionRequired.make({});
          const source = yield* sessions.inspect(token);
          const original = source.provenance.evidence;

          if (
            source.session.sessionId !== invocation.sessionId ||
            source.session.subjectId !== invocation.subjectId ||
            original.revision.subjectId !== challenge.revision.subjectId ||
            original.revision.securityRevision !== challenge.revision.securityRevision ||
            original.revision.credentials.some(
              (item) =>
                !challenge.revision.credentials.some(
                  (current) =>
                    current.credentialId === item.credentialId &&
                    current.revision === item.revision,
                ),
            )
          )
            return yield* PasskeyActionRequired.make({});

          return {
            evidence: {
              ...original,
              revision: challenge.revision,
              flowId: AuthenticationFlowId.make(challenge.flowId),
              bindingDigest: challenge.bindingDigest,
            },
            requirement: challenge.action === "remove" ? requirement : sessionRequirement,
          };
        },
        Effect.mapError((error) =>
          Schema.is(PasskeyActionRequired)(error) ? error : PasskeyUnavailable.make({}),
        ),
      ),
    });
  }),
).pipe(Layer.provide(SessionReader));

export const ActionPoliciesLive = Layer.mergeAll(EmailActions, PasswordActions, PasskeyActions);
