import {
  coordinateCommit,
  CurrentCommitJournal,
  hasCommitScope,
  HookConfigurationError,
  LifecycleHooks,
} from "@yielded/auth/Hooks";
import {
  PasswordPersistence,
  PasswordUnavailable,
  type PasswordMutationInput,
} from "@yielded/auth/Password";
import { reportPersistenceFailure } from "@yielded/auth/Persistence";
import { ProofUnavailable } from "@yielded/auth/Proofs";
import { Cause, Effect, Option, Schema } from "effect";

import type { AnyPasswordPersistenceMapping } from "./models/password-model";
import type { NativeSqlTables } from "./native-sql-table";
import { makePasswordCredentials } from "./password-credentials";
import {
  allocatePasswordNextSecurityRevision,
  allocatePasswordValue,
  passwordProofCompletionMatches,
  passwordMutationEvidenceMatches,
  snapshotPasswordMutation,
  validatePasswordMutation,
  type PasswordWorkflowOptions,
} from "./password-policy";
import type { PasswordMutationRevisions, PasswordStore } from "./password-store";
import type { PersistenceOwner } from "./persistence-owner";
import { completeProofPlan, inspectProofCompletion } from "./proof-workflow";

const unavailable = () => PasswordUnavailable.make({});

export const translatePasswordFailure = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
  reportPersistenceFailure(
    effect,
    (error) =>
      Schema.is(PasswordUnavailable)(error) ||
      Schema.is(ProofUnavailable)(error) ||
      Schema.is(HookConfigurationError)(error),
  ).pipe(Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, unavailable))));

export const makePasswordWorkflow = Effect.fnUntraced(function* (
  policy: AnyPasswordPersistenceMapping,
  options: PasswordWorkflowOptions,
  owner: PersistenceOwner<PasswordStore>,
  tables: NativeSqlTables,
) {
  const hooks = yield* LifecycleHooks;

  const guard = Effect.gen(function* () {
    if (!options.coordinated) {
      if (yield* hasCommitScope) return yield* unavailable();
      yield* options.standaloneGuard;
    }
  });

  const owned = <A, E, R>(body: (store: PasswordStore) => Effect.Effect<A, E, R>) =>
    guard.pipe(
      Effect.andThen(coordinateCommit(() => owner.transaction(body))),
      Effect.map((committed) => committed.value),
      Effect.provideService(LifecycleHooks, hooks),
    );

  const read = <A, E, R>(body: (store: PasswordStore) => Effect.Effect<A, E, R>) =>
    guard.pipe(Effect.andThen(body(owner.read)));

  const revisions = Effect.fnUntraced(function* (input: PasswordMutationInput, adding: boolean) {
    const credentialId = adding
      ? yield* allocatePasswordValue(
          options.mode,
          policy.allocateCredentialId,
          policy.allocateCredentialIdSync,
        )
      : (input.credential?.credentialId ?? "");

    const credentialRevision = yield* allocatePasswordValue(
      options.mode,
      policy.allocateRevision,
      policy.allocateRevisionSync,
    );

    const verifierVersion = yield* allocatePasswordValue(
      options.mode,
      policy.allocateRevision,
      policy.allocateRevisionSync,
    );

    const nextSecurityRevision = yield* allocatePasswordNextSecurityRevision(
      policy,
      options.mode,
      input.expectedRevision.securityRevision,
    );

    if (
      nextSecurityRevision === input.expectedRevision.securityRevision ||
      (!adding &&
        input.credential !== undefined &&
        credentialRevision === input.credential.credentialRevision)
    )
      return yield* unavailable();

    return {
      credentialId,
      credentialRevision,
      verifierVersion,
      nextSecurityRevision,
    } satisfies PasswordMutationRevisions;
  });

  return PasswordPersistence.of({
    ...(yield* makePasswordCredentials(tables, policy, options)),
    readForSubject: (input) =>
      read((store) => store.readForSubject(input).pipe(Effect.map(Option.fromUndefinedOr))).pipe(
        translatePasswordFailure,
      ),
    recoveryTarget: (input) =>
      read((store) =>
        store
          .readCredential(input, false)
          .pipe(
            Effect.map((read) =>
              read?.snapshot?.identifierVerifiedAtMillis === undefined
                ? Option.none()
                : Option.some(read.snapshot),
            ),
          ),
      ).pipe(translatePasswordFailure),
    addIfAbsent: (uncaptured, prepare) =>
      Effect.gen(function* () {
        const input = yield* snapshotPasswordMutation(uncaptured);
        const allocated = yield* revisions(input, true);

        return yield* owned((store) =>
          Effect.gen(function* () {
            const journal = yield* CurrentCommitJournal;

            if (!passwordMutationEvidenceMatches(input)) return prepare("rejected", journal);
            const current = yield* store.readMutation(input, "add-password");
            const now = yield* validatePasswordMutation(policy, input, "add-password", current);

            if (now === undefined || current.commandPresent || current.passwordPresent)
              return prepare("rejected", journal);
            if (!(yield* current.applyMutation(allocated, now))) return yield* unavailable();

            return prepare("changed", journal);
          }),
        );
      }).pipe(translatePasswordFailure),
    replaceIfCurrent: (uncaptured, prepare) =>
      Effect.gen(function* () {
        const input = yield* snapshotPasswordMutation(uncaptured);
        const allocated = yield* revisions(input, false);

        return yield* owned((store) =>
          Effect.gen(function* () {
            const journal = yield* CurrentCommitJournal;

            if (!passwordMutationEvidenceMatches(input)) return prepare("rejected", journal);
            const current = yield* store.readMutation(input, "change-password");
            const now = yield* validatePasswordMutation(policy, input, "change-password", current);

            if (now === undefined || current.commandPresent || !current.expectedPasswordCurrent)
              return prepare("rejected", journal);
            const prepared = prepare("changed", journal);

            if (!(yield* current.applyMutation(allocated, now))) return yield* unavailable();

            return prepared;
          }),
        );
      }).pipe(translatePasswordFailure),
    checkReset: (input) =>
      read((store) =>
        Effect.gen(function* () {
          if (options.proof === undefined) return yield* unavailable();
          if (
            input.moduleId.length <= "/reset".length ||
            !input.moduleId.endsWith("/reset") ||
            input.purpose !== "password-reset" ||
            input.binding._tag !== "Subject"
          )
            return false;
          const selected = yield* store.readReset(input);
          const { credential } = selected;

          if (
            credential === undefined ||
            credential.revision.securityRevision !== input.binding.revision.securityRevision ||
            !input.binding.revision.credentials.every((item) =>
              credential.revision.credentials.some(
                (actual) =>
                  actual.credentialId === item.credentialId && actual.revision === item.revision,
              ),
            )
          )
            return false;
          if (options.coordinated === true) return yield* unavailable();

          return (
            (yield* inspectProofCompletion(options.proof, input, selected.completion, false)) !==
            undefined
          );
        }),
      ).pipe(translatePasswordFailure),
    resetWithProof: (uncaptured, prepare) =>
      Effect.gen(function* () {
        if (options.proof === undefined) return yield* unavailable();
        const proof = options.proof;

        const input = Object.freeze({
          ...(yield* snapshotPasswordMutation(uncaptured)),
          completion: uncaptured.completion,
        });

        const allocated = yield* revisions(input, false);

        return yield* owned((store) =>
          Effect.gen(function* () {
            const journal = yield* CurrentCommitJournal;

            if (!passwordProofCompletionMatches(input) || !passwordMutationEvidenceMatches(input))
              return prepare("rejected", journal);
            if (store.proof === undefined) return yield* unavailable();
            const current = yield* store.readMutation(input, "reset-password");
            const now = yield* validatePasswordMutation(policy, input, "reset-password", current);

            if (now === undefined || current.commandPresent || !current.expectedPasswordCurrent)
              return prepare("rejected", journal);
            let receipt: ReturnType<typeof prepare> | undefined;

            yield* completeProofPlan(
              proof,
              store.proof,
              input.completion,
              current.applyMutation(allocated, now),
              (decision) => {
                receipt = prepare(decision === "completed" ? "changed" : "rejected", journal);

                return decision;
              },
            );

            return receipt ?? prepare("rejected", journal);
          }),
        );
      }).pipe(translatePasswordFailure),
  });
});
