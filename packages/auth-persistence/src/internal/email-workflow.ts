import {
  EmailAddressPersistence,
  EmailUnavailable,
  snapshotEmailCredential,
  snapshotEmailRevision,
  type EmailAction,
  type EmailAddressMutation,
  type PrepareEmailCommit,
  type EmailAddressDecision,
} from "@yielded/auth/Email";
import {
  coordinateCommit,
  CurrentCommitJournal,
  hasCommitScope,
  HookConfigurationError,
  LifecycleHooks,
} from "@yielded/auth/Hooks";
import { reportPersistenceFailure } from "@yielded/auth/Persistence";
import { ProofUnavailable } from "@yielded/auth/Proofs";
import { assessAuthentication } from "@yielded/auth/Sessions";
import { Cause, DateTime, Effect, Schema } from "effect";

import {
  allocateEmailValue,
  allocateEmailSecurityRevision,
  sameEmailRevision,
  snapshotEmailMutation,
  validateEmailMutation,
  type EmailWorkflowOptions,
  type EmailWorkflowPolicy,
} from "./email-policy";
import type { EmailAddressStore } from "./email-store";
import { isMappedConstraintConflict } from "./mapping-error";
import type { PersistenceOwner } from "./persistence-owner";
import { completeProofPlan, inspectProofCompletion } from "./proof-workflow";

const unavailable = () => EmailUnavailable.make({});

export const translateEmailFailure = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
  reportPersistenceFailure(
    effect,
    (error) =>
      Schema.is(EmailUnavailable)(error) ||
      Schema.is(ProofUnavailable)(error) ||
      Schema.is(HookConfigurationError)(error),
  ).pipe(Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, unavailable))));

export const makeEmailAddressWorkflow = Effect.fnUntraced(function* (
  policy: EmailWorkflowPolicy,
  options: EmailWorkflowOptions,
  owner: PersistenceOwner<EmailAddressStore>,
) {
  const hooks = yield* LifecycleHooks;

  const guard = Effect.gen(function* () {
    if (!options.coordinated) {
      if (yield* hasCommitScope) return yield* unavailable();
      yield* options.standaloneGuard;
    }
  });

  const owned = <A, E, R>(body: (store: EmailAddressStore) => Effect.Effect<A, E, R>) =>
    guard.pipe(
      Effect.andThen(coordinateCommit(() => owner.transaction(body))),
      Effect.map((result) => result.value),
      Effect.provideService(LifecycleHooks, hooks),
    );

  const read = <A, E, R>(
    body: (store: EmailAddressStore) => Effect.Effect<A, E, R>,
    advisory: boolean,
  ) => guard.pipe(Effect.andThen(advisory ? body(owner.read) : owner.transaction(body)));

  const mutate = Effect.fnUntraced(function* <A>(
    uncaptured: EmailAddressMutation,
    action: EmailAction,
    prepare: PrepareEmailCommit<EmailAddressDecision, A>,
  ) {
    if (options.proof === undefined) return yield* unavailable();
    const proof = options.proof;
    const input = yield* snapshotEmailMutation(uncaptured);

    const targetCredentialId = yield* allocateEmailValue(
      options.mode,
      policy.allocateCredentialId,
      policy.allocateCredentialIdSync,
    );

    const revision = () =>
      allocateEmailValue(options.mode, policy.allocateRevision, policy.allocateRevisionSync);

    const targetIdentifierRevision = yield* revision();
    const targetCredentialRevision = yield* revision();
    const sourceIdentifierRevision = yield* revision();
    const sourceCredentialRevision = yield* revision();

    const confirmsExisting =
      action === "verify-address" && input.captured.targetIdentifierRevision !== undefined;

    const nextSecurityRevision = confirmsExisting
      ? input.captured.revision.securityRevision
      : yield* allocateEmailSecurityRevision(
          policy,
          options.mode,
          input.captured.revision.securityRevision,
        );

    if (
      (!confirmsExisting && nextSecurityRevision === input.captured.revision.securityRevision) ||
      [
        targetIdentifierRevision,
        targetCredentialRevision,
        sourceIdentifierRevision,
        sourceCredentialRevision,
      ].some((value) => input.captured.revision.credentials.some((item) => item.revision === value))
    )
      return yield* unavailable();

    return yield* owned((store) =>
      Effect.gen(function* () {
        const journal = yield* CurrentCommitJournal;
        const current = yield* store.readMutation(input, action);

        if (
          !(yield* validateEmailMutation(policy, input, action, current)) ||
          current === undefined ||
          current.commandPresent
        )
          return prepare("rejected", journal);
        if (store.proof === undefined) return yield* unavailable();
        let receipt: ReturnType<typeof prepare> | undefined;

        yield* completeProofPlan(
          proof,
          store.proof,
          input.completion,
          Effect.gen(function* () {
            // Proof locks may wait. Reassess both policies against the commit clock.
            const requirement = yield* current.requirement;

            const original = yield* assessAuthentication(
              input.authorization.evidence,
              input.authorization.requirement,
            ).pipe(Effect.mapError(unavailable));

            const configured = yield* assessAuthentication(
              input.authorization.evidence,
              requirement,
            ).pipe(Effect.mapError(unavailable));

            if (!original.satisfied || !configured.satisfied) return false;
            const now = DateTime.toEpochMillis(yield* DateTime.now);

            return yield* current.applyMutation(
              {
                targetCredentialId,
                targetIdentifierRevision,
                targetCredentialRevision,
                sourceIdentifierRevision,
                sourceCredentialRevision,
                nextSecurityRevision,
              },
              now,
            );
          }),
          (decision) => {
            receipt = prepare(decision === "completed" ? "changed" : "rejected", journal);

            return decision;
          },
        );

        return receipt ?? prepare("rejected", journal);
      }),
    ).pipe(
      Effect.catchCause((cause) =>
        cause.reasons.every(Cause.isFailReason) &&
        [policy.isCommandConflict, policy.isIdentifierConflict, policy.isCredentialConflict].some(
          (classify) => isMappedConstraintConflict(classify, cause),
        )
          ? owned(() =>
              CurrentCommitJournal.use((journal) => Effect.succeed(prepare("rejected", journal))),
            )
          : Effect.failCause(cause),
      ),
    );
  });

  return EmailAddressPersistence.of({
    target: (input) => {
      const advisory = input.sourceCredentialId === undefined && !options.coordinated;

      return read(
        (store) =>
          Effect.gen(function* () {
            const current = yield* store.readAddress(input, !advisory && options.locking);

            if (current === undefined) return yield* unavailable();

            return Object.freeze({
              revision: snapshotEmailRevision(current.revision),
              eligible: current.eligible,
              ...(current.targetIdentifierRevision === undefined
                ? {}
                : { targetIdentifierRevision: current.targetIdentifierRevision }),
              ...(current.source === undefined
                ? {}
                : { source: yield* snapshotEmailCredential(current.source) }),
            });
          }),
        advisory,
      ).pipe(translateEmailFailure);
    },
    checkCompletion: (input) =>
      read(
        (store) =>
          Effect.gen(function* () {
            if (options.proof === undefined || input.binding._tag !== "IdentifierChange")
              return false;

            const action =
              input.moduleId.endsWith("/verify-address") &&
              input.purpose === "email-address-verification"
                ? "verify-address"
                : input.moduleId.endsWith("/change-address") &&
                    input.purpose === "email-address-change"
                  ? "change-address"
                  : undefined;

            if (action === undefined) return false;
            const selected = yield* store.readCompletion(input);

            return (
              selected.revision !== undefined &&
              sameEmailRevision(selected.revision, input.binding.revision) &&
              (yield* inspectProofCompletion(options.proof, input, selected.completion, false)) !==
                undefined
            );
          }),
        true,
      ).pipe(translateEmailFailure),
    verifyWithProof: (input, prepare) =>
      mutate(input, "verify-address", prepare).pipe(translateEmailFailure),
    changeWithProof: (input, prepare) =>
      mutate(input, "change-address", prepare).pipe(translateEmailFailure),
    cleanup: (input, prepare) =>
      owned((store) =>
        Effect.gen(function* () {
          const journal = yield* CurrentCommitJournal;

          const selected = yield* store.readExpired({
            ...input,
            nowMillis: DateTime.toEpochMillis(yield* DateTime.now),
          });

          const receipt = prepare(selected.result, journal);

          yield* selected.deleteExpired;

          return receipt;
        }),
      ).pipe(translateEmailFailure),
  });
});
