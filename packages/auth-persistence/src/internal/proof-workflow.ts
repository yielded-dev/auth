import {
  coordinateCommit,
  CurrentCommitJournal,
  hasCommitScope,
  HookConfigurationError,
  LifecycleHooks,
} from "@yielded/auth/Hooks";
import { reportPersistenceFailure } from "@yielded/auth/Persistence";
import {
  ProofPersistence,
  ProofRequestConflict,
  ProofUnavailable,
  type ProofCompletionDecision,
  type ProofCompletionPlan,
  type ProofDeliveryClaim,
} from "@yielded/auth/Proofs";
import { Cause, DateTime, Effect, Schema } from "effect";

import type { PersistenceOwner } from "./persistence-owner";
import {
  allocateProofVersion,
  matchesProofAuthority,
  proofScopeEntries,
  sameProofBinding,
  type ProofWorkflowOptions,
  type ProofWorkflowPolicy,
} from "./proof-policy";
import {
  CurrentProofStore,
  type ProofCompletionRead,
  type ProofCompletionStore,
  type ProofScopeRequest,
  type ProofStore,
} from "./proof-store";

const unavailable = () => ProofUnavailable.make({});
const nowMillis = DateTime.now.pipe(Effect.map(DateTime.toEpochMillis));

export const translateProofFailure = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
  reportPersistenceFailure(
    effect,
    (error) => Schema.is(ProofUnavailable)(error) || Schema.is(HookConfigurationError)(error),
  ).pipe(Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, unavailable))));

const translateIssueFailure = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
  reportPersistenceFailure(
    effect,
    (error) =>
      Schema.is(ProofUnavailable)(error) ||
      Schema.is(ProofRequestConflict)(error) ||
      Schema.is(HookConfigurationError)(error),
  ).pipe(
    Effect.catchCause((cause) =>
      Effect.failCause(
        Cause.map(cause, (error) =>
          Schema.is(ProofRequestConflict)(error) ? error : unavailable(),
        ),
      ),
    ),
  );

const admittedScopes = (store: ProofStore, request: ProofScopeRequest, now: number) =>
  store
    .readScopeCounts(request, now)
    .pipe(
      Effect.map((counts) =>
        request.entries.filter(
          (entry, index) => counts[index] !== undefined && counts[index]! < entry.budget.limit,
        ),
      ),
    );

export const inspectProofCompletion = Effect.fnUntraced(function* (
  policy: ProofWorkflowPolicy,
  input: ProofCompletionPlan["input"],
  selected: ProofCompletionRead,
  mutating: boolean,
) {
  if (mutating && !selected.seriesPresent) return undefined;
  const continuation = selected.continuation;
  const now = yield* nowMillis;

  if (continuation === undefined) return undefined;
  const { record } = continuation;

  return matchesProofAuthority(input.binding, selected.authority) &&
    record.moduleId === input.moduleId &&
    record.continuationId === input.continuationId &&
    record.purpose === input.purpose &&
    record.digest === input.continuationDigest &&
    record.seriesKey === policy.scopeKeys(input).series &&
    sameProofBinding(record.binding, input.binding) &&
    !continuation.consumed &&
    record.expiresAtMillis > now
    ? continuation
    : undefined;
});

export const checkProofCompletion = Effect.fnUntraced(function* (
  policy: ProofWorkflowPolicy,
  store: ProofCompletionStore,
  input: ProofCompletionPlan["input"],
) {
  return (
    (yield* inspectProofCompletion(
      policy,
      input,
      yield* store.readCompletion(input, false),
      false,
    )) !== undefined
  );
});

export const completeProofIn = Effect.fnUntraced(function* <A, E = never, R = never>(
  policy: ProofWorkflowPolicy,
  store: ProofCompletionStore,
  input: ProofCompletionPlan["input"],
  prepare: (decision: ProofCompletionDecision) => A,
  protectedMutation?: Effect.Effect<boolean, E, R>,
) {
  const selected = yield* inspectProofCompletion(
    policy,
    input,
    yield* store.readCompletion(input, true),
    true,
  );

  if (selected === undefined) return prepare("rejected");
  if (protectedMutation !== undefined && !(yield* protectedMutation)) return yield* unavailable();
  const value = prepare("completed");

  yield* selected.consumeCompletion;

  return value;
});

export const completeProofPlan = Effect.fnUntraced(function* <A, E, R>(
  policy: ProofWorkflowPolicy,
  store: ProofCompletionStore,
  plan: ProofCompletionPlan,
  protectedMutation: Effect.Effect<boolean, E, R>,
  project: (decision: ProofCompletionDecision) => A,
) {
  const journal = yield* CurrentCommitJournal;

  return yield* completeProofIn(
    policy,
    store,
    plan.input,
    (decision) => plan.prepare(decision, journal, project),
    protectedMutation,
  );
});

export const makeProofWorkflow = Effect.fnUntraced(function* (
  policy: ProofWorkflowPolicy,
  options: ProofWorkflowOptions,
  owner: PersistenceOwner<ProofStore>,
) {
  const hooks = yield* LifecycleHooks;

  const owned = <A, E, R>(body: (store: ProofStore) => Effect.Effect<A, E, R>) =>
    Effect.gen(function* () {
      if (!options.coordinated) {
        if (yield* hasCommitScope) return yield* unavailable();
        yield* options.standaloneGuard;
      }

      return yield* coordinateCommit(() =>
        owner.transaction((store) =>
          body(store).pipe(Effect.provideService(CurrentProofStore, store)),
        ),
      ).pipe(Effect.map((committed) => committed.value));
    }).pipe(Effect.provideService(LifecycleHooks, hooks));

  return ProofPersistence.of({
    issue: (input, prepare) =>
      owned((store) =>
        Effect.gen(function* () {
          const journal = yield* CurrentCommitJournal;

          const authorityInput = {
            moduleId: input.record.moduleId,
            purpose: input.record.purpose,
            binding: input.record.binding,
          };

          const keys = policy.scopeKeys(authorityInput);

          const authorityCurrent = matchesProofAuthority(
            input.record.binding,
            yield* store.readAuthority(authorityInput, options.locking),
          );

          const scopes = proofScopeEntries(keys, input.record.binding, "issue", input.policy);

          const request: ProofScopeRequest = {
            ...authorityInput,
            action: "issue",
            entries: scopes,
          };

          const action = { ...request, entries: scopes.slice(0, 1) };

          yield* store.lockScopes(action);
          const actionOpen = (yield* admittedScopes(store, action, yield* nowMillis)).length === 1;

          if (actionOpen) yield* store.lockScopes({ ...request, entries: scopes.slice(1) });

          const series = actionOpen
            ? yield* store.readSeries(
                { ...authorityInput, scopeKey: keys.series },
                yield* allocateProofVersion(policy, options.mode),
              )
            : undefined;

          if (actionOpen && series === undefined) return yield* unavailable();
          const now = yield* nowMillis;
          const retentionUntilMillis = now + input.policy.requestRetentionMillis;

          const reserved = yield* store.reserveRequest({
            record: input.record,
            nowMillis: now,
            retentionUntilMillis,
          });

          if (reserved.fingerprint !== input.record.fingerprint)
            return yield* ProofRequestConflict.make({});
          if (reserved.replay || reserved.proofId !== input.record.proofId)
            return prepare({ _tag: "Existing", receipt: yield* reserved.receipt }, journal);
          const admitted = actionOpen ? yield* admittedScopes(store, request, now) : [];
          const active = series?.activeProofId;

          const generation =
            active === undefined
              ? undefined
              : yield* store.readGeneration(input.record.moduleId, active, options.locking);

          if (
            active !== undefined &&
            (generation === undefined || generation.purpose !== input.record.purpose)
          )
            return yield* unavailable();

          const replacementAuthorized =
            generation === undefined ||
            generation.state !== "active" ||
            generation.expiresAtMillis <= now ||
            sameProofBinding(yield* generation.binding, input.record.binding);

          const allowed =
            authorityCurrent &&
            input.eligible &&
            admitted.length === scopes.length &&
            input.record.issuedAtMillis <= now &&
            input.record.expiresAtMillis > now &&
            replacementAuthorized &&
            (input.supersedes === undefined || input.supersedes === active) &&
            (series?.lastIssueAtMillis === undefined ||
              now - series.lastIssueAtMillis >= input.policy.abuse.resendCooldownMillis);

          const receipt = {
            requestId: input.record.requestId,
            reference: {
              proofId: input.record.proofId,
              purpose: input.record.purpose,
              keyId: input.record.verifier.keyId,
            },
          };

          const prepared = prepare(
            allowed ? { _tag: "Issued", record: input.record } : { _tag: "Suppressed", receipt },
            journal,
          );

          if (!allowed) return prepared;
          yield* store.publishGeneration({
            record: input.record,
            policy: input.policy,
            seriesKey: keys.series,
            previousProofId: active,
            scopes,
            nowMillis: now,
            retentionUntilMillis,
            nextSeriesVersion: yield* allocateProofVersion(policy, options.mode),
          });

          return prepared;
        }),
      ).pipe(translateIssueFailure),
    attempt: (input, prepare) =>
      owned((store) =>
        Effect.gen(function* () {
          const journal = yield* CurrentCommitJournal;
          const keys = policy.scopeKeys(input);

          const authorityCurrent = matchesProofAuthority(
            input.binding,
            yield* store.readAuthority(input, options.locking),
          );

          const scopes = proofScopeEntries(keys, input.binding, "attempt", input.policy);
          const request: ProofScopeRequest = { ...input, action: "attempt", entries: scopes };
          const action = { ...request, entries: scopes.slice(0, 1) };

          yield* store.lockScopes(action);
          const actionOpen = (yield* admittedScopes(store, action, yield* nowMillis)).length === 1;

          if (actionOpen) yield* store.lockScopes({ ...request, entries: scopes.slice(1) });

          const { series, generation, command } = yield* store.readAttempt({
            attempt: input,
            seriesKey: keys.series,
            includeSeries: actionOpen,
          });

          if (command !== undefined) {
            if (command.decision === "rejected") return prepare({ _tag: "Rejected" }, journal);

            return yield* unavailable();
          }
          const now = yield* nowMillis;
          const admitted = actionOpen ? yield* admittedScopes(store, request, now) : [];

          const failures = yield* store.readFailureCount({
            ...input,
            seriesKey: keys.series,
            nowMillis: now,
          });

          const binding = generation === undefined ? undefined : yield* generation.binding;

          const candidateMatches =
            generation !== undefined &&
            input.candidate !== undefined &&
            generation.verifierKeyId === input.candidate.keyId &&
            generation.verifierDigest === input.candidate.digest;

          const currentGeneration =
            generation !== undefined &&
            generation.purpose === input.purpose &&
            generation.state === "active" &&
            series?.activeProofId === input.proofId &&
            binding !== undefined &&
            sameProofBinding(binding, input.binding) &&
            generation.expiresAtMillis > now;

          const accepted =
            authorityCurrent &&
            currentGeneration &&
            candidateMatches &&
            admitted.length === scopes.length &&
            failures < input.policy.maximumFailedAttempts;

          const write = {
            input,
            seriesKey: keys.series,
            scopes: admitted,
            nowMillis: now,
            retentionUntilMillis: now + input.policy.requestRetentionMillis,
          };

          if (!accepted) {
            const prepared = prepare({ _tag: "Rejected" }, journal);

            yield* store.recordAttempt({
              ...write,
              decision: "rejected",
              recordFailure:
                admitted.length === scopes.length &&
                currentGeneration &&
                !candidateMatches &&
                failures < input.policy.maximumFailedAttempts,
            });

            return prepared;
          }
          const version = yield* allocateProofVersion(policy, options.mode);

          const expiresAtMillis = Math.min(
            generation!.expiresAtMillis,
            now + input.policy.continuationLifetimeMillis,
          );

          const continuation = {
            moduleId: input.moduleId,
            purpose: input.purpose,
            continuationId: input.continuationId,
            digest: input.continuationDigest,
            proofId: input.proofId,
            seriesKey: keys.series,
            binding: input.binding,
            expiresAtMillis,
            version,
          };

          const prepared = prepare(
            {
              _tag: "Accepted",
              continuation: {
                continuationId: input.continuationId,
                purpose: input.purpose,
                expiresAtMillis,
              },
            },
            journal,
          );

          yield* store.recordAttempt({ ...write, scopes, decision: "accepted", continuation });

          return prepared;
        }),
      ).pipe(translateProofFailure),
    complete: (input, prepare) =>
      owned((store) =>
        Effect.gen(function* () {
          const journal = yield* CurrentCommitJournal;

          return yield* completeProofIn(policy, store, input, (decision) =>
            prepare(decision, journal),
          );
        }),
      ).pipe(translateProofFailure),
    claimDelivery: (input, prepare) =>
      owned((store) =>
        Effect.gen(function* () {
          const journal = yield* CurrentCommitJournal;

          const generation = yield* store.readGeneration(
            input.moduleId,
            input.proofId,
            options.locking,
          );

          const now = yield* nowMillis;

          if (generation === undefined) return prepare({ _tag: "Declined" }, journal);
          let state = generation.deliveryState;

          if (
            state === "claimed" &&
            generation.claimDeadlineMillis !== undefined &&
            generation.claimDeadlineMillis <= now
          ) {
            state = "ambiguous";
            yield* store.writeDelivery({
              transition: "ExpiredClaim",
              moduleId: input.moduleId,
              proofId: input.proofId,
            });
          }

          const canClaim =
            generation.version === input.version &&
            generation.deliveryId === input.deliveryId &&
            generation.state === "active" &&
            generation.expiresAtMillis > now &&
            generation.sendCount < input.policy.maximumDeliveryAttempts &&
            (state === "new" ||
              (state === "ambiguous" &&
                input.allowAmbiguousRetry &&
                (generation.retryAtMillis === undefined || generation.retryAtMillis <= now)));

          if (!canClaim) return prepare({ _tag: "Declined" }, journal);
          const claimVersion = yield* allocateProofVersion(policy, options.mode);
          const decision: ProofDeliveryClaim = { _tag: "Claimed", claimVersion };
          const prepared = prepare(decision, journal);

          yield* store.writeDelivery({
            transition: "Claim",
            moduleId: input.moduleId,
            proofId: input.proofId,
            sendCount: generation.sendCount + 1,
            claimVersion,
            claimDeadlineMillis: now + input.policy.deliveryClaimMillis,
            retryAtMillis: now + input.policy.deliveryRetryMillis,
          });

          return prepared;
        }),
      ).pipe(translateProofFailure),
    settleDelivery: (input, prepare) =>
      owned((store) =>
        Effect.gen(function* () {
          const journal = yield* CurrentCommitJournal;
          const generation = yield* store.readDeliverySettlement(input);
          const prepared = prepare(undefined, journal);

          if (
            generation === undefined ||
            generation.version !== input.version ||
            generation.deliveryId !== input.deliveryId ||
            generation.claimVersion !== input.claimVersion ||
            generation.deliveryState !== "claimed"
          )
            return prepared;

          const state =
            input.outcome._tag === "Accepted"
              ? "accepted"
              : input.outcome._tag === "DefiniteFailure"
                ? "failed"
                : "ambiguous";

          yield* store.writeDelivery({
            transition: "Settle",
            generation,
            state,
            ...(state === "ambiguous"
              ? { retryAtMillis: (yield* nowMillis) + generation.deliveryRetryMillis }
              : {}),
          });

          return prepared;
        }),
      ).pipe(translateProofFailure),
    cancel: (input, prepare) =>
      owned((store) =>
        Effect.gen(function* () {
          const journal = yield* CurrentCommitJournal;

          const current = matchesProofAuthority(
            input.binding,
            yield* store.readAuthority(input, options.locking),
          );

          const key = {
            moduleId: input.moduleId,
            purpose: input.purpose,
            scopeKey: policy.scopeKeys(input).series,
          };

          const series = yield* store.readSeries(key);
          const prepared = prepare(undefined, journal);

          if (current && series?.activeProofId !== undefined) {
            const generation = yield* store.readGeneration(
              input.moduleId,
              series.activeProofId,
              options.locking,
            );

            if (
              generation === undefined ||
              !sameProofBinding(yield* generation.binding, input.binding)
            )
              return prepared;
            yield* store.cancelGeneration(key, series.activeProofId);
          }

          return prepared;
        }),
      ).pipe(translateProofFailure),
    cleanup: (input, prepare) =>
      owned((store) =>
        Effect.gen(function* () {
          const journal = yield* CurrentCommitJournal;
          const page = yield* store.readExpired({ ...input, nowMillis: yield* nowMillis });
          const prepared = prepare(page.result, journal);

          yield* page.deleteExpired;

          return prepared;
        }),
      ).pipe(translateProofFailure),
  });
});
