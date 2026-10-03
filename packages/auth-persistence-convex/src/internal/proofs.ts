import * as Proofs from "@yielded/auth/Proofs";
import { TokenDigest } from "@yielded/auth/Schema";
import { SecurityRevision } from "@yielded/auth/Sessions";
import { Effect, Layer, Schema } from "effect";

import { DocumentStore, Transaction } from "./documents";
import {
  Identifier,
  identifierKey,
  identityPartitions,
  revisionCurrent,
  tupleKey,
} from "./identity";

const Digest = Schema.Struct({ keyId: Schema.NonEmptyString, digest: TokenDigest });

const Record = Schema.Struct({
  moduleId: Schema.NonEmptyString,
  purpose: Proofs.ProofPurpose,
  proofId: Proofs.ProofId,
  requestId: Proofs.ProofRequestId,
  fingerprint: TokenDigest,
  deliveryId: Proofs.ProofDeliveryId,
  binding: Proofs.ProofBinding,
  issuedAtMillis: Proofs.ProofInstant,
  expiresAtMillis: Proofs.ProofInstant,
  version: Proofs.ProofVersion,
});

const Generation = Schema.Struct({
  record: Record,
  verifier: Schema.NullOr(Digest),
  identifierRevision: Schema.NullOr(SecurityRevision),
  policy: Proofs.ProofPolicy,
  series: Schema.String,
  state: Schema.Literals(["active", "consumed", "superseded", "cancelled", "expired"]),
  retentionUntil: Proofs.ProofInstant,
  sendCount: Schema.Natural,
  deliveryState: Schema.Literals(["new", "claimed", "accepted", "failed", "ambiguous"]),
  claimVersion: Schema.NullOr(Proofs.ProofVersion),
  claimDeadline: Schema.NullOr(Proofs.ProofInstant),
  retryAt: Schema.NullOr(Proofs.ProofInstant),
});

type Generation = typeof Generation.Type;

const Request = Schema.Struct({
  fingerprint: TokenDigest,
  receipt: Proofs.ProofRequestReceipt,
  retentionUntil: Proofs.ProofInstant,
});

const Series = Schema.Struct({
  proofId: Proofs.ProofId,
  lastIssueAt: Proofs.ProofInstant,
  retentionUntil: Proofs.ProofInstant,
});

const Continuation = Schema.Struct({
  purpose: Proofs.ProofPurpose,
  proofId: Proofs.ProofId,
  digest: Schema.NullOr(TokenDigest),
  binding: Proofs.ProofBinding,
  expiresAt: Proofs.ProofInstant,
  consumed: Schema.Boolean,
  retentionUntil: Proofs.ProofInstant,
});

const DigestReservation = Schema.Struct({
  continuationId: Proofs.ProofContinuationId,
  retentionUntil: Proofs.ProofInstant,
});

const Charge = Schema.Struct({
  occurredAt: Proofs.ProofInstant,
  retentionUntil: Proofs.ProofInstant,
});

const CleanupEntry = Schema.Struct({
  kind: Schema.Literals([
    "generation",
    "generation-expiry",
    "request",
    "series",
    "continuation",
    "continuation-expiry",
    "digest",
    "charge",
  ]),
  key: Schema.String,
  scope: Schema.String,
  at: Proofs.ProofInstant,
});

type CleanupEntry = typeof CleanupEntry.Type;

const partition = (moduleId: string, kind: string, scope = "") =>
  tupleKey("proofs", moduleId, kind, scope);

const seriesKey = (purpose: string, binding: Proofs.ProofBinding) =>
  tupleKey(purpose, binding.identifier.namespace, binding.identifier.value);

// The store's authority clock is nonnegative. Fixed-width milliseconds preserve
// chronological order in Convex's string index, including equal-time entries.
const timeKey = (at: number) => Math.max(0, at).toString().padStart(16, "0");

const cleanupKey = (entry: CleanupEntry) =>
  `${timeKey(entry.at)}:${tupleKey(entry.kind, entry.scope, entry.key)}`;

const sameBinding = Schema.toEquivalence(Proofs.ProofBinding);

const scheduleCleanup = Effect.fnUntraced(function* (moduleId: string, entry: CleanupEntry) {
  const tx = yield* Transaction;

  yield* tx.put(CleanupEntry, partition(moduleId, "cleanup"), cleanupKey(entry), entry);
});

const unscheduleCleanup = Effect.fnUntraced(function* (moduleId: string, entry: CleanupEntry) {
  const tx = yield* Transaction;

  yield* tx.remove(partition(moduleId, "cleanup"), cleanupKey(entry));
});

/** Identifier-only proofs bind an unowned destination. Subject proofs bind its
 * current owner; identifier changes may target an unowned or own unverified
 * destination. Method adapters own eligibility (for example verified reset email).
 */
const bindingCurrent = Effect.fnUntraced(function* (
  binding: Proofs.ProofBinding,
  expectedIdentifierRevision?: SecurityRevision | null,
) {
  const tx = yield* Transaction;

  const identifier = yield* tx.get(
    Identifier,
    identityPartitions.identifiers,
    identifierKey(binding.identifier),
  );

  if (
    identifier !== undefined &&
    (identifier.identifier.namespace !== binding.identifier.namespace ||
      identifier.identifier.value !== binding.identifier.value)
  )
    return false;
  if (
    expectedIdentifierRevision !== undefined &&
    (identifier?.bindingRevision ?? null) !== expectedIdentifierRevision
  )
    return false;
  if (binding._tag === "Identifier") return identifier === undefined;
  if (!(yield* revisionCurrent(binding.revision))) return false;

  return binding._tag === "IdentifierChange"
    ? identifier === undefined ||
        (identifier.subjectId === binding.revision.subjectId &&
          identifier.verifiedAtMillis === undefined)
    : identifier?.subjectId === binding.revision.subjectId;
});

interface Budget {
  readonly scope: string;
  readonly limit: number;
  readonly windowMillis: number;
}

const budgets = (
  purpose: Proofs.ProofPurpose,
  binding: Proofs.ProofBinding,
  action: "issue" | "attempt",
  policy: Proofs.ProofPolicy,
): ReadonlyArray<Budget> => [
  {
    scope: tupleKey(purpose, action, "action"),
    ...(action === "issue" ? policy.abuse.actionIssues : policy.abuse.actionAttempts),
  },
  {
    scope: tupleKey(
      purpose,
      action,
      "identifier",
      binding.identifier.namespace,
      binding.identifier.value,
    ),
    ...(action === "issue" ? policy.abuse.issues : policy.abuse.attempts),
  },
  ...(binding._tag === "Identifier"
    ? []
    : [
        {
          scope: tupleKey(purpose, action, "subject", binding.revision.subjectId),
          ...(action === "issue" ? policy.abuse.subjectIssues : policy.abuse.subjectAttempts),
        },
      ]),
];

const failureBudget = (
  purpose: Proofs.ProofPurpose,
  binding: Proofs.ProofBinding,
  policy: Proofs.ProofPolicy,
): Budget => ({
  scope: tupleKey(purpose, "failure", binding.identifier.namespace, binding.identifier.value),
  limit: policy.maximumFailedAttempts,
  windowMillis: policy.abuse.attempts.windowMillis,
});

/** Point-sized charge records avoid ever growing a budget document. Read only
 * this scope's live rolling window, with explicit pagination. Larger windows
 * than the transaction's bounded read capacity fail closed, never undercount.
 */
const budgetOpen = Effect.fnUntraced(function* (moduleId: string, budget: Budget) {
  const tx = yield* Transaction;
  let after = timeKey(tx.now - budget.windowMillis);
  let count = 0;

  for (let page = 0; page < 16; page++) {
    const limit = Math.min(500, budget.limit - count);

    const rows = yield* tx.scan(Charge, partition(moduleId, "charge", budget.scope), {
      after,
      limit,
    });

    count += rows.length;
    if (count >= budget.limit) return false;
    if (rows.length < limit) return true;
    const last = rows[rows.length - 1];

    if (last === undefined) return true;
    after = last.key;
  }

  return yield* Proofs.ProofUnavailable.make({});
});

const addCharge = Effect.fnUntraced(function* (
  moduleId: string,
  budget: Budget,
  retentionMillis: number,
) {
  const tx = yield* Transaction;
  const key = `${timeKey(tx.now)}:${yield* tx.id}`;
  // The left endpoint is inclusive, so cleanup starts one millisecond later.
  const retentionUntil = tx.now + Math.max(retentionMillis, budget.windowMillis) + 1;

  yield* tx.put(Charge, partition(moduleId, "charge", budget.scope), key, {
    occurredAt: tx.now,
    retentionUntil,
  });
  yield* scheduleCleanup(moduleId, {
    kind: "charge",
    key,
    scope: budget.scope,
    at: retentionUntil,
  });
});

const charge = Effect.fnUntraced(function* (
  moduleId: string,
  entries: ReadonlyArray<Budget>,
  retentionMillis: number,
) {
  let admitted = true;

  for (const budget of entries) {
    if (yield* budgetOpen(moduleId, budget)) yield* addCharge(moduleId, budget, retentionMillis);
    else admitted = false;
  }

  return admitted;
});

const terminalGeneration = Effect.fnUntraced(function* (
  row: Generation,
  state: Generation["state"],
) {
  const tx = yield* Transaction;

  yield* tx.put(Generation, partition(row.record.moduleId, "generation"), row.record.proofId, {
    ...row,
    state,
    verifier: null,
  });
  yield* unscheduleCleanup(row.record.moduleId, {
    kind: "generation-expiry",
    key: row.record.proofId,
    scope: "",
    at: row.record.expiresAtMillis,
  });
});

/** This check joins the caller's Transaction and registers the continuation's
 * final-commit deadline. Its boolean never grants authentication by itself.
 */
export const completionCurrent = Effect.fnUntraced(function* (
  input: Proofs.ProofCompletionInput,
): Effect.fn.Return<boolean, Proofs.ProofUnavailable, Transaction> {
  return yield* Effect.gen(function* () {
    const tx = yield* Transaction;

    const row = yield* tx.get(
      Continuation,
      partition(input.moduleId, "continuation"),
      input.continuationId,
    );

    if (
      row === undefined ||
      row.consumed ||
      row.expiresAt <= tx.now ||
      row.purpose !== input.purpose ||
      row.digest !== input.continuationDigest ||
      !sameBinding(row.binding, input.binding)
    )
      return false;
    const proof = yield* tx.get(Generation, partition(input.moduleId, "generation"), row.proofId);

    if (
      proof === undefined ||
      proof.state !== "consumed" ||
      proof.record.moduleId !== input.moduleId ||
      proof.record.proofId !== row.proofId ||
      proof.record.purpose !== input.purpose ||
      !sameBinding(proof.record.binding, input.binding) ||
      !(yield* bindingCurrent(input.binding, proof.identifierRevision))
    )
      return false;
    yield* tx.before(Math.min(row.expiresAt, proof.record.expiresAtMillis));

    return true;
  }).pipe(Effect.mapError(() => Proofs.ProofUnavailable.make({})));
});

/** Call before changing identity/credentials in the same Transaction. A false
 * result must reject the protected write. No nested transaction or commit occurs.
 */
export const consumeCompletion = Effect.fnUntraced(function* (
  input: Proofs.ProofCompletionInput,
): Effect.fn.Return<boolean, Proofs.ProofUnavailable, Transaction> {
  return yield* Effect.gen(function* () {
    if (!(yield* completionCurrent(input))) return false;
    const tx = yield* Transaction;

    const row = yield* tx.get(
      Continuation,
      partition(input.moduleId, "continuation"),
      input.continuationId,
    );

    if (row === undefined) return yield* Proofs.ProofUnavailable.make({});
    yield* tx.put(Continuation, partition(input.moduleId, "continuation"), input.continuationId, {
      ...row,
      consumed: true,
      digest: null,
    });
    yield* unscheduleCleanup(input.moduleId, {
      kind: "continuation-expiry",
      key: input.continuationId,
      scope: "",
      at: row.expiresAt,
    });

    return true;
  }).pipe(Effect.mapError(() => Proofs.ProofUnavailable.make({})));
});

export const layer = Layer.effect(
  Proofs.ProofPersistence,
  Effect.gen(function* () {
    const store = yield* DocumentStore;

    return Proofs.ProofPersistence.of({
      issue: (input, prepare) =>
        store
          .transaction(
            Effect.gen(function* () {
              const tx = yield* Transaction;
              const { record } = input;

              const policy = yield* Proofs.validateProofPolicy(input.policy).pipe(
                Effect.mapError(() => Proofs.ProofUnavailable.make({})),
              );

              const previous = yield* tx.get(
                Request,
                partition(record.moduleId, "request"),
                record.requestId,
              );

              if (previous !== undefined && previous.retentionUntil > tx.now) {
                if (previous.fingerprint !== record.fingerprint)
                  return yield* Proofs.ProofRequestConflict.make({});

                return prepare({ _tag: "Existing", receipt: previous.receipt }, tx.journal);
              }

              const receipt: Proofs.ProofRequestReceipt = {
                requestId: record.requestId,
                reference: {
                  proofId: record.proofId,
                  purpose: record.purpose,
                  keyId: record.verifier.keyId,
                },
              };

              const retentionUntil = tx.now + policy.requestRetentionMillis;

              if (previous !== undefined)
                yield* unscheduleCleanup(record.moduleId, {
                  kind: "request",
                  key: record.requestId,
                  scope: "",
                  at: previous.retentionUntil,
                });
              yield* tx.put(Request, partition(record.moduleId, "request"), record.requestId, {
                fingerprint: record.fingerprint,
                receipt,
                retentionUntil,
              });
              yield* scheduleCleanup(record.moduleId, {
                kind: "request",
                key: record.requestId,
                scope: "",
                at: retentionUntil,
              });

              const admitted = yield* charge(
                record.moduleId,
                budgets(record.purpose, record.binding, "issue", policy),
                policy.requestRetentionMillis,
              );

              const key = seriesKey(record.purpose, record.binding);
              const series = yield* tx.get(Series, partition(record.moduleId, "series"), key);

              const predecessor =
                series === undefined
                  ? undefined
                  : yield* tx.get(
                      Generation,
                      partition(record.moduleId, "generation"),
                      series.proofId,
                    );

              if (
                !admitted ||
                !input.eligible ||
                (series !== undefined &&
                  series.lastIssueAt > tx.now - policy.abuse.resendCooldownMillis) ||
                record.expiresAtMillis <= tx.now ||
                record.expiresAtMillis > tx.now + policy.lifetimeMillis ||
                !(yield* bindingCurrent(record.binding)) ||
                (yield* tx.get(
                  Generation,
                  partition(record.moduleId, "generation"),
                  record.proofId,
                )) !== undefined ||
                (input.supersedes !== undefined &&
                  (predecessor?.state !== "active" ||
                    predecessor.record.proofId !== input.supersedes ||
                    !sameBinding(predecessor.record.binding, record.binding)))
              )
                return prepare({ _tag: "Suppressed", receipt }, tx.journal);

              const identifier = yield* tx.get(
                Identifier,
                identityPartitions.identifiers,
                identifierKey(record.binding.identifier),
              );

              const fresh: Proofs.ProofRecord = { ...record, issuedAtMillis: tx.now };
              const result = prepare({ _tag: "Issued", record: fresh }, tx.journal);

              yield* tx.before(fresh.expiresAtMillis);
              if (predecessor?.state === "active")
                yield* terminalGeneration(predecessor, "superseded");
              const { verifier, ...metadata } = fresh;

              yield* tx.put(Generation, partition(record.moduleId, "generation"), record.proofId, {
                record: metadata,
                verifier,
                identifierRevision: identifier?.bindingRevision ?? null,
                policy,
                series: key,
                state: "active",
                retentionUntil,
                sendCount: 0,
                deliveryState: "new",
                claimVersion: null,
                claimDeadline: null,
                retryAt: null,
              });
              yield* scheduleCleanup(record.moduleId, {
                kind: "generation",
                key: record.proofId,
                scope: "",
                at: retentionUntil,
              });
              yield* scheduleCleanup(record.moduleId, {
                kind: "generation-expiry",
                key: record.proofId,
                scope: "",
                at: fresh.expiresAtMillis,
              });
              if (series !== undefined)
                yield* unscheduleCleanup(record.moduleId, {
                  kind: "series",
                  key,
                  scope: "",
                  at: series.retentionUntil,
                });

              const seriesRetention = Math.max(
                retentionUntil,
                series?.retentionUntil ?? retentionUntil,
              );

              yield* tx.put(Series, partition(record.moduleId, "series"), key, {
                proofId: record.proofId,
                lastIssueAt: tx.now,
                retentionUntil: seriesRetention,
              });
              yield* scheduleCleanup(record.moduleId, {
                kind: "series",
                key,
                scope: "",
                at: seriesRetention,
              });

              return result;
            }),
          )
          .pipe(
            Effect.catchTag(["ConvexPersistenceUnavailable", "ConvexTransactionConflict"], () =>
              Proofs.ProofUnavailable.make({}),
            ),
          ),

      attempt: (input, prepare) =>
        store
          .transaction(
            Effect.gen(function* () {
              const tx = yield* Transaction;

              const row = yield* tx.get(
                Generation,
                partition(input.moduleId, "generation"),
                input.proofId,
              );

              // An unrelated candidate must not select another binding's policy.
              const policy = yield* Proofs.validateProofPolicy(
                row?.record.purpose === input.purpose &&
                  sameBinding(row.record.binding, input.binding)
                  ? row.policy
                  : input.policy,
              );

              const admitted = yield* charge(
                input.moduleId,
                budgets(input.purpose, input.binding, "attempt", policy),
                policy.requestRetentionMillis,
              );

              const failure = failureBudget(input.purpose, input.binding, policy);
              const failuresOpen = yield* budgetOpen(input.moduleId, failure);
              const key = seriesKey(input.purpose, input.binding);
              const series = yield* tx.get(Series, partition(input.moduleId, "series"), key);

              if (
                !admitted ||
                !failuresOpen ||
                row === undefined ||
                row.state !== "active" ||
                row.record.moduleId !== input.moduleId ||
                row.record.proofId !== input.proofId ||
                row.record.purpose !== input.purpose ||
                row.series !== key ||
                series?.proofId !== input.proofId ||
                row.record.expiresAtMillis <= tx.now ||
                !sameBinding(row.record.binding, input.binding) ||
                !(yield* bindingCurrent(input.binding, row.identifierRevision)) ||
                row.verifier === null ||
                input.candidate === undefined ||
                input.candidate.keyId !== row.verifier.keyId ||
                input.candidate.digest !== row.verifier.digest ||
                (yield* tx.get(
                  Continuation,
                  partition(input.moduleId, "continuation"),
                  input.continuationId,
                )) !== undefined ||
                (yield* tx.get(
                  DigestReservation,
                  partition(input.moduleId, "digest"),
                  input.continuationDigest,
                )) !== undefined
              ) {
                if (failuresOpen)
                  yield* addCharge(input.moduleId, failure, policy.requestRetentionMillis);
                if (row?.state === "active" && row.record.expiresAtMillis <= tx.now)
                  yield* terminalGeneration(row, "expired");

                return prepare({ _tag: "Rejected" }, tx.journal);
              }

              const expiresAt = Math.min(
                row.record.expiresAtMillis,
                tx.now + policy.continuationLifetimeMillis,
              );

              const result = prepare(
                {
                  _tag: "Accepted",
                  continuation: {
                    continuationId: input.continuationId,
                    purpose: input.purpose,
                    expiresAtMillis: expiresAt,
                  },
                },
                tx.journal,
              );

              yield* tx.before(expiresAt);
              yield* terminalGeneration(row, "consumed");
              yield* tx.put(
                Continuation,
                partition(input.moduleId, "continuation"),
                input.continuationId,
                {
                  purpose: input.purpose,
                  proofId: input.proofId,
                  digest: input.continuationDigest,
                  binding: input.binding,
                  expiresAt,
                  consumed: false,
                  retentionUntil: row.retentionUntil,
                },
              );
              yield* tx.put(
                DigestReservation,
                partition(input.moduleId, "digest"),
                input.continuationDigest,
                {
                  continuationId: input.continuationId,
                  retentionUntil: row.retentionUntil,
                },
              );
              yield* scheduleCleanup(input.moduleId, {
                kind: "continuation",
                key: input.continuationId,
                scope: "",
                at: row.retentionUntil,
              });
              yield* scheduleCleanup(input.moduleId, {
                kind: "continuation-expiry",
                key: input.continuationId,
                scope: "",
                at: expiresAt,
              });
              yield* scheduleCleanup(input.moduleId, {
                kind: "digest",
                key: input.continuationDigest,
                scope: "",
                at: row.retentionUntil,
              });

              return result;
            }),
          )
          .pipe(Effect.mapError(() => Proofs.ProofUnavailable.make({}))),

      complete: (input, prepare) =>
        store
          .transaction(
            Effect.gen(function* () {
              const tx = yield* Transaction;
              const consumed = yield* consumeCompletion(input);

              return prepare(consumed ? "completed" : "rejected", tx.journal);
            }),
          )
          .pipe(Effect.mapError(() => Proofs.ProofUnavailable.make({}))),

      claimDelivery: (input, prepare) =>
        store
          .transaction(
            Effect.gen(function* () {
              const tx = yield* Transaction;

              let row = yield* tx.get(
                Generation,
                partition(input.moduleId, "generation"),
                input.proofId,
              );

              if (
                row === undefined ||
                row.record.moduleId !== input.moduleId ||
                row.record.proofId !== input.proofId ||
                row.record.version !== input.version ||
                row.record.deliveryId !== input.deliveryId
              )
                return prepare({ _tag: "Declined" }, tx.journal);
              if (row.deliveryState === "claimed" && (row.claimDeadline ?? 0) <= tx.now) {
                row = { ...row, deliveryState: "ambiguous" };
                yield* tx.put(
                  Generation,
                  partition(input.moduleId, "generation"),
                  input.proofId,
                  row,
                );
              }
              const policy = yield* Proofs.validateProofPolicy(input.policy);
              const series = yield* tx.get(Series, partition(input.moduleId, "series"), row.series);

              if (
                row.state !== "active" ||
                row.verifier === null ||
                row.record.expiresAtMillis <= tx.now ||
                series?.proofId !== input.proofId ||
                row.sendCount >=
                  Math.min(row.policy.maximumDeliveryAttempts, policy.maximumDeliveryAttempts) ||
                !(
                  row.deliveryState === "new" ||
                  (row.deliveryState === "ambiguous" &&
                    input.allowAmbiguousRetry &&
                    (row.retryAt ?? 0) <= tx.now)
                ) ||
                !(yield* bindingCurrent(row.record.binding, row.identifierRevision))
              )
                return prepare({ _tag: "Declined" }, tx.journal);
              const claimVersion = Proofs.ProofVersion.make(yield* tx.id);

              const claimDeadline = Math.min(
                row.record.expiresAtMillis,
                tx.now + Math.min(row.policy.deliveryClaimMillis, policy.deliveryClaimMillis),
              );

              const result = prepare({ _tag: "Claimed", claimVersion }, tx.journal);

              yield* tx.before(claimDeadline);
              yield* tx.put(Generation, partition(input.moduleId, "generation"), input.proofId, {
                ...row,
                deliveryState: "claimed",
                claimVersion,
                claimDeadline,
                sendCount: row.sendCount + 1,
                retryAt:
                  tx.now + Math.max(row.policy.deliveryRetryMillis, policy.deliveryRetryMillis),
              });

              return result;
            }),
          )
          .pipe(Effect.mapError(() => Proofs.ProofUnavailable.make({}))),

      settleDelivery: (input, prepare) =>
        store
          .transaction(
            Effect.gen(function* () {
              const tx = yield* Transaction;
              const result = prepare(undefined, tx.journal);

              const row = yield* tx.get(
                Generation,
                partition(input.moduleId, "generation"),
                input.proofId,
              );

              if (
                row === undefined ||
                row.record.moduleId !== input.moduleId ||
                row.record.proofId !== input.proofId ||
                row.record.version !== input.version ||
                row.record.deliveryId !== input.deliveryId ||
                row.claimVersion !== input.claimVersion ||
                row.deliveryState !== "claimed"
              )
                return result;
              const failed = input.outcome._tag === "DefiniteFailure";

              const settled: Generation = {
                ...row,
                deliveryState:
                  input.outcome._tag === "Accepted" ? "accepted" : failed ? "failed" : "ambiguous",
                retryAt: Math.max(row.retryAt ?? 0, tx.now + row.policy.deliveryRetryMillis),
              };

              if (failed && row.state === "active") yield* terminalGeneration(settled, "cancelled");
              else
                yield* tx.put(
                  Generation,
                  partition(input.moduleId, "generation"),
                  input.proofId,
                  settled,
                );

              return result;
            }),
          )
          .pipe(Effect.mapError(() => Proofs.ProofUnavailable.make({}))),

      cancel: (input, prepare) =>
        store
          .transaction(
            Effect.gen(function* () {
              const tx = yield* Transaction;
              const result = prepare(undefined, tx.journal);

              const series = yield* tx.get(
                Series,
                partition(input.moduleId, "series"),
                seriesKey(input.purpose, input.binding),
              );

              const row =
                series === undefined
                  ? undefined
                  : yield* tx.get(
                      Generation,
                      partition(input.moduleId, "generation"),
                      series.proofId,
                    );

              if (
                row?.state === "active" &&
                row.record.moduleId === input.moduleId &&
                row.record.purpose === input.purpose &&
                sameBinding(row.record.binding, input.binding) &&
                (yield* bindingCurrent(input.binding, row.identifierRevision))
              )
                yield* terminalGeneration(row, "cancelled");

              return result;
            }),
          )
          .pipe(Effect.mapError(() => Proofs.ProofUnavailable.make({}))),

      cleanup: (input, prepare) =>
        store
          .transaction(
            Effect.gen(function* () {
              const tx = yield* Transaction;
              const requested = yield* Schema.decodeUnknownEffect(Schema.Natural)(input.limit);
              // Leave capacity for the point observations and writes behind each entry.
              const limit = Math.min(requested, 20);

              const entries = yield* tx.scan(CleanupEntry, partition(input.moduleId, "cleanup"), {
                limit: limit + 1,
              });

              let removed = 0;

              for (const { key, value: entry } of entries.slice(0, limit)) {
                if (entry.at > tx.now) break;
                if (key !== cleanupKey(entry)) return yield* Proofs.ProofUnavailable.make({});
                if (entry.kind === "generation-expiry") {
                  const row = yield* tx.get(
                    Generation,
                    partition(input.moduleId, "generation"),
                    entry.key,
                  );

                  if (
                    row !== undefined &&
                    row.record.expiresAtMillis === entry.at &&
                    row.state === "active"
                  ) {
                    yield* tx.put(Generation, partition(input.moduleId, "generation"), entry.key, {
                      ...row,
                      state: "expired",
                      verifier: null,
                    });
                  }
                } else if (entry.kind === "continuation-expiry") {
                  const row = yield* tx.get(
                    Continuation,
                    partition(input.moduleId, "continuation"),
                    entry.key,
                  );

                  if (row !== undefined && row.expiresAt === entry.at) {
                    yield* tx.put(
                      Continuation,
                      partition(input.moduleId, "continuation"),
                      entry.key,
                      { ...row, consumed: true, digest: null },
                    );
                  }
                } else {
                  yield* tx.remove(partition(input.moduleId, entry.kind, entry.scope), entry.key);
                }
                yield* tx.remove(partition(input.moduleId, "cleanup"), key);
                removed++;
              }
              const next = entries[removed];

              return prepare(
                { removed, hasMore: next !== undefined && next.value.at <= tx.now },
                tx.journal,
              );
            }),
          )
          .pipe(Effect.mapError(() => Proofs.ProofUnavailable.make({}))),
    });
  }),
);

/** Convex proof commands. Provide DocumentStore; method-specific atomic writes
 * use the internal Transaction helpers before changing their captured authority.
 */
export const ProofPersistence = { layer };
