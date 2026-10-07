import {
  makeProofWorkflow,
  completeProofPlan,
  inspectProofCompletion,
  requiredProofConstraints,
} from "@yielded/auth-persistence/Adapter";
import {
  ProofUnavailable,
  type ProofCompletionPlan,
  type ProofCompletionDecision,
} from "@yielded/auth/Proofs";
import { Effect } from "effect";

import { NativeDatabase } from "./native-database";
import { CurrentProofSql, type ProofSqlConfiguration } from "./proof-database";
import { type Mapping, readRows } from "./proof-native";
import { completionSnapshot, makeProofOwner, proofCompletionStore } from "./proof-store";
import { readSnapshot, type SnapshotRead } from "./sql-snapshot";
import { validateDrizzleStorage } from "./storage-validation";
export { CurrentProofSql } from "./proof-database";
export type { ProofSqlConfiguration } from "./proof-database";

export const makeSqlProofPersistence = Effect.fnUntraced(function* (
  mapping: Mapping,
  initialConfiguration: ProofSqlConfiguration,
) {
  const database = yield* CurrentProofSql;
  const native = yield* NativeDatabase;

  const configuration = {
    ...initialConfiguration,
    pgOrderedLocks: native.$client.onDialectOrElse({
      pg: () => initialConfiguration.locking,
      orElse: () => false,
    }),
  };

  if (
    !Object.entries(requiredProofConstraints).every(
      ([key, value]) => mapping.constraints[key as keyof typeof requiredProofConstraints] === value,
    )
  )
    return yield* ProofUnavailable.make({});
  if (!configuration.coordinated)
    yield* validateDrizzleStorage(mapping).pipe(Effect.mapError(() => ProofUnavailable.make({})));
  const owner = yield* makeProofOwner(mapping, configuration, database);

  return yield* makeProofWorkflow(mapping, configuration, owner);
});

export const checkProofCompletionIn = Effect.fn("Drizzle.checkProofCompletionIn")(function* <
  E = never,
  R = never,
>(
  mapping: Mapping,
  configuration: ProofSqlConfiguration,
  input: ProofCompletionPlan["input"],
  advisory?: {
    readonly reads: ReadonlyArray<SnapshotRead>;
    readonly current: (
      rows: ReadonlyArray<ReadonlyArray<Record<string, unknown>>>,
    ) => Effect.Effect<boolean, E, R>;
    readonly fallback: Effect.Effect<boolean, E, R>;
  },
) {
  const database = yield* CurrentProofSql;
  const read = yield* completionSnapshot(mapping, configuration, database, input, false);

  if (advisory === undefined)
    return (
      (yield* inspectProofCompletion(
        mapping,
        input,
        yield* read.decode(yield* readRows(database, read.reads, configuration)),
        false,
      )) !== undefined
    );

  const snapshot = readSnapshot(
    database,
    [...advisory.reads, ...read.reads],
    configuration.maxParameters,
  );

  if (!snapshot.singleStatement) return yield* advisory.fallback;
  const rows = yield* snapshot.rows;

  if (!(yield* advisory.current(rows.slice(0, advisory.reads.length)))) return false;

  return (
    (yield* inspectProofCompletion(
      mapping,
      input,
      yield* read.decode(rows.slice(advisory.reads.length)),
      false,
    )) !== undefined
  );
});

/** Cross-feature completion shares the caller's physical transaction and journal. */
export const completeProofPlanIn = Effect.fn("Drizzle.completeProofPlanIn")(function* <A, E, R>(
  mapping: Mapping,
  configuration: ProofSqlConfiguration,
  plan: ProofCompletionPlan,
  protectedMutation: Effect.Effect<boolean, E, R>,
  project: (decision: ProofCompletionDecision) => A,
) {
  const store = proofCompletionStore(mapping, configuration, yield* CurrentProofSql);

  return yield* completeProofPlan(mapping, store, plan, protectedMutation, project);
});
