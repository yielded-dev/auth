/* oxlint-disable no-explicit-any -- existing mapped-row bridge; public adapters preserve table, ID, and Effect types. */

import type { PasskeyCeremony, PasskeyMethodPolicy } from "@yielded/auth/Passkey";
import { Effect } from "effect";

import type { PasskeyChargeKind } from "../models/passkey-model";
import type { SqlExpression as SQL, QueryOperations } from "../query-operations";
import type { makeTransactionKernel, Observation, TransactionRead } from "../transaction-kernel";
import { CurrentPasskeyTransaction } from "./state";
import type { makePasskeyStateKernel } from "./state";

export const makePasskeyAdmissionKernel = (
  operations: QueryOperations,
  state: Pick<
    ReturnType<typeof makePasskeyStateKernel>,
    | "col"
    | "equal"
    | "existsExact"
    | "invariant"
    | "key"
    | "mappedColumns"
    | "subjectScope"
    | "targetScope"
  >,
  transactions: Pick<ReturnType<typeof makeTransactionKernel>, "both">,
) => {
  const { sql } = operations;
  const { col, equal, existsExact, key, mappedColumns, subjectScope, targetScope } = state;
  const invariant: (value: unknown) => asserts value = state.invariant;
  const { both } = transactions;

  const chargeRetentionMillis = 86_400_000;

  const chargeScopes = Effect.fnUntraced(function* (ceremony: PasskeyCeremony, subjectId?: string) {
    const scopes: { kind: PasskeyChargeKind; scope: string }[] = [
      { kind: "global", scope: yield* key("global", [ceremony.moduleId]) },
    ];

    if (subjectId !== undefined)
      scopes.push({ kind: "subject", scope: yield* subjectScope(subjectId) });
    const target = yield* targetScope(ceremony);

    if (target !== null) scopes.push({ kind: "target", scope: target });

    return scopes;
  });

  const admissionRead = (mapping: any): TransactionRead => {
    const table = mapping.admission;

    return {
      table: table.table,
      where: equal(table.table, {
        [table.authorityScope]: mapping.authorityScope,
        [table.moduleId]: mapping.moduleId,
      }),
      options: { limit: 1, columns: [table.authorityScope, table.moduleId], clock: mapping.clock },
    };
  };

  const lockAdmission = Effect.fn("passkey.lockAdmission")(function* (
    mapping: any,
    captured?: Observation,
  ) {
    const owner = yield* CurrentPasskeyTransaction;
    const table = mapping.admission;
    const request = admissionRead(mapping);
    const found = captured ?? (yield* owner.read(request.table, request.where, request.options));
    const row = found.rows[0];

    // PostgreSQL locks the admission row; SQLite serializes physical writes.
    // D1 rechecks admission and the rolling budgets inside its atomic batch.
    invariant(
      row !== undefined &&
        row[table.authorityScope] === mapping.authorityScope &&
        row[table.moduleId] === mapping.moduleId &&
        found.nowMillis !== undefined,
    );

    return found.nowMillis;
  });

  const pendingCount = (mapping: any, scope?: string) => {
    const table = mapping.flow;

    return sql`(select count(*) from ${table.table} where ${both(
      equal(table.table, { [table.moduleId]: mapping.moduleId }),
      sql`${col(table.table, table.state)} in (${table.states.Pending}, ${table.states.Claimed})`,
      scope === undefined ? undefined : equal(table.table, { [table.subjectScope]: scope }),
    )})`;
  };

  const chargedCount = (mapping: any, kind: PasskeyChargeKind, scope: string, window: number) => {
    const table = mapping.charge;
    const clock = mapping.clock;

    return sql`(select count(*) from ${table.table} where ${both(
      equal(table.table, { [table.moduleId]: mapping.moduleId, [table.kind]: kind }),
      kind === "global" ? undefined : equal(table.table, { [table.scope]: scope }),
      sql`${col(table.table, table.admittedAt)} is not null`,
      sql`${clock.toMillis(sql`${col(table.table, table.admittedAt)}`)} > ${clock.engineNowMillis} - ${window}`,
    )})`;
  };

  const admissionCondition = Effect.fnUntraced(function* (
    mapping: any,
    policies: ReadonlyArray<PasskeyMethodPolicy>,
    ceremony: PasskeyCeremony,
    subjectId: string | undefined,
    added: ReadonlyArray<PasskeyChargeKind>,
    newFlow: boolean,
    resolvedSubject: boolean,
  ) {
    const subject = subjectId === undefined ? undefined : yield* subjectScope(subjectId);
    const scopes = yield* chargeScopes(ceremony, subjectId);

    return both(
      ...policies.flatMap((policy) => [
        sql`${pendingCount(mapping)} + ${newFlow ? 1 : 0} <= ${policy.maximumPending}`,
        subjectId === undefined
          ? undefined
          : sql`${pendingCount(mapping, subject)} + ${newFlow || resolvedSubject ? 1 : 0} <= ${policy.maximumPendingPerSubject}`,
        ...scopes.map(
          ({ kind, scope }) =>
            sql`${chargedCount(mapping, kind, scope, policy.admission[kind].windowMillis)} + ${added.includes(kind) ? 1 : 0} <= ${policy.admission[kind].limit}`,
        ),
      ]),
    );
  });

  const guardAdmission = (
    mapping: any,
    policies: ReadonlyArray<PasskeyMethodPolicy>,
    ceremony: PasskeyCeremony,
    subjectId?: string,
  ) =>
    Effect.gen(function* () {
      const owner = yield* CurrentPasskeyTransaction;

      owner.postconditions.push(
        yield* admissionCondition(mapping, policies, ceremony, subjectId, [], false, false),
      );
    });

  const chargeRead = (mapping: any, ceremony: PasskeyCeremony): TransactionRead => {
    const table = mapping.charge;

    return {
      table: table.table,
      where: equal(table.table, {
        [table.moduleId]: ceremony.moduleId,
        [table.flowId]: ceremony.flowId,
      }),
      options: { limit: 3, observe: false, columns: mappedColumns(table) },
    };
  };

  const readCharges = Effect.fn("passkey.readCharges")(function* (
    mapping: any,
    ceremony: PasskeyCeremony,
    policy: PasskeyMethodPolicy,
    subjectId?: string,
    captured?: Observation,
  ) {
    const owner = yield* CurrentPasskeyTransaction;
    const table = mapping.charge;

    const request = chargeRead(mapping, ceremony);
    const found = captured ?? (yield* owner.read(request.table, request.where, request.options));

    const scopes = yield* chargeScopes(ceremony, subjectId);

    invariant(found.rows.length === scopes.length);
    for (const { kind, scope } of scopes) {
      const rows = found.rows.filter((row) => row[table.kind] === kind);

      invariant(rows.length === 1);
      const row = rows[0]!;
      const admitted = mapping.clock.decodeInstant(row[table.admittedAt]);
      const retained = mapping.clock.decodeInstant(row[table.retainUntil]);

      invariant(
        Number.isSafeInteger(admitted) &&
          admitted >= 0 &&
          retained === admitted + chargeRetentionMillis,
      );
      invariant(
        row[table.moduleId] === ceremony.moduleId &&
          row[table.flowId] === ceremony.flowId &&
          row[table.purpose] === ceremony.purpose,
      );
      invariant(
        row[table.scope] === scope &&
          row[table.originalWindowMillis] === policy.admission[kind].windowMillis,
      );
      owner.observations.push({
        table: table.table,
        where: equal(table.table, {
          [table.moduleId]: ceremony.moduleId,
          [table.flowId]: ceremony.flowId,
          [table.kind]: kind,
        }),
        rows: [row],
      });
    }
  });

  const guardChargeSet = (mapping: any, ceremony: PasskeyCeremony, subjectId?: string) =>
    Effect.flatMap(CurrentPasskeyTransaction, (owner) =>
      Effect.gen(function* () {
        const table = mapping.charge;
        const scopes = yield* chargeScopes(ceremony, subjectId);

        const where = equal(table.table, {
          [table.moduleId]: ceremony.moduleId,
          [table.flowId]: ceremony.flowId,
        });

        owner.postconditions.push(
          sql`(select count(*) from ${table.table} where ${where}) = ${scopes.length}`,
        );
        for (const { kind, scope } of scopes)
          owner.postconditions.push(
            yield* existsExact(table.table, {
              [table.moduleId]: ceremony.moduleId,
              [table.flowId]: ceremony.flowId,
              [table.purpose]: ceremony.purpose,
              [table.kind]: kind,
              [table.scope]: scope,
            }),
          );
      }),
    );

  const insertCharges = Effect.fn("passkey.insertCharges")(function* (
    mapping: any,
    ceremony: PasskeyCeremony,
    policy: PasskeyMethodPolicy,
    kinds: ReadonlyArray<PasskeyChargeKind>,
    subjectId?: string,
  ) {
    const owner = yield* CurrentPasskeyTransaction;

    if (kinds.length === 0) return;
    const table = mapping.charge;
    const anchor = mapping.admission;
    const clock = mapping.clock;

    const earliest = owner.observations.find(
      (observation) =>
        observation.table === anchor.table &&
        observation.rows.some(
          (row) =>
            row[anchor.authorityScope] === mapping.authorityScope &&
            row[anchor.moduleId] === mapping.moduleId,
        ),
    )?.nowMillis;

    invariant(earliest !== undefined);
    const entries: Array<{ values: Record<string, unknown>; key: Record<string, unknown> }> = [];

    for (const { kind, scope } of (yield* chargeScopes(ceremony, subjectId)).filter((item) =>
      kinds.includes(item.kind),
    )) {
      const identity = {
        [table.moduleId]: ceremony.moduleId,
        [table.flowId]: ceremony.flowId,
        [table.kind]: kind,
      };

      const values = {
        ...table.encodeInsert({
          moduleId: ceremony.moduleId,
          flowId: ceremony.flowId,
          purpose: ceremony.purpose,
          kind,
          scope,
          originalWindowMillis: policy.admission[kind].windowMillis,
          marker: owner.marker,
        }),
        ...identity,
        [table.purpose]: ceremony.purpose,
        [table.scope]: scope,
        [table.originalWindowMillis]: policy.admission[kind].windowMillis,
        [table.admittedAt]: null,
        [table.retainUntil]: null,
        [table.version]: owner.marker,
        [table.ownerMarker]: owner.marker,
      };

      entries.push({ values, key: identity });
    }
    invariant(entries.length === kinds.length);

    const anchorIdentity = {
      [anchor.authorityScope]: mapping.authorityScope,
      [anchor.moduleId]: mapping.moduleId,
      [anchor.version]: owner.marker,
      [anchor.ownerMarker]: owner.marker,
    };

    const stamp = sql`(select ${col(anchor.table, anchor.admittedAt)} from ${anchor.table} where ${owner.exact(anchor.table, anchorIdentity)})`;
    const stampMillis = clock.toMillis(stamp);

    const validStamp: SQL = both(
      yield* existsExact(anchor.table, anchorIdentity),
      sql`${stamp} is not null`,
      sql`${stampMillis} >= ${earliest}`,
      sql`${stampMillis} <= ${clock.engineNowMillis}`,
      sql`${stampMillis} <= ${8640000000000000 - chargeRetentionMillis}`,
    );

    yield* owner.finalUpdate(
      anchor.table,
      owner.exact(anchor.table, {
        [anchor.authorityScope]: mapping.authorityScope,
        [anchor.moduleId]: mapping.moduleId,
      }),
      {
        [anchor.version]: owner.marker,
        [anchor.ownerMarker]: owner.marker,
        [anchor.admittedAt]: clock.fromMillis(clock.engineNowMillis),
      },
      { rows: 1, postcondition: validStamp },
    );
    yield* owner.finalInsertMany(
      table.table,
      entries.map(({ key, values }) => ({
        key,
        values: {
          ...values,
          [table.admittedAt]: stamp,
          [table.retainUntil]: clock.fromMillis(sql`${stampMillis} + ${chargeRetentionMillis}`),
        },
      })),
    );
    owner.postconditions.push(
      sql`(select count(*) from ${table.table} where ${owner.exact(table.table, {
        [table.moduleId]: ceremony.moduleId,
        [table.flowId]: ceremony.flowId,
        [table.ownerMarker]: owner.marker,
      })}) = ${entries.length}`,
    );
  });

  return {
    chargeRetentionMillis,
    chargeScopes,
    admissionRead,
    lockAdmission,
    admissionCondition,
    guardAdmission,
    chargeRead,
    readCharges,
    guardChargeSet,
    insertCharges,
  };
};
