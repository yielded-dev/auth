/* oxlint-disable no-explicit-any -- existing mapped-row bridge; public adapters preserve table, ID, and Effect types. */

import type { PasskeyCeremony } from "@yielded/auth/Passkey";
import { Array, Effect } from "effect";

import type { QueryOperations, SqlExpression } from "../query-operations";
import type { Row } from "../transaction-kernel";
import { CurrentPasskeyTransaction } from "./state";
import type { makePasskeyStateKernel } from "./state";

export const makePasskeyRegistrationCustodyKernel = (
  state: Pick<
    ReturnType<typeof makePasskeyStateKernel>,
    "ceremonyStorage" | "col" | "equal" | "handleKey" | "invariant" | "matchesNativeRow"
  >,
  operations: QueryOperations,
) => {
  const { ceremonyStorage, col, equal, handleKey, matchesNativeRow } = state;
  const { and, inArray, or, sql } = operations;
  const invariant: (value: unknown) => asserts value = state.invariant;

  /** SQL-local writers have no external provisioning work. A definite terminal
   * rejection can release only its exact still-reserved handle; ambiguous owners
   * retain custody, and an accepted transaction no longer matches this reservation. */
  const releaseRegistrationCustody = Effect.fn("passkey.releaseRegistrationCustody")(function* (
    mapping: any,
    ceremony: PasskeyCeremony,
  ) {
    if (mapping.registration === undefined || ceremony.context._tag !== "Registration") return;
    const owner = yield* CurrentPasskeyTransaction;
    const handle = mapping.handle;
    const intent = mapping.intent;
    const hashed = yield* handleKey(ceremony.profile.rpId, ceremony.context.userHandle);

    const held = (yield* owner.read(
      handle.table,
      equal(handle.table, { [handle.handleKey]: hashed }),
      { limit: 1 },
    )).rows[0];

    const row = (yield* owner.read(
      intent.table,
      equal(intent.table, {
        [intent.moduleId]: mapping.moduleId,
        [intent.flowId]: ceremony.flowId,
      }),
      { limit: 1 },
    )).rows[0];

    if (row === undefined || !intent.isPendingState(row[intent.state])) return;
    invariant(
      held !== undefined &&
        handle.isReservedState(held[handle.state]) &&
        held[handle.reservationId] === row[intent.reservationId] &&
        row[intent.handleKey] === hashed &&
        row[intent.commandId] === ceremony.commandId &&
        row[intent.ceremonySnapshot] === ceremonyStorage.encode(ceremony),
    );
    yield* owner.update(
      intent.table,
      { [intent.moduleId]: mapping.moduleId, [intent.flowId]: ceremony.flowId },
      { [intent.state]: intent.rejectedState, [intent.version]: owner.marker },
    );
    yield* owner.remove(handle.table, { [handle.handleKey]: hashed });
  });

  /** Keep the command/flow tombstone after retention, without retaining the
   * application registration payload or ceremony. Ambiguous custody is never scrubbed. */
  const scrubRegistrationIntent = Effect.fn("passkey.scrubRegistrationIntent")(function* (
    mapping: any,
    ceremony: PasskeyCeremony,
  ) {
    if (mapping.registration === undefined || ceremony.context._tag !== "Registration") return;
    const owner = yield* CurrentPasskeyTransaction;
    const intent = mapping.intent;
    const identity = { [intent.moduleId]: mapping.moduleId, [intent.flowId]: ceremony.flowId };

    const row = (yield* owner.read(intent.table, equal(intent.table, identity), { limit: 1 }))
      .rows[0];

    if (row === undefined) return;
    invariant(
      (row[intent.state] === intent.acceptedState || row[intent.state] === intent.rejectedState) &&
        row[intent.commandId] === ceremony.commandId &&
        row[intent.ceremonySnapshot] === ceremonyStorage.encode(ceremony),
    );
    yield* owner.update(intent.table, identity, {
      [intent.applicationSnapshot]: "",
      [intent.ceremonySnapshot]: "",
      [intent.version]: owner.marker,
    });
  });

  /** Native cleanup locks related rows in groups while retaining each exact
   * reservation and tombstone as a final transaction observation. */
  const cleanupRegistrationCustody = Effect.fn("passkey.cleanupRegistrationCustody")(function* (
    mapping: any,
    release: ReadonlyArray<PasskeyCeremony>,
    scrub: ReadonlyArray<PasskeyCeremony>,
  ) {
    if (mapping.registration === undefined) return;
    const owner = yield* CurrentPasskeyTransaction;

    invariant(!owner.batch);
    const pending = [];

    for (const ceremony of release)
      if (ceremony.context._tag === "Registration")
        pending.push({
          ceremony,
          handleKey: yield* handleKey(ceremony.profile.rpId, ceremony.context.userHandle),
        });
    const terminal = scrub.filter((ceremony) => ceremony.context._tag === "Registration");

    if (pending.length === 0 && terminal.length === 0) return;

    const handle = mapping.handle,
      intent = mapping.intent;

    const readSet = Effect.fnUntraced(function* (
      table: object,
      column: string,
      values: ReadonlyArray<string>,
      scope: Row,
    ) {
      const keys = [...new Set(values)];
      const rows: Row[] = [];
      const key = (value: string) => ({ ...scope, [column]: value });
      const captured = yield* owner.readKeys(table, keys.map(key), { observe: false });

      if (captured !== undefined)
        return { table, keys, rows: captured.rows, key, aliased: !captured.canonical };
      // IN, CASE identities and CASE positions consume three binds per key.
      const size = Math.max(1, Math.min(64, Math.floor((owner.maxParameters - 4) / 3)));

      for (const group of Array.chunksOf(keys, size)) {
        const selected = yield* owner.read(
          table,
          and(equal(table, scope), inArray(col(table, column), group))!,
          {
            limit: group.length,
            observe: false,
            orderBy: sql`case ${sql.join(
              group.map(
                (value, index) => sql`when ${equal(table, { [column]: value })} then ${index}`,
              ),
              sql` `,
            )} else ${group.length} end`,
          },
        );

        rows.push(...selected.rows);
      }

      const aliased = rows.some(
        (row) => !keys.some((value) => matchesNativeRow(table, row, key(value))),
      );

      return { table, keys, rows, key, aliased };
    });

    const handles = yield* readSet(
      handle.table,
      handle.handleKey,
      pending.map((item) => item.handleKey),
      {},
    );

    const intents = yield* readSet(
      intent.table,
      intent.flowId,
      [
        ...pending.map(({ ceremony }) => ceremony.flowId),
        ...terminal.map((ceremony) => ceremony.flowId),
      ],
      { [intent.moduleId]: mapping.moduleId },
    );

    // Preserve point-operation behavior for application column codecs/collations
    // whose stored identities differ from the requested native identities.
    if (handles.aliased || intents.aliased) {
      for (const ceremony of release) yield* releaseRegistrationCustody(mapping, ceremony);
      for (const ceremony of scrub) yield* scrubRegistrationIntent(mapping, ceremony);

      return;
    }
    for (const selected of [handles, intents])
      yield* owner.observeKeys(selected.table, selected.keys.map(selected.key), selected.rows);

    const rejected: Row[] = [],
      released: Row[] = [],
      scrubbed: Row[] = [];

    for (const { ceremony, handleKey: hashed } of pending) {
      const row = intents.rows.find((row) =>
        matchesNativeRow(intent.table, row, intents.key(ceremony.flowId)),
      );

      if (row === undefined || !intent.isPendingState(row[intent.state])) continue;

      const held = handles.rows.find((row) =>
        matchesNativeRow(handle.table, row, handles.key(hashed)),
      );

      invariant(
        held !== undefined &&
          handle.isReservedState(held[handle.state]) &&
          held[handle.reservationId] === row[intent.reservationId] &&
          row[intent.handleKey] === hashed &&
          row[intent.commandId] === ceremony.commandId &&
          row[intent.ceremonySnapshot] === ceremonyStorage.encode(ceremony) &&
          !released.some((row) => matchesNativeRow(handle.table, row, handles.key(hashed))),
      );
      rejected.push(row);
      released.push(held);
    }
    for (const ceremony of terminal) {
      const row = intents.rows.find((row) =>
        matchesNativeRow(intent.table, row, intents.key(ceremony.flowId)),
      );

      if (row === undefined) continue;
      invariant(
        (row[intent.state] === intent.acceptedState ||
          row[intent.state] === intent.rejectedState) &&
          row[intent.commandId] === ceremony.commandId &&
          row[intent.ceremonySnapshot] === ceremonyStorage.encode(ceremony),
      );
      scrubbed.push(row);
    }

    const writeRows = Effect.fnUntraced(function* (
      table: object,
      rows: ReadonlyArray<Row>,
      key: (row: Row) => Row,
      values?: Row,
    ) {
      if (
        yield* owner.changeRows(
          table,
          rows.map((row) => ({
            key: key(row),
            before: row,
            after: values ?? null,
          })),
        )
      )
        return;
      const parameters = Object.keys(values ?? {}).length;
      const byteLimit = owner.maxParameters <= 100 ? 48_000 : 512_000;

      let group: Row[] = [],
        conditions: SqlExpression[] = [],
        count = parameters,
        bytes = 0;

      const flush = Effect.fnUntraced(function* () {
        if (group.length === 0) return;
        const where = or(...conditions)!;

        yield* owner.write(
          values === undefined
            ? owner.database.delete(table).where(where)
            : owner.database.update(table).set(values).where(where),
        );
        for (const observation of owner.observations)
          if (observation.table === table)
            observation.rows = observation.rows.flatMap((row) =>
              group.some((changed) => matchesNativeRow(table, row, key(changed)))
                ? values === undefined
                  ? []
                  : [{ ...row, ...values }]
                : [row],
            );
        group = [];
        conditions = [];
        count = parameters;
        bytes = 0;
      });

      for (const row of rows) {
        const condition = owner.exact(table, row);
        const rendered = owner.database.select().from(table).where(condition).toSQL();
        const size = new TextEncoder().encode(rendered.sql).length;

        if (
          group.length > 0 &&
          (count + rendered.params.length > owner.maxParameters || bytes + size > byteLimit)
        )
          yield* flush();
        group.push(row);
        conditions.push(condition);
        count += rendered.params.length;
        bytes += size;
      }
      yield* flush();
    });

    const intentKey = (row: Row) => ({
      [intent.moduleId]: mapping.moduleId,
      [intent.flowId]: row[intent.flowId],
    });

    yield* writeRows(intent.table, rejected, intentKey, {
      [intent.state]: intent.rejectedState,
      [intent.version]: owner.marker,
    });
    yield* writeRows(handle.table, released, (row) => ({
      [handle.handleKey]: row[handle.handleKey],
    }));
    yield* writeRows(intent.table, scrubbed, intentKey, {
      [intent.applicationSnapshot]: "",
      [intent.ceremonySnapshot]: "",
      [intent.version]: owner.marker,
    });
  });

  return { releaseRegistrationCustody, scrubRegistrationIntent, cleanupRegistrationCustody };
};
