import { type CommitJournal, type PreparedCommit } from "@yielded/auth/Hooks";
import { reportAuthFailure } from "@yielded/auth/Persistence";
import {
  eq,
  getTableColumns,
  isNull,
  or,
  sql,
  type SQL,
  type AnyColumn,
  type Table,
  type SQLWrapper,
} from "drizzle-orm";
import type { EffectDrizzleQueryError } from "drizzle-orm/effect-core";
/* oxlint-disable no-explicit-any -- existing storage kernels erase foreign table shapes; domain errors remain typed. */
import { Cause, Effect } from "effect";
import type * as SqlClient from "effect/sql/SqlClient";
import type { SqlError } from "effect/sql/SqlError";
import type { Statement } from "effect/sql/Statement";

import { balancedD1And, compactD1GeneratedStatement } from "./d1-generated-statement";
import { makeBoundRows, rowsetEquality, type BoundRows } from "./sql-rowset";
import { combineSnapshotQueries } from "./sql-snapshot";

export type Row = Record<string, any>;

/** Only query-builder/table shapes are erased here. Installed native
 * queries have captured clients, and their error channel remains explicit. */
type NativeQuery<A> = Effect.Effect<A, EffectDrizzleQueryError | SqlError>;

export interface TransactionNativeDatabase {
  /** Bind budget supplied by a backend with stricter limits than its dialect. */
  readonly maxParameters?: number;
  readonly $client: SqlClient.SqlClient & {
    readonly batch: (statements: ReadonlyArray<Statement<any>>) => Effect.Effect<any, SqlError>;
  };
  readonly transaction: <A, E, R>(
    body: (transaction: any) => Effect.Effect<A, E, R>,
  ) => Effect.Effect<A, E | SqlError, R>;
}

export interface TransactionRows {
  readonly table: Table;
  readonly where: SQL;
  readonly rows: ReadonlyArray<Row>;
  readonly conditionHolds?: boolean;
  readonly nowMillis?: number;
  readonly checks?: Readonly<Record<string, boolean>>;
}

/** Read semantic columns when telemetry changes atomically, and state the result. */
export interface GuardedUpdate {
  readonly rows: number;
  readonly postcondition: SQL;
}

export interface TransactionReadOptions {
  readonly lock?: boolean;
  readonly limit?: number;
  /** Preserve this read at its position in a staged batch. */
  readonly admit?: boolean;
  readonly takeOnly?: boolean;
  readonly orderBy?: any;
  readonly columns?: ReadonlyArray<string>;
  /** Evaluate a row predicate in the same locked snapshot as its columns. */
  readonly condition?: SQL;
  /** Read the authority clock with the row that owns a timed decision. */
  readonly clock?: { readonly engineNowMillis: SQL };
  /** Independent decisions evaluated with a present row, without extra SELECTs. */
  readonly checks?: Readonly<Record<string, SQL>>;
}

export interface TransactionRead {
  readonly table: Table;
  readonly where: SQL;
  readonly options?: TransactionReadOptions;
}

export interface TransactionScope<Failure> {
  readonly database: any;
  readonly marker: string;
  readonly batch: boolean;
  /** Generated bind budget; batch compilers may compact physical parameters. */
  readonly maxParameters: number;
  readonly postconditions: Array<SQL | (() => SQL)>;
  readonly statements: Statement<any>[];
  readonly guards: PreparedCommit<void>[];
  exact(table: Table, row: Row): SQL;
  /** Predicates for an operation's explicitly chosen final projection. */
  matchRows(table: Table, where: SQL, rows: ReadonlyArray<Row>): ReadonlyArray<SQL>;
  matchKeys(
    table: Table,
    keys: ReadonlyArray<Row>,
    rows: ReadonlyArray<Row>,
    base?: SQL,
  ): ReadonlyArray<SQL>;
  /** Retain a fact already established under native locks inside a staged batch. */
  admit(conditions: ReadonlyArray<SQL>): Effect.Effect<void, Failure>;
  /** Require a fact at this exact position in the transaction or staged batch. */
  assert(conditions: ReadonlyArray<SQL>): Effect.Effect<void, Failure>;
  /** Operation-owned SQL executed after application work and before final checks. */
  finalWrite(query: any): Effect.Effect<void, Failure>;
  rowsets(
    table: Table,
    rows: ReadonlyArray<Row>,
    names?: Readonly<Record<string, string>>,
  ): ReadonlyArray<BoundRows> | undefined;
  read(
    table: Table,
    where: SQL,
    options?: TransactionReadOptions,
  ): Effect.Effect<TransactionRows, Failure>;
  /** Independent bounded row sets share a statement, retaining native column codecs. */
  readMany(
    reads: ReadonlyArray<TransactionRead>,
  ): Effect.Effect<ReadonlyArray<TransactionRows>, Failure>;
  readKeys(
    table: Table,
    keys: ReadonlyArray<Row>,
    options?: Pick<TransactionReadOptions, "lock" | "columns"> & {
      readonly base?: SQL;
    },
  ): Effect.Effect<
    { readonly rows: ReadonlyArray<Row>; readonly canonical: boolean } | undefined,
    Failure
  >;
  write(query: any): Effect.Effect<void, Failure>;
  insert(
    table: Table,
    values: Row,
    key: Row,
    absent?: boolean,
  ): Effect.Effect<TransactionRows, Failure>;
  updateGuarded(
    table: Table,
    where: SQL,
    values: Row,
    guard: GuardedUpdate,
  ): Effect.Effect<void, Failure>;
  changeRows(
    table: Table,
    entries: ReadonlyArray<{ readonly key: Row; readonly before: Row; readonly after: Row | null }>,
    base?: SQL,
  ): Effect.Effect<boolean, Failure>;
  check(condition: SQL): Effect.Effect<boolean, Failure>;
  now(clock: { readonly engineNowMillis: SQL }): Effect.Effect<number, Failure>;
  finish(): Effect.Effect<void, Failure>;
}

export interface TransactionOwner<Failure> extends TransactionScope<Failure> {
  readonly journal: CommitJournal;
}

const isUnavailableCause = <Failure>(cause: Cause.Cause<unknown>, unavailable: () => Failure) => {
  const expected = unavailable();

  const tag =
    typeof expected === "object" && expected !== null && "_tag" in expected
      ? expected._tag
      : undefined;

  return (
    tag !== undefined &&
    cause.reasons.length > 0 &&
    cause.reasons.every(
      (reason) =>
        Cause.isFailReason(reason) &&
        typeof reason.error === "object" &&
        reason.error !== null &&
        "_tag" in reason.error &&
        reason.error._tag === tag,
    )
  );
};

/** Report once, before an adapter replaces the raw cause with its public
 * unavailable error. Already translated failures stay quiet at outer owners. */
export const reportTransactionFailure = <A, E, R, Failure>(
  effect: Effect.Effect<A, E, R>,
  unavailable: () => Failure,
): Effect.Effect<A, E, R> =>
  Effect.catchCause(effect, (cause) =>
    isUnavailableCause(cause, unavailable)
      ? Effect.failCause(cause)
      : reportAuthFailure("auth-persistence", cause).pipe(Effect.andThen(Effect.failCause(cause))),
  );

export const both = (...parts: ReadonlyArray<SQL | undefined>) =>
  balancedD1And(...parts) ?? sql`1 = 1`;

export const makeTransactionRows = <Failure>(unavailable: () => Failure) => {
  const invariant: (value: unknown) => asserts value = (value) => {
    if (!value) throw unavailable();
  };

  const col = (table: Table, key: string) => {
    const value = getTableColumns(table)[key];

    invariant(value !== undefined);

    return value;
  };

  const equal = (table: Table, values: Row) =>
    both(
      ...Object.entries(values).map(([key, value]) =>
        value === null ? isNull(col(table, key)) : eq(col(table, key), value),
      ),
    );

  /** Mapped driver values use plain data, Dates and binary views. Application
   * identity classes are reconstructed by the mapped codecs, never cloned here. */
  const copiedRow = (row: Row) => {
    const seen = new WeakSet<object>();

    const supported = (value: unknown): void => {
      if (value === null || typeof value !== "object" || seen.has(value)) return;
      seen.add(value);
      if (value instanceof Date || value instanceof ArrayBuffer || ArrayBuffer.isView(value))
        return;
      invariant(
        Array.isArray(value) ||
          Object.getPrototypeOf(value) === Object.prototype ||
          Object.getPrototypeOf(value) === null,
      );
      for (const item of Object.values(value)) supported(item);
    };

    supported(row);

    return structuredClone(row);
  };

  const nativeKey = (value: unknown): string => {
    const packed = (tag: string, text: string) => tag + text.length + ":" + text;

    if (value instanceof Date) return packed("date", value.toISOString());
    if (typeof value === "bigint") return packed("bigint", value.toString());

    const bytes =
      value instanceof ArrayBuffer
        ? new Uint8Array(value)
        : ArrayBuffer.isView(value)
          ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
          : undefined;

    if (bytes !== undefined) return packed("bytes", Array.from(bytes).join(","));
    if (value === null || typeof value !== "object") return packed(typeof value, String(value));
    if (Array.isArray(value)) return packed("array", value.map(nativeKey).join(""));
    invariant(
      Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null,
    );

    return packed(
      "object",
      Object.entries(value)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([name, item]) => nativeKey(name) + nativeKey(item))
        .join(""),
    );
  };

  const matchesNativeRow = (table: Table, row: Row, key: Row) =>
    Object.entries(key).every(([name, value]) => {
      if (value === null || row[name] === null) return value === row[name];
      const column = col(table, name);

      return (
        nativeKey(column.mapToDriverValue(row[name])) === nativeKey(column.mapToDriverValue(value))
      );
    });

  const sameDriverValue = (left: unknown, right: unknown) => nativeKey(left) === nativeKey(right);

  const rowIdentity = (table: Table, row: Row, fields: ReadonlyArray<string>) =>
    nativeKey(
      fields.map((name) => [
        name,
        row[name] === null ? null : col(table, name).mapToDriverValue(row[name]),
      ]),
    );

  return { col, equal, copiedRow, matchesNativeRow, sameDriverValue, rowIdentity };
};

export const makeTransactionScope = <Failure>(
  database: any,
  marker: string,
  unavailable: () => Failure,
  configuration: {
    readonly client?: any;
    readonly batch: boolean;
    readonly locking: boolean;
    readonly mysql: boolean;
    readonly dialect: "pg" | "mysql" | "sqlite";
    readonly maxParameters?: number;
    readonly compactGeneratedStatements?: boolean;
    /** Advisory callers validate all decisions from their captured read. */
    readonly readonlySnapshot?: boolean;
  },
): TransactionScope<Failure> => {
  const invariant: (value: unknown) => asserts value = (value) => {
    if (!value) throw unavailable();
  };

  const { col, equal, matchesNativeRow, rowIdentity } = makeTransactionRows(unavailable);
  const boundRows = makeBoundRows(database, configuration.dialect);

  const rowsets = (
    table: Table,
    rows: ReadonlyArray<Row>,
    names?: Readonly<Record<string, string>>,
  ) => (configuration.batch ? undefined : boundRows(table, rows, names));

  const exactRows = (table: Table, rows: BoundRows, names?: Readonly<Record<string, string>>) =>
    both(
      ...Object.entries(
        names ?? Object.fromEntries(Object.keys(rows.fields).map((name) => [name, name])),
      ).map(([field, name]) =>
        rowsetEquality(
          configuration.dialect,
          col(table, name),
          rows.exactFields[field]!,
          rows.rows.some((row) => typeof row[field] === "string"),
        ),
      ),
    );

  const rowKeys = (
    table: Table,
    rows: BoundRows,
    names?: Readonly<Record<string, string>>,
    values: Readonly<Record<string, SQLWrapper>> = rows.fields,
  ) =>
    both(
      ...Object.entries(
        names ?? Object.fromEntries(Object.keys(rows.fields).map((name) => [name, name])),
      ).map(([field, name]) =>
        rows.rows.some((row) => row[field] === null)
          ? rowsetEquality(configuration.dialect, col(table, name), values[field]!, false)
          : eq(col(table, name), values[field]!),
      ),
    );

  const maxParameters =
    configuration.maxParameters ??
    (configuration.batch || configuration.dialect !== "sqlite" ? 16_000 : 900);

  invariant(Number.isSafeInteger(maxParameters) && maxParameters > 0);
  let phase: "open" | "finishing" | "finished" = "open";
  let poisoned = false;
  let readStatements = 0;
  const open = () => invariant(phase === "open" && !poisoned);

  const result = <A, E>(effect: Effect.Effect<A, E>) =>
    effect.pipe(
      (operation) => reportTransactionFailure(operation, unavailable),
      Effect.mapError(unavailable),
      Effect.catchDefect(() => Effect.fail(unavailable())),
      Effect.onExit((exit) =>
        Effect.sync(() => {
          if (exit._tag === "Failure") poisoned = true;
        }),
      ),
    );

  const statements: Statement<any>[] = [];
  const postconditions: Array<SQL | (() => SQL)> = [];
  const guards: PreparedCommit<void>[] = [];
  const finalWrites: any[] = [];

  const exactRow = (table: Table, row: Row) =>
    both(
      ...Object.entries(row).map(([key, value]) => {
        if (typeof value !== "string") return equal(table, { [key]: value });

        const column = col(table, key),
          bound = sql.param(value, column);

        return configuration.dialect === "mysql"
          ? sql`binary ${column} = binary ${bound}`
          : configuration.dialect === "pg"
            ? sql`convert_to(cast(${column} as text), 'UTF8') = convert_to(cast(${bound} as text), 'UTF8')`
            : sql`cast(${column} as blob) = cast(${bound} as blob)`;
      }),
    );

  const toStatement = (query: any): Statement<any> => {
    const rendered = query.toSQL();
    const client = configuration.client ?? database.$client;

    return compactD1GeneratedStatement(
      client,
      client.unsafe(rendered.sql, rendered.params),
      unavailable,
    );
  };

  const assertion = (condition: SQL) =>
    database
      .select({
        value: sql`case when ${condition} then 1 else json_extract('[]', ${"$[oauth-owner-" + marker + "]"}) end`,
      })
      .from(sql`(select 1) as oauth_assertion`);

  const fullRowConditions = (
    table: Table,
    where: SQL,
    rows: ReadonlyArray<Row>,
    keys?: ReadonlyArray<string>,
  ) => {
    const sets = rowsets(table, rows);

    return sets === undefined
      ? rows.map(
          (row) => sql`exists(select 1 from ${table} where ${both(where, exactRow(table, row))})`,
        )
      : sets.map(
          (set) =>
            sql`not exists(select 1 from ${set.source} where not exists(select 1 from ${table} where ${both(
              where,
              keys === undefined
                ? undefined
                : rowKeys(table, set, Object.fromEntries(keys.map((name) => [name, name]))),
              exactRows(table, set),
            )}))`,
        );
  };

  const matchRows = (table: Table, where: SQL, rows: ReadonlyArray<Row>) => [
    sql`(select count(*) from ${table} where ${where}) = ${rows.length}`,
    ...fullRowConditions(table, where, rows),
  ];

  const matchKeys = (
    table: Table,
    keys: ReadonlyArray<Row>,
    rows: ReadonlyArray<Row>,
    base?: SQL,
  ) => {
    const sets = rowsets(table, keys);

    if (sets === undefined)
      return keys.flatMap((key) =>
        matchRows(
          table,
          both(base, equal(table, key)),
          rows.filter((row) => matchesNativeRow(table, row, key)),
        ),
      );
    const conditions: SQL[] = [];

    for (const set of sets) {
      const selected = rows.filter((row) =>
        set.rows.some((key) => matchesNativeRow(table, row, key)),
      );

      const match = rowKeys(table, set);

      conditions.push(
        configuration.dialect === "sqlite"
          ? sql`(select count(*) from ${set.source} cross join ${table} where ${both(base, match)}) = ${selected.length}`
          : sql`(select count(*) from ${set.source} inner join ${table} on ${match} where ${base ?? sql`1 = 1`}) = ${selected.length}`,
      );
      conditions.push(
        ...fullRowConditions(table, base ?? sql`1 = 1`, selected, Object.keys(keys[0]!)),
      );
    }

    return conditions;
  };

  // D1 and Durable Object SQLite have tighter limits than local SQLite.
  // Keep final checks bounded without turning each expected row into a trip.
  const chunks = (conditions: ReadonlyArray<SQL>) => {
    const output: SQL[] = [];
    let pending: SQL[] = [];
    let parameters = 1;
    let bytes = 0;
    const parameterLimit = configuration.batch ? 96 : maxParameters;
    const byteLimit = configuration.batch || maxParameters <= 100 ? 48_000 : 512_000;

    for (const condition of conditions) {
      const rendered = queryCondition(condition).toSQL();

      // Count each predicate once. Re-rendering the growing conjunction made
      // large bounded collections quadratic before they reached the database.
      const size = new TextEncoder().encode(rendered.sql).length + rendered.params.length * 4 + 16;

      if (
        pending.length > 0 &&
        (parameters + rendered.params.length > parameterLimit || bytes + size > byteLimit)
      ) {
        output.push(both(...pending));
        pending = [];
        parameters = 1;
        bytes = 0;
      }
      pending.push(condition);
      parameters += rendered.params.length;
      bytes += size;
    }
    if (pending.length > 0) output.push(both(...pending));

    return output;
  };

  const appendAssertions = (conditions: ReadonlyArray<SQL>) => {
    for (const condition of chunks(conditions)) statements.push(toStatement(assertion(condition)));
  };

  const projection = (
    table: Table,
    names?: ReadonlyArray<string>,
    condition?: SQL,
    clock?: { readonly engineNowMillis: SQL },
    checks: Readonly<Record<string, SQL>> = {},
  ) => {
    const columns = getTableColumns(table);

    const selection: Record<string, AnyColumn | SQL | SQL.Aliased> =
      names === undefined
        ? { ...columns }
        : Object.fromEntries(names.map((key) => [key, col(table, key)]));

    let conditionKey = "__auth_condition";
    let clockKey = "__auth_now";

    while (conditionKey in columns) conditionKey += "_";
    while (clockKey in columns) clockKey += "_";
    if (condition !== undefined)
      selection[conditionKey] = sql`case when ${condition} then 1 else 0 end`
        .mapWith(Number)
        .as(conditionKey);
    if (clock !== undefined)
      selection[clockKey] = sql`${clock.engineNowMillis}`.mapWith(Number).as(clockKey);

    const checkKeys = Object.keys(checks).map((name, index) => {
      let key = `__auth_check_${index}`;

      while (key in selection) key += "_";
      selection[key] = sql`case when ${checks[name]} then 1 else 0 end`.mapWith(Number).as(key);

      return { name, key };
    });

    const rows = (selected: ReadonlyArray<Row>) =>
      condition === undefined && clock === undefined && checkKeys.length === 0
        ? selected
        : selected.map((row) => {
            if (condition !== undefined)
              invariant(row[conditionKey] === 0 || row[conditionKey] === 1);
            if (clock !== undefined)
              invariant(Number.isSafeInteger(row[clockKey]) && row[clockKey] >= 0);
            const { [conditionKey]: _condition, [clockKey]: _clock, ...values } = row;

            for (const { key } of checkKeys) {
              invariant(row[key] === 0 || row[key] === 1);
              delete values[key];
            }

            return values;
          });

    return { selection, conditionKey, clockKey, checkKeys, rows };
  };

  const queryCondition = (condition: SQL) =>
    database
      .select({
        value: sql`case when ${condition} then 1 else 0 end`.mapWith(Number).as("value"),
      })
      .from(sql`(select 1) as oauth_guard`);

  const conditionHolds = (condition: SQL) =>
    Effect.gen(function* () {
      const query = queryCondition(condition);

      readStatements++;

      const rows: ReadonlyArray<Row> = yield* configuration.batch ||
      configuration.compactGeneratedStatements
        ? toStatement(query)
        : (query as NativeQuery<Row[]>);

      invariant(rows.length === 1);

      return rows[0]!.value === 1;
    });

  const guardedQuery = (table: Table, where: SQL, values: Row, guard: GuardedUpdate) => {
    invariant(!configuration.readonlySnapshot);
    invariant(Number.isSafeInteger(guard.rows) && guard.rows > 0 && guard.rows <= 1000);

    return { table, query: database.update(table).set(values).where(where), guard: { ...guard } };
  };

  const applyGuarded = (entry: {
    readonly table: Table;
    readonly query: any;
    readonly guard: GuardedUpdate;
  }) =>
    Effect.gen(function* () {
      if (configuration.batch) {
        statements.push(toStatement(entry.query));
        statements.push(toStatement(assertion(sql`changes() = ${entry.guard.rows}`)));
        appendAssertions([entry.guard.postcondition]);
      } else {
        if (configuration.mysql) {
          // mysql2 reports matched rows (FOUND_ROWS), including a telemetry no-op.
          const changed = yield* entry.query as NativeQuery<{ readonly affectedRows: number }>;

          invariant(changed.affectedRows === entry.guard.rows);
        } else {
          const changed = yield* entry.query.returning({ value: sql`1` }) as NativeQuery<
            ReadonlyArray<Row>
          >;

          invariant(changed.length === entry.guard.rows);
        }
        invariant(yield* conditionHolds(entry.guard.postcondition));
      }
    });

  const prepareRead = ({ table, where, options = {} }: TransactionRead, previous?: SQLWrapper) => {
    const limit = options.limit ?? 64;

    const selectedRows = projection(
      table,
      options.columns,
      options.condition,
      options.clock,
      options.checks,
    );

    let query = database
      .select(selectedRows.selection)
      .from(table)
      .where(
        previous === undefined ? where : both(where, sql`(select count(*) from ${previous}) >= 0`),
      )
      .limit(options.takeOnly ? limit : limit + 1);

    if (options.orderBy !== undefined) query = query.orderBy(options.orderBy);
    if (options.lock !== false && configuration.locking) query = query.for("update");

    const capture = (selected: ReadonlyArray<Row>) => {
      const rows = selectedRows.rows(selected);
      const { conditionKey } = selectedRows;

      invariant(rows.length <= limit);
      if (configuration.batch && options.admit !== false)
        appendAssertions(matchRows(table, where, rows));
      if (configuration.batch && options.condition !== undefined)
        appendAssertions(
          rows.map(
            (row, index) =>
              sql`exists(select 1 from ${table} where ${both(
                where,
                exactRow(table, row),
                selected[index]?.[conditionKey] === 1
                  ? options.condition
                  : sql`case when ${options.condition} then 0 else 1 end = 1`,
              )})`,
          ),
        );
      if (configuration.batch)
        for (const { name, key } of selectedRows.checkKeys)
          appendAssertions(
            rows.map(
              (row, index) =>
                sql`exists(select 1 from ${table} where ${both(
                  where,
                  exactRow(table, row),
                  selected[index]?.[key] === 1
                    ? options.checks![name]!
                    : sql`case when ${options.checks![name]} then 0 else 1 end = 1`,
                )})`,
            ),
          );

      return {
        table,
        where,
        rows,
        ...(options.condition === undefined
          ? {}
          : {
              conditionHolds: rows.length > 0 && selected.every((row) => row[conditionKey] === 1),
            }),
        ...(options.clock === undefined || selected.length === 0
          ? {}
          : { nowMillis: selected[0]![selectedRows.clockKey] as number }),
        ...(options.checks === undefined
          ? {}
          : {
              checks: Object.fromEntries(
                selectedRows.checkKeys.map(({ name, key }) => [
                  name,
                  selected.length > 0 && selected.every((row) => row[key] === 1),
                ]),
              ),
            }),
      };
    };

    return { table, selectedRows, query, capture, request: { table, where, options } };
  };

  const selectMany = (
    reads: ReadonlyArray<ReturnType<typeof prepareRead>>,
  ): Effect.Effect<ReadonlyArray<TransactionRows>, EffectDrizzleQueryError | SqlError> =>
    Effect.gen(function* () {
      if (reads.length === 0) return [];
      if (reads.length === 1) {
        const read = reads[0]!;
        const rendered = read.query.toSQL();

        invariant(rendered.params.length <= (configuration.batch ? 96 : maxParameters));
        if (configuration.batch || maxParameters <= 100) {
          invariant(Object.keys(read.selectedRows.selection).length <= 100);
          invariant(new TextEncoder().encode(rendered.sql).length <= 96_000);
        }
        readStatements++;

        return [read.capture(yield* read.query as NativeQuery<Row[]>)];
      }

      const fields = reads.flatMap((read, index) =>
        Object.keys(read.selectedRows.selection).map((name) => ({
          read,
          index,
          name,
          column: getTableColumns(read.table)[name],
        })),
      );

      if ((configuration.batch || maxParameters <= 100) && fields.length + 1 > 100) {
        const midpoint = Math.ceil(reads.length / 2);

        return [
          ...(yield* selectMany(reads.slice(0, midpoint))),
          ...(yield* selectMany(reads.slice(midpoint))),
        ];
      }

      const hasDecoder = (column: AnyColumn): column is AnyColumn =>
        typeof column.mapFromDriverValue === "function";

      if (fields.some(({ column }) => column !== undefined && !hasDecoder(column)))
        return yield* Effect.forEach(reads, (read) => selectMany([read])).pipe(
          Effect.map((groups) => groups.flat()),
        );
      const ordered = configuration.dialect === "pg" && configuration.locking;

      if (ordered && sql.identifier === undefined)
        return yield* Effect.forEach(reads, (read) => selectMany([read])).pipe(
          Effect.map((groups) => groups.flat()),
        );
      const names = ordered ? reads.map((_, index) => sql.identifier!(`auth_read_${index}`)) : [];

      const selectedReads = ordered
        ? reads.map((read, index) => prepareRead(read.request, names[index - 1]))
        : reads;

      const combined = combineSnapshotQueries(
        selectedReads.map((read) => read.query),
        fields.map((field) => {
          if (field.column !== undefined) invariant(hasDecoder(field.column));

          return {
            index: field.index,
            name: field.name,
            empty:
              field.column === undefined
                ? configuration.mysql
                  ? sql`cast(null as decimal(65, 0))`
                  : sql`cast(null as numeric)`
                : sql`(select ${field.column} from ${field.read.table} where 1 = 0)`,
            decode: field.column === undefined ? Number : field.column,
          };
        }),
        ordered ? names : undefined,
        configuration.dialect === "sqlite" && (configuration.batch || maxParameters <= 100)
          ? 5
          : Infinity,
      );

      if (combined === undefined)
        return yield* Effect.forEach(reads, (read) => selectMany([read])).pipe(
          Effect.map((groups) => groups.flat()),
        );
      const query = database.select(combined.selection).from(combined.source);
      const rendered = query.toSQL();
      const byteLimit = configuration.batch || maxParameters <= 100 ? 48_000 : 512_000;

      if (
        rendered.params.length > (configuration.batch ? 96 : maxParameters) ||
        new TextEncoder().encode(rendered.sql).length > byteLimit
      ) {
        const midpoint = Math.ceil(reads.length / 2);

        return [
          ...(yield* selectMany(reads.slice(0, midpoint))),
          ...(yield* selectMany(reads.slice(midpoint))),
        ];
      }
      readStatements++;
      const selected = yield* query as NativeQuery<Row[]>;
      const groups = combined.regroup(selected);

      return reads.map((read, index) => read.capture(groups[index]!));
    });

  const owner: TransactionScope<Failure> = {
    database,
    marker,
    batch: configuration.batch,
    maxParameters,
    statements,
    postconditions,
    guards,
    exact: exactRow,
    matchRows,
    matchKeys,
    admit: (conditions) =>
      result(
        Effect.sync(() => {
          open();
          if (configuration.batch) appendAssertions(conditions);
        }),
      ),
    assert: (conditions) =>
      result(
        Effect.gen(function* () {
          open();
          if (configuration.batch) appendAssertions(conditions);
          else
            for (const condition of chunks(conditions)) invariant(yield* conditionHolds(condition));
        }),
      ),
    finalWrite: (query) =>
      result(
        Effect.sync(() => {
          open();
          invariant(!configuration.readonlySnapshot);
          finalWrites.push(query);
        }),
      ),
    rowsets,
    read: (table, where, options = {}) =>
      result(
        Effect.gen(function* () {
          open();
          const read = prepareRead({ table, where, options });

          readStatements++;

          return read.capture(yield* read.query as NativeQuery<Row[]>);
        }),
      ),
    readMany: (reads) =>
      result(
        Effect.gen(function* () {
          open();

          return yield* selectMany(reads.map((read) => prepareRead(read)));
        }),
      ),
    readKeys: (table, keys, options = {}) =>
      result(
        Effect.gen(function* () {
          open();
          invariant(keys.length <= 1000);
          const sets = rowsets(table, keys);

          if (sets === undefined) return undefined;
          const columns = getTableColumns(table);

          let ordinal = "__auth_ordinal",
            canonical = "__auth_canonical";

          while (ordinal in columns) ordinal += "_";
          while (canonical in columns) canonical += "_";
          const selectedRows = projection(table, options.columns);

          if (maxParameters <= 100 && Object.keys(selectedRows.selection).length + 2 > 100)
            return undefined;

          const queries = sets.map((set) => {
            const match = rowKeys(table, set);

            let query = database
              .select({
                ...selectedRows.selection,
                [ordinal]: sql`${set.ordinal}`.mapWith(Number).as(ordinal),
                [canonical]: sql`case when ${exactRows(table, set)} then 1 else 0 end`
                  .mapWith(Number)
                  .as(canonical),
              })
              .from(set.source);

            // Keep the bounded payload outside indexed table probes. SQLite
            // otherwise can scan the payload again for every row in a module.
            query = (
              configuration.dialect === "sqlite"
                ? query.crossJoin(table).where(both(options.base, match))
                : query.innerJoin(table, match).where(options.base ?? sql`1 = 1`)
            ).orderBy(set.ordinal);

            if (options.lock !== false && configuration.locking)
              query = query.for("update", { of: table });

            return { set, query };
          });

          if (
            queries.some(({ query }) => {
              const rendered = query.toSQL();

              return (
                rendered.params.length > maxParameters ||
                (maxParameters <= 100 && new TextEncoder().encode(rendered.sql).length > 96_000)
              );
            })
          )
            return undefined;
          const rows: Row[] = [];
          let allCanonical = true;

          for (const { set, query } of queries) {
            readStatements++;
            const selected = yield* query as NativeQuery<Row[]>;
            const seen = new Set<number>();

            for (const row of selected) {
              const index = row[ordinal];

              invariant(
                Number.isInteger(index) &&
                  index >= set.offset &&
                  index < set.offset + set.rows.length &&
                  !seen.has(index),
              );
              seen.add(index);
              invariant(row[canonical] === 0 || row[canonical] === 1);
              allCanonical &&= row[canonical] === 1;
              const { [ordinal]: _ordinal, [canonical]: _canonical, ...values } = row;

              rows.push(...selectedRows.rows([values]));
            }
          }

          return { rows, canonical: allCanonical };
        }),
      ),
    write: (query) =>
      result(
        Effect.gen(function* () {
          open();
          invariant(!configuration.readonlySnapshot);
          if (configuration.batch) statements.push(toStatement(query));
          else yield* query as NativeQuery<unknown>;
        }),
      ),
    insert: (table, values, key, absent = false) =>
      result(
        Effect.gen(function* () {
          open();
          invariant(!configuration.readonlySnapshot);
          let query = database.insert(table).values(values);

          if (absent)
            query = configuration.mysql
              ? query.onDuplicateKeyUpdate({
                  set: { [Object.keys(key)[0]!]: col(table, Object.keys(key)[0]!) },
                })
              : query.onConflictDoNothing();
          const where = equal(table, key);

          if (configuration.batch) {
            yield* owner.write(query);

            return { table, where, rows: [values] };
          }

          if (!configuration.mysql) {
            const selectedRows = projection(table, undefined, exactRow(table, values));
            const selected = yield* query.returning(selectedRows.selection) as NativeQuery<Row[]>;

            if (absent && selected.length === 0)
              return yield* owner.read(table, where, { limit: 1 });
            invariant(selected.length === 1 && selected[0]?.[selectedRows.conditionKey] === 1);

            // The operation owns final checks after triggers and application work.
            return { table, where, rows: selectedRows.rows(selected) };
          }
          yield* owner.write(query);

          const found = yield* owner.read(table, where, {
            limit: 1,
            condition: exactRow(table, values),
          });

          const markerColumn = Object.keys(values).find((key) => values[key] === marker);

          if (!absent || (markerColumn !== undefined && found.rows[0]?.[markerColumn] === marker))
            invariant(found.rows.length === 1 && found.conditionHolds);

          return found;
        }),
      ),
    updateGuarded: (table, where, values, guard) =>
      result(
        Effect.gen(function* () {
          open();
          const entry = guardedQuery(table, where, values, guard);

          yield* applyGuarded(entry);
          postconditions.push(entry.guard.postcondition);
        }),
      ),
    changeRows: (table, entries, base) =>
      result(
        Effect.gen(function* () {
          open();
          invariant(!configuration.readonlySnapshot && entries.length <= 1000);
          if (entries.length === 0) return true;
          invariant(entries.every(({ before, key }) => matchesNativeRow(table, before, key)));
          const keyFields = Object.keys(entries[0]!.key).sort();
          const beforeFields = Object.keys(entries[0]!.before).sort();
          const fields = Object.keys(entries[0]!.after ?? {}).sort();
          const remove = entries[0]!.after === null;

          if (
            entries.some(
              ({ key, before, after }) =>
                (after === null) !== remove ||
                Object.keys(key).sort().join("\0") !== keyFields.join("\0") ||
                Object.keys(before).sort().join("\0") !== beforeFields.join("\0") ||
                Object.keys(after ?? {})
                  .sort()
                  .join("\0") !== fields.join("\0"),
            )
          )
            return false;

          const names = Object.fromEntries([
            ...keyFields.map((name, i) => [`k${i}`, name]),
            ...beforeFields.map((name, i) => [`b${i}`, name]),
            ...fields.map((name, i) => [`v${i}`, name]),
          ]);

          const sets = rowsets(
            table,
            entries.map(({ key, before, after }) =>
              Object.fromEntries([
                ...keyFields.map((name, i) => [`k${i}`, key[name]]),
                ...beforeFields.map((name, i) => [`b${i}`, before[name]]),
                ...fields.map((name, i) => [`v${i}`, after![name]]),
              ]),
            ),
            names,
          );

          if (sets === undefined) return false;

          const queries = sets.map((set) => {
            const match = rowKeys(
              table,
              set,
              Object.fromEntries(keyFields.map((name, i) => [`k${i}`, name])),
            );

            const exact = exactRows(
              table,
              set,
              Object.fromEntries(beforeFields.map((name, i) => [`b${i}`, name])),
            );

            const where = both(base, match, exact);

            let selected = database
              .select(Object.fromEntries(keyFields.map((name) => [name, col(table, name)])))
              .from(set.source);

            selected =
              configuration.dialect === "sqlite"
                ? selected.crossJoin(table).where(both(base, match, exact))
                : selected.innerJoin(table, match).where(both(base, exact));

            const selectedKeys = sql`(${sql.join(
              keyFields.map((name) => col(table, name)),
              sql`, `,
            )}) in (${selected})`;

            // An uncorrelated IN relation is indexed once. A correlated EXISTS
            // over json_each would scan the entire bound page for every row.
            // Separate NULL shapes so IN retains native affinity and collation
            // without either NULL's three-valued comparison or sentinel values.
            const shapes = new Map<string, ReadonlyArray<boolean>>();

            for (const row of set.rows) {
              const shape = beforeFields.map((_, i) => row[`b${i}`] === null);

              shapes.set(shape.map(Number).join(""), shape);
            }

            const liveBefore = or(
              ...Array.from(shapes.values(), (shape) => {
                const populated = beforeFields.flatMap((name, i) =>
                  shape[i] ? [] : [{ name, i }],
                );

                const bytes = (value: SQLWrapper, strings: boolean) =>
                  !strings
                    ? value
                    : configuration.dialect === "pg"
                      ? sql`convert_to(cast(${value} as text), 'UTF8')`
                      : sql`cast(${value} as blob)`;

                const stringField = (i: number) =>
                  set.rows.some((row) => typeof row[`b${i}`] === "string");

                const nulls = beforeFields.flatMap((name, i) =>
                  shape[i] ? [isNull(col(table, name))] : [],
                );

                if (populated.length === 0) return both(...nulls);

                const values = populated.map(({ i }) =>
                  bytes(set.exactFields[`b${i}`]!, stringField(i)),
                );

                const actual = populated.map(({ name, i }) =>
                  bytes(col(table, name), stringField(i)),
                );

                const expectedShape = both(
                  ...beforeFields.map((_, i) =>
                    shape[i]
                      ? isNull(set.fields[`b${i}`]!)
                      : sql`${set.fields[`b${i}`]} is not null`,
                  ),
                );

                return both(
                  ...nulls,
                  sql`(${sql.join(actual, sql`, `)}) in (select ${sql.join(values, sql`, `)} from ${set.source} where ${expectedShape})`,
                );
              }),
            )!;

            let query;

            if (remove) query = database.delete(table).where(selectedKeys);
            else if (configuration.dialect === "sqlite") {
              const applied = entries.slice(set.offset, set.offset + set.rows.length);

              const values = fields.map((name, i) => {
                const choices: unknown[] = [];

                for (const entry of applied) {
                  if (
                    !choices.some((value) =>
                      matchesNativeRow(table, entry.after!, { [name]: value }),
                    )
                  )
                    choices.push(entry.after![name]);
                  if (choices.length > 4) break;
                }
                const encoded = (value: unknown) => sql`${sql.param(value, col(table, name))}`;
                let value: SQL;

                if (choices.length === 1) value = encoded(choices[0]);
                else if (choices.length <= 4) {
                  // Terminal states often have two outcomes. Index each key
                  // group once instead of scanning the payload for every row.
                  const cases = choices.slice(0, -1).map(
                    (value) => sql`when
                    (${sql.join(
                      keyFields.map((name) => col(table, name)),
                      sql`, `,
                    )}) in
                    (select ${sql.join(
                      keyFields.map((_, index) => set.fields[`k${index}`]),
                      sql`, `,
                    )}
                      from ${set.source} where ${set.fields[`v${i}`]} is ${encoded(value)})
                    then ${encoded(value)}`,
                  );

                  value = sql`case ${sql.join(cases, sql` `)} else ${encoded(choices[choices.length - 1])} end`;
                } else {
                  const keys = Object.fromEntries(
                    keyFields.map((name, index) => [`k${index}`, name]),
                  );

                  const patch = database
                    .select({
                      ...Object.fromEntries(
                        keyFields.map((name, index) => [
                          `k${index}`,
                          sql`${col(table, name)}`.as(`k${index}`),
                        ]),
                      ),
                      value: sql`${set.fields[`v${i}`]}`.as("value"),
                    })
                    .from(set.source)
                    .crossJoin(table)
                    .where(both(base, match));

                  const lookup = rowKeys(
                    table,
                    set,
                    keys,
                    Object.fromEntries(
                      Object.keys(keys).map((key) => [
                        key,
                        sql`auth_patch.${sql.identifier!(key)}`,
                      ]),
                    ),
                  );

                  // Native key columns retain their affinity and collation.
                  // The one-row probe lets SQLite index the materialized patch
                  // once instead of rescanning JSON for every changed row.
                  value = sql`(with auth_patch as materialized (${patch.getSQL()})
                    select auth_patch.value from json_each('[0]') as auth_patch_probe
                    cross join auth_patch where ${lookup})`;
                }

                return [
                  name,
                  i === 0
                    ? sql`case when ${both(base, liveBefore)} then ${value} else json_extract('[]', '$[auth-row-changed]') end`
                    : value,
                ] as const;
              });

              // UPDATE FROM precomputes assignments before row triggers run.
              // Ordinary UPDATE evaluates this guard on the row being changed,
              // so a trigger cannot refresh a later row and have it overwritten.
              query = database.update(table).set(Object.fromEntries(values)).where(selectedKeys);
            } else
              query = database
                .update(table)
                .set(
                  Object.fromEntries(fields.map((name, i) => [name, sql`${set.fields[`v${i}`]}`])),
                )
                .from(set.source)
                .where(where);

            const returned = projection(table, keyFields, remove ? liveBefore : sql`1 = 1`);

            return {
              set,
              returned,
              query: query.returning(returned.selection),
            };
          });

          if (
            queries.some(({ query }) => {
              const rendered = query.toSQL();

              return (
                rendered.params.length > maxParameters ||
                (maxParameters <= 100 && new TextEncoder().encode(rendered.sql).length > 96_000)
              );
            })
          )
            return false;
          for (const { set, query, returned } of queries) {
            const changed = yield* query as NativeQuery<Row[]>;

            invariant(
              changed.length === set.rows.length &&
                changed.every((row) => row[returned.conditionKey] === 1),
            );
            const applied = entries.slice(set.offset, set.offset + set.rows.length);
            const identities = new Map<string, number>();

            for (const row of changed) {
              const identity = rowIdentity(table, row, keyFields);

              identities.set(identity, (identities.get(identity) ?? 0) + 1);
            }
            // A trigger can rename a later row to an already deleted key.
            // Each expected identity must have its own RETURNING witness.
            invariant(
              applied.every(({ key }) => identities.get(rowIdentity(table, key, keyFields)) === 1),
            );
          }

          return true;
        }),
      ),
    check: (condition) =>
      result(
        Effect.gen(function* () {
          open();
          const holds = yield* conditionHolds(condition);

          if (configuration.batch)
            statements.push(
              toStatement(
                assertion(holds ? condition : sql`case when ${condition} then 0 else 1 end = 1`),
              ),
            );

          return holds;
        }),
      ),
    now: (clock) =>
      result(
        Effect.gen(function* () {
          open();
          readStatements++;

          const rows: Row[] = yield* database
            .select({
              value: sql`${clock.engineNowMillis}`.mapWith(Number),
            })
            .from(sql`(select 1) as oauth_clock`) as NativeQuery<Row[]>;

          const value = rows[0]?.value;

          invariant(Number.isSafeInteger(value) && value >= 0);

          return value as number;
        }),
      ),
    finish: () =>
      result(
        Effect.gen(function* () {
          open();
          phase = "finishing";
          Object.freeze(postconditions);
          Object.freeze(guards);
          Object.freeze(finalWrites);

          // Close registration before any late-bound SQL predicate is materialized.
          // No callback is invoked after the first final write.
          const conditions = postconditions.map((condition) =>
            typeof condition === "function" ? condition() : condition,
          );

          for (const guard of guards) {
            const status = yield* Effect.result(guard.read);

            invariant(status._tag === "Failure" && status.failure._tag === "CommitPending");
          }
          invariant(!poisoned);
          if (configuration.readonlySnapshot && readStatements <= 1) {
            invariant(guards.length === 0 && finalWrites.length === 0 && statements.length === 0);

            return;
          }
          for (const query of finalWrites)
            if (configuration.batch) statements.push(toStatement(query));
            else yield* query as NativeQuery<unknown>;
          if (configuration.batch) appendAssertions(conditions);
          else
            for (const condition of chunks(conditions)) invariant(yield* conditionHolds(condition));
          invariant(!poisoned);
        }).pipe(
          Effect.ensuring(
            Effect.sync(() => {
              phase = "finished";
            }),
          ),
        ),
      ),
  };

  return owner;
};

/** Receipt-bearing coordinators add their real journal to the native SQL scope. */
export const makeTransactionOwner = <Failure>(
  database: any,
  journal: CommitJournal,
  marker: string,
  unavailable: () => Failure,
  configuration: Parameters<typeof makeTransactionScope>[3],
): TransactionOwner<Failure> => ({
  ...makeTransactionScope(database, marker, unavailable, configuration),
  journal,
});
