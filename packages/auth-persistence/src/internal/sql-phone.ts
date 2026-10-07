import { PhoneCustody, PhoneOtpUnavailable } from "@yielded/auth/PhoneOtp";
import { AuthenticationRevision } from "@yielded/auth/Sessions";
import { Crypto, Effect, Schema } from "effect";
import type { SqlClient } from "effect/sql/SqlClient";
import type { Fragment } from "effect/sql/Statement";

import type { MappingInput } from "./configuration";
import { digest, randomId } from "./crypto";
import { jsonBatches } from "./json-batches";
import type { PersistenceOwner } from "./persistence-owner";
import {
  PhoneAdmissionCounter,
  PhoneAdmissionReceipt,
  PhoneStoredState,
  phoneAdmissionDecision,
  phoneAdmissionExpiry,
  phoneAdmissionReplay,
  phoneSignInSnapshot,
  phoneStateScope,
  validPhoneAdmissionInput,
} from "./phone-policy";
import { composedPhoneAdmission, type PhoneStore } from "./phone-store";
import {
  decodeSqlRow,
  requireSqlTable,
  sqlColumn,
  sqlInsert,
  sqlName,
  sqlProjection,
  sqlTable,
  sqlUpdate,
  sqlValue,
} from "./sql-metadata";
import type { Table } from "./sql-table";

type Row = Readonly<Record<string, unknown>>;

export const makeSqlPhoneOwner = Effect.fnUntraced(function* (
  client: SqlClient,
  storage: MappingInput,
  options: { readonly dialect: "pg" | "sqlite"; readonly maxParameters?: number },
): Effect.fn.Return<PersistenceOwner<PhoneStore>, never, Crypto.Crypto> {
  const crypto = yield* Crypto.Crypto;
  const sql = client.withoutTransforms();

  const state = requireSqlTable(storage.tables.phoneState!),
    subjects = requireSqlTable(storage.subjects.table),
    identifiers = requireSqlTable(storage.tables.identifiers!),
    credentials = requireSqlTable(storage.tables.credentials!);

  const subject = storage.subjects;
  const policy = composedPhoneAdmission;

  const c = (table: Table, key: string) => sqlColumn(sql, table, key),
    t = (table: Table) => sqlTable(sql, table),
    v = (table: Table, key: string, value: unknown) => sqlValue(sql, table, key, value);

  const lock = options.dialect === "pg" ? sql`for update` : sql``;

  const engineNow =
    options.dialect === "pg"
      ? sql`cast(extract(epoch from clock_timestamp()) * 1000 as bigint)`
      : sql`cast(round((julianday('now') - 2440587.5) * 86400000) as integer)`;

  const now = sql`select ${engineNow} as now`.pipe(
    Effect.flatMap((rows) => Schema.decodeEffect(Schema.Natural)(Number(rows[0]?.now))),
  );

  const exact = (table: Table, row: Row) =>
    sql.and(
      Object.entries(row)
        .filter(([key]) => table.columns[key] !== undefined)
        .map(([key, value]) =>
          value === null
            ? sql`${c(table, key)} is null`
            : sql`${c(table, key)}=${v(table, key, value)}`,
        ),
    );

  const witness = (table: Table, key: Fragment, row: Row | undefined) =>
    row === undefined
      ? sql`not exists(select 1 from ${t(table)} where ${key})`
      : sql`exists(select 1 from ${t(table)} where ${key} and ${exact(table, row)})`;

  const assert = (conditions: ReadonlyArray<Fragment>) =>
    sql`select case when ${sql.and(conditions)} then 1 else 0 end as valid`.pipe(
      Effect.flatMap((rows) =>
        Number(rows[0]?.valid) === 1 ? Effect.void : Effect.fail(PhoneOtpUnavailable.make({})),
      ),
    );

  const read = Effect.fnUntraced(function* (table: Table, condition: Fragment) {
    const rows =
      yield* sql`select ${sqlProjection(sql, table)} from ${t(table)} where ${condition} limit 1 ${lock}`;

    return rows[0] === undefined ? undefined : yield* decodeSqlRow(table, rows[0]);
  });

  const stateRead = Effect.fnUntraced(function* (moduleId: string, key: string) {
    const row = yield* read(state, sql`${c(state, "scope")}=${key}`);

    const stored =
      row === undefined
        ? undefined
        : yield* Schema.decodeUnknownEffect(PhoneStoredState)(row.state);

    if (stored !== undefined && stored.moduleId !== moduleId)
      return yield* PhoneOtpUnavailable.make({});

    return { key, row, record: stored?.record };
  });

  const stateWrite = Effect.fnUntraced(function* (
    moduleId: string,
    captured: Effect.Success<ReturnType<typeof stateRead>>,
    record: (typeof PhoneStoredState.Type)["record"],
  ) {
    const payload = yield* Schema.encodeEffect(PhoneStoredState)({ moduleId, record });
    const version = yield* randomId;
    const values = { state: payload, version };

    if (captured.row === undefined)
      yield* sql`insert into ${t(state)} ${sqlInsert(sql, state, { scope: captured.key, ...values })}`;
    else
      yield* sql`update ${t(state)} set ${sqlUpdate(sql, state, values)} where ${exact(state, captured.row)}`;

    return { ...captured.row, scope: captured.key, ...values };
  });

  const protect = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(Effect.provideService(Crypto.Crypto, crypto));

  const store: PhoneStore = {
    admit: (input) =>
      protect(
        Effect.gen(function* () {
          if (!validPhoneAdmissionInput(input)) return yield* PhoneOtpUnavailable.make({});
          const timestamp = yield* now;
          const network = yield* digest(input.networkKey);

          const key = yield* phoneStateScope(
            input.moduleId,
            "admission",
            input.action + "/" + input.requestId,
          );

          const receipt = yield* stateRead(input.moduleId, key);

          if (receipt.record !== undefined) {
            const saved = yield* Schema.decodeUnknownEffect(PhoneAdmissionReceipt)(receipt.record);

            yield* assert([
              witness(state, sql`${c(state, "scope")}=${key}`, receipt.row),
              ...(saved.expiresAtMillis > timestamp
                ? [sql`${engineNow}<${saved.expiresAtMillis}`]
                : []),
            ]);

            return phoneAdmissionReplay(saved, input, network, timestamp);
          }

          const entries = [
            {
              key: yield* phoneStateScope(input.moduleId, "network", input.action + "/" + network),
              limit: input.action === "request" ? policy.networkRequests : policy.networkAttempts,
            },
            ...(input.action === "request"
              ? [
                  {
                    key: yield* phoneStateScope(input.moduleId, "messages", "global"),
                    limit: policy.maximumMessages,
                  },
                ]
              : []),
          ].sort((a, b) => a.key.localeCompare(b.key));

          const observed = yield* Effect.forEach(entries, (entry) =>
            Effect.gen(function* () {
              const captured = yield* stateRead(input.moduleId, entry.key);

              const previous =
                captured.record === undefined
                  ? undefined
                  : yield* Schema.decodeUnknownEffect(PhoneAdmissionCounter)(captured.record);

              return { ...entry, captured, previous };
            }),
          );

          const decision = phoneAdmissionDecision(timestamp, policy, observed);
          const conditions: Fragment[] = [];

          for (const [index, entry] of observed.entries()) {
            const expected = decision.accepted
              ? yield* stateWrite(input.moduleId, entry.captured, {
                  window: decision.window,
                  count: decision.counts[index]! + 1,
                })
              : entry.captured.row;

            conditions.push(witness(state, sql`${c(state, "scope")}=${entry.key}`, expected));
          }

          const expected = yield* stateWrite(input.moduleId, receipt, {
            fingerprint: input.fingerprint,
            network,
            accepted: decision.accepted,
            expiresAtMillis:
              timestamp + Math.min(policy.requestRetentionMillis, input.replayLifetimeMillis),
          });

          conditions.push(
            witness(state, sql`${c(state, "scope")}=${key}`, expected),
            sql`${engineNow}>=${decision.window * policy.windowMillis} and ${engineNow}<${(decision.window + 1) * policy.windowMillis}`,
          );
          yield* assert(conditions);

          return decision.accepted;
        }),
      ),
    lookup: (input) =>
      protect(
        Effect.gen(function* () {
          const key = yield* phoneStateScope(input.moduleId, "custody", input.phoneNumber);
          const saved = yield* stateRead(input.moduleId, key);

          const custody =
            saved.record === undefined
              ? null
              : yield* Schema.decodeUnknownEffect(PhoneCustody)(saved.record);

          if (custody !== null && custody.phoneNumber !== input.phoneNumber)
            return yield* PhoneOtpUnavailable.make({});
          const native = custody === null ? undefined : subject.toNativeSync(custody.subjectId);
          const subjectWhere = sql`${c(subjects, subject.id)}=${v(subjects, subject.id, native)}`;

          const ownerRows =
            custody === null
              ? []
              : yield* sql`select ${sqlProjection(sql, subjects)}, case when ${c(subjects, subject.status)} = ${v(subjects, subject.status, subject.activeValue)} then 1 else 0 end as phone_subject_active from ${t(subjects)} where ${subjectWhere} limit 1 ${lock}`;

          const owner =
            ownerRows[0] === undefined ? undefined : yield* decodeSqlRow(subjects, ownerRows[0]);

          const identifierWhere = sql`${c(identifiers, "namespace")}=${"phone"} and ${c(identifiers, "value")}=${input.phoneNumber}`;
          const identifier = yield* read(identifiers, identifierWhere);

          const credentialWhere =
            custody === null
              ? sql`false`
              : sql`${c(credentials, "credentialId")}=${custody.credentialId} and ${c(credentials, "subjectId")}=${v(credentials, "subjectId", native)}`;

          const credential =
            custody?.state === "verified" ? yield* read(credentials, credentialWhere) : undefined;

          const conditions = [
            witness(state, sql`${c(state, "scope")}=${key}`, saved.row),
            witness(identifiers, identifierWhere, identifier),
            ...(custody === null ? [] : [witness(subjects, subjectWhere, owner)]),
            ...(custody?.state !== "verified"
              ? []
              : [witness(credentials, credentialWhere, credential)]),
          ];

          const active = owner !== undefined && Number(ownerRows[0]?.phone_subject_active) === 1;

          const credentialCurrent =
            custody !== null &&
            credential !== undefined &&
            credential.active === true &&
            credential.revision === custody.credentialRevision;

          const revision =
            active && custody !== null
              ? yield* Schema.decodeUnknownEffect(AuthenticationRevision)({
                  subjectId: custody.subjectId,
                  securityRevision: owner[subject.securityRevision],
                  credentials: credentialCurrent
                    ? [{ credentialId: custody.credentialId, revision: custody.credentialRevision }]
                    : [],
                })
              : null;

          const matches =
            identifier !== undefined &&
            custody !== null &&
            identifier.revision === custody.custodyRevision &&
            identifier.active === true;

          // Native comparison binds through the identifier column, preserving its codec.
          const identifierOwned = matches
            ? yield* sql`select 1 as present from ${t(identifiers)} where ${identifierWhere} and ${c(identifiers, "subjectId")}=${v(identifiers, "subjectId", native)} limit 1`.pipe(
                Effect.map((rows) => rows.length === 1),
              )
            : false;

          const result = yield* phoneSignInSnapshot(input, custody, revision, identifierOwned);

          yield* assert(conditions);

          return result;
        }),
      ),
    cleanup: (input) =>
      protect(
        Effect.gen(function* () {
          if (!Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > 1000)
            return yield* PhoneOtpUnavailable.make({});
          const timestamp = yield* now;

          const selected =
            yield* sql`select ${sqlProjection(sql, state)} from ${t(state)} where ${input.after === undefined ? sql`true` : sql`${c(state, "scope")}>${input.after}`} order by ${c(state, "scope")} limit ${input.limit} ${lock}`;

          const rows = yield* Effect.forEach(selected, (row) => decodeSqlRow(state, row));
          const expired: Row[] = [];
          let horizon = 0;

          for (const row of rows) {
            const stored = yield* Schema.decodeUnknownEffect(PhoneStoredState)(row.state);

            if (stored.moduleId !== input.moduleId) continue;
            const expires = phoneAdmissionExpiry(stored.record, policy);

            if (expires !== undefined && expires <= timestamp) {
              expired.push(row);
              horizon = Math.max(horizon, expires);
            }
          }
          let cleanupName = "__auth_phone_cleanup";

          while (state.name.toLowerCase() === cleanupName.toLowerCase()) cleanupName += "_";
          const cleanupAlias = sqlName(sql, cleanupName);
          const cleanupValue = sql`${cleanupAlias}.${sqlName(sql, "value")}`;

          const relation = (payload: string) =>
            options.dialect === "pg"
              ? sql`jsonb_array_elements(cast(${payload} as jsonb)) as ${cleanupAlias}(value)`
              : sql`json_each(${payload}) as ${cleanupAlias}`;

          const captured = (key: string) =>
            options.dialect === "pg"
              ? sql`${cleanupValue} -> 'row' ->> ${key}`
              : sql`json_extract(${cleanupValue}, ${"$.row." + JSON.stringify(key)})`;

          // These are raw metadata primitives. Keep SQLite's storage class and
          // compare text bytes so collations cannot weaken the captured snapshot.
          const unchanged = sql.and(
            Object.entries(state.columns).map(([key, column]) => {
              const current = c(state, key),
                expected = captured(key);

              if (column.options.type === "text")
                return options.dialect === "pg"
                  ? sql`convert_to(cast(${current} as text), 'UTF8') is not distinct from convert_to(${expected}, 'UTF8')`
                  : sql`cast(${current} as blob) is cast(${expected} as blob)`;

              return options.dialect === "pg"
                ? column.options.type === "integer"
                  ? sql`${current} is not distinct from cast(${expected} as bigint)`
                  : sql`${current} is not distinct from cast(${expected} as boolean)`
                : sql`${current} is ${expected}`;
            }),
          );

          const scopeMatches = sql`${c(state, "scope")}=${captured("scope")}`;

          for (const batch of yield* jsonBatches(expired.map((row) => ({ row })))) {
            const removed =
              yield* sql`delete from ${t(state)} where ${c(state, "scope")} in (select ${c(state, "scope")} from ${relation(batch.payload)} join ${t(state)} on ${scopeMatches} where ${unchanged}) and ${engineNow}>=${horizon} returning 1 as removed`;

            if (removed.length !== batch.rows.length) return yield* PhoneOtpUnavailable.make({});
          }
          for (const batch of yield* jsonBatches(
            rows.map((row) => ({ row, deleted: expired.includes(row) ? 1 : 0 })),
          )) {
            const deleted =
              options.dialect === "pg"
                ? sql`${cleanupValue} ->> 'deleted' = '1'`
                : sql`json_extract(${cleanupValue}, '$.deleted') = 1`;

            yield* assert([
              sql`not exists(select 1 from ${relation(batch.payload)} where case when ${deleted} then exists(select 1 from ${t(state)} where ${scopeMatches}) else not exists(select 1 from ${t(state)} where ${scopeMatches} and ${unchanged}) end)`,
              ...(expired.length === 0 ? [] : [sql`${engineNow}>=${horizon}`]),
            ]);
          }

          return {
            deleted: expired.length,
            nextCursor: rows.length === input.limit ? String(rows[rows.length - 1]!.scope) : null,
          };
        }),
      ),
  };

  return {
    read: store,
    transaction: (body) => sql.withTransaction(body(store)),
  };
});
