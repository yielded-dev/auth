/* oxlint-disable no-explicit-any -- physical mapping generics are erased only at this shared adapter boundary. */
import * as M from "@yielded/auth/Passkey";
import { Effect, Schema } from "effect";
import { SqlClient } from "effect/sql";
import type { Fragment } from "effect/sql/Statement";

import type { PasskeyCredentialMapping, PasskeyPersistenceMapping } from "./models/passkey-model";
import { sqlMapping, type NativeSqlTables } from "./native-sql-table";
import { makePasskeyNativeFlow } from "./passkey-native-flow";
import { passkeyCredentialKey } from "./passkey-policy";
import { exactSqlText } from "./sql-change";
import type { TableModel } from "./table-model";

// Physical expression types are validated by NativeSqlTables at this boundary.
export type PasskeyNativeRead = PasskeyCredentialMapping<
  TableModel,
  TableModel,
  TableModel,
  unknown,
  any
>;

export type PasskeyNativeMapping = PasskeyPersistenceMapping<
  PasskeyNativeRead,
  TableModel,
  unknown,
  any
>;

export type PasskeyNativeRow = Readonly<Record<string, unknown>>;

export const passkeyNativeInvariant: (value: unknown) => asserts value = (value) => {
  if (!value) throw M.PasskeyUnavailable.make({});
};

export const makePasskeyNativeReadState = Effect.fnUntraced(function* (
  tables: NativeSqlTables,
  read: PasskeyNativeRead,
  clock?: PasskeyNativeMapping["clock"],
) {
  const sql = (yield* SqlClient.SqlClient).withoutTransforms();
  const subject = tables(read.subject.table);
  const credential = tables(read.credential.table);
  const factor = tables(read.authority.table);
  const now = clock === undefined ? sql`0` : tables.expression(clock.engineNowMillis);

  const millis = (expression: Fragment) =>
    clock === undefined ? expression : tables.expression(clock.toMillis(expression));

  const storedNow =
    clock === undefined ? sql`0` : tables.expression(clock.fromMillis(clock.engineNowMillis));

  const active = (table: "subject" | "credential" | "authority") =>
    tables.expression(read[table].activeCondition);

  const invariant: typeof passkeyNativeInvariant = passkeyNativeInvariant;
  const sameId = (nativeId: unknown, value: unknown) => read.subjectIds.equals(nativeId, value);

  const native = (id: M.PasskeyCredential["revision"]["subjectId"]) => {
    const value = read.subjectIds.toNative(id);

    invariant(read.subjectIds.toSubject(value) === id);

    return value;
  };

  const revisions = (nativeId: unknown, rows: ReadonlyArray<PasskeyNativeRow>) => {
    const entries = new Map<string, M.PasskeyCredential["revision"]["securityRevision"]>();

    for (const row of rows) {
      if (row[read.authority.credentialId] === null) continue;
      invariant(sameId(nativeId, row[read.authority.subjectId]));
      if (!read.authority.isActiveStatus(row[read.authority.status])) continue;

      const decoded = Schema.decodeUnknownSync(M.PasskeyRevision.fields.credentials)([
        {
          credentialId: row[read.authority.credentialId],
          revision: row[read.authority.revision],
        },
      ]);

      const entry = decoded[0];

      invariant(entry !== undefined);
      const previous = entries.get(entry.credentialId);

      invariant(previous === undefined || previous === entry.revision);
      entries.set(entry.credentialId, entry.revision);
    }
    invariant(entries.size <= 64);

    return [...entries]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([credentialId, revision]) => ({ credentialId, revision }));
  };

  const revision = (row: PasskeyNativeRow, factors: ReadonlyArray<PasskeyNativeRow>) => {
    const id = read.subject.decodeId(row);
    const subjectId = read.subjectIds.toSubject(id);

    invariant(sameId(native(subjectId), id));

    return Schema.decodeUnknownSync(M.PasskeyRevision)({
      subjectId,
      securityRevision: row[read.subject.securityRevision],
      credentials: revisions(id, factors),
    });
  };

  const decodeCredential = Effect.fnUntraced(function* (
    row: PasskeyNativeRow,
    current: M.PasskeyCredential["revision"],
    subjectRow: PasskeyNativeRow,
  ) {
    const value = read.credential.decode(row);
    const owned = current.credentials.find((entry) => entry.credentialId === value.credentialId);

    if (
      !read.credential.isActiveStatus(row[read.credential.status]) ||
      owned?.revision !== row[read.credential.credentialRevision]
    )
      return undefined;
    invariant(
      read.subjectIds.toSubject(read.credential.decodeSubjectId(row)) === current.subjectId,
    );

    return M.snapshotPasskeySync(M.PasskeyCredential, {
      ...value,
      revision: current,
      requirement: yield* read.subject.decodeRequirement(subjectRow),
      active: true,
    });
  });

  const readAuthority = Effect.fnUntraced(function* (nativeId: unknown, lock: boolean) {
    // The subject lock is a distinct first statement; joined FOR UPDATE cannot
    // establish the lock order required by coordinated application transactions.
    if (lock) {
      const locked =
        yield* sql<PasskeyNativeRow>`select ${subject.fields("s_")}, ${now} as "engineNow" from ${subject.name} where ${subject.column(read.subject.id)} = ${subject.value(read.subject.id, nativeId)} and ${active("subject")} ${sql.onDialectOrElse({ pg: () => sql`for update`, mysql: () => sql`for update`, orElse: () => sql`` })}`;

      if (locked.length !== 1) return undefined;
      const row = subject.decode(locked[0]!, "s_");

      if (
        !sameId(read.subject.decodeId(row), nativeId) ||
        !read.subject.isActiveStatus(row[read.subject.status])
      )
        return undefined;

      const rows =
        yield* sql<PasskeyNativeRow>`select ${factor.fields("f_")} from ${factor.name} where ${factor.column(read.authority.subjectId)} = ${factor.value(read.authority.subjectId, nativeId)} and ${active("authority")} order by ${factor.column(read.authority.credentialId)} limit 65 ${sql.onDialectOrElse({ pg: () => sql`for update`, mysql: () => sql`for update`, orElse: () => sql`` })}`;

      return {
        row,
        revision: revision(
          row,
          rows.map((row) => factor.decode(row, "f_")),
        ),
        nowMillis: yield* Schema.decodeEffect(Schema.Int)(Number(locked[0]!.engineNow)),
      };
    }

    const observedSubject = joinedSubject,
      observedFactor = joinedFactor;

    const rows =
      yield* sql<PasskeyNativeRow>`select ${observedSubject.fields("s_")}, ${observedFactor.fields("f_")}, ${now} as "engineNow" from ${selected("subject", "passkey_subject")} left join ${selected("authority", "passkey_factor")} on ${observedFactor.column(read.authority.subjectId)} = ${observedFactor.value(read.authority.subjectId, nativeId)} where ${observedSubject.column(read.subject.id)} = ${observedSubject.value(read.subject.id, nativeId)} limit 65`;

    if (rows.length === 0 || rows.length > 64) return undefined;
    const row = observedSubject.decode(rows[0]!, "s_");

    if (
      !sameId(read.subject.decodeId(row), nativeId) ||
      !read.subject.isActiveStatus(row[read.subject.status])
    )
      return undefined;
    invariant(
      rows.every((selected) => {
        const other = observedSubject.decode(selected, "s_");

        return (
          sameId(read.subject.decodeId(other), nativeId) &&
          other[read.subject.securityRevision] === row[read.subject.securityRevision] &&
          read.subject.isActiveStatus(other[read.subject.status])
        );
      }),
    );

    return {
      row,
      revision: revision(
        row,
        rows.map((selected) => observedFactor.decode(selected, "f_")),
      ),
      nowMillis: yield* Schema.decodeEffect(Schema.Int)(Number(rows[0]!.engineNow)),
    };
  });

  // Active predicates retain their original table qualification inside each
  // subquery; aliases allow applications to map several roles to one table.
  const joinedSubject = subject.as("passkey_subject");
  const joinedFactor = factor.as("passkey_factor");
  const joinedCredential = credential.as("passkey_credential");

  const selected = (kind: "subject" | "authority" | "credential", alias: string) => {
    const table = kind === "subject" ? subject : kind === "authority" ? factor : credential;

    return sql`(select * from ${table.name} where ${active(kind)}) as ${sql(alias)}`;
  };

  const lookup = Effect.fnUntraced(function* (rpId: string, protocolCredentialId: string) {
    const key = yield* passkeyCredentialKey(rpId, protocolCredentialId);

    if (
      subject.unencodedTextColumn?.(read.subject.id) !== undefined &&
      credential.unencodedTextColumn?.(read.credential.subjectId) !== undefined &&
      factor.unencodedTextColumn?.(read.authority.subjectId) !== undefined
    ) {
      const s = joinedSubject,
        c = joinedCredential,
        f = joinedFactor;

      const rows =
        yield* sql<PasskeyNativeRow>`select ${s.fields("s_")}, ${c.fields("c_")}, ${f.fields("f_")}
        from ${selected("credential", "passkey_credential")}
        join ${selected("subject", "passkey_subject")} on ${exactSqlText(sql, s.column(read.subject.id), c.column(read.credential.subjectId))}
        left join ${selected("authority", "passkey_factor")} on ${exactSqlText(sql, f.column(read.authority.subjectId), c.column(read.credential.subjectId))}
        where ${exactSqlText(sql, c.column(read.credential.credentialKey), c.value(read.credential.credentialKey, key))} limit 65`;

      if (rows.length === 0 || rows.length > 64) return undefined;
      const row = c.decode(rows[0]!, "c_");
      const subjectRow = s.decode(rows[0]!, "s_");
      const owner = read.credential.decodeSubjectId(row);

      invariant(
        row[read.credential.rpId] === rpId &&
          row[read.credential.protocolCredentialId] === protocolCredentialId,
      );
      invariant(
        rows.every((selected) => {
          const other = c.decode(selected, "c_");
          const subjectValue = s.decode(selected, "s_");

          return (
            sameId(owner, read.credential.decodeSubjectId(other)) &&
            sameId(owner, read.subject.decodeId(subjectValue)) &&
            other[read.credential.credentialId] === row[read.credential.credentialId] &&
            other[read.credential.credentialRevision] === row[read.credential.credentialRevision] &&
            subjectValue[read.subject.securityRevision] ===
              subjectRow[read.subject.securityRevision]
          );
        }),
      );

      return yield* decodeCredential(
        row,
        revision(
          subjectRow,
          rows.map((row) => f.decode(row, "f_")),
        ),
        subjectRow,
      );
    }

    const rows =
      yield* sql<PasskeyNativeRow>`select ${credential.fields("c_")} from ${credential.name} where ${credential.column(read.credential.credentialKey)} = ${credential.value(read.credential.credentialKey, key)} and ${active("credential")}`;

    if (rows.length !== 1) return undefined;
    const row = credential.decode(rows[0]!, "c_");

    invariant(
      row[read.credential.rpId] === rpId &&
        row[read.credential.protocolCredentialId] === protocolCredentialId,
    );
    const current = yield* readAuthority(read.credential.decodeSubjectId(row), false);

    return current === undefined
      ? undefined
      : yield* decodeCredential(row, current.revision, current.row);
  });

  return {
    sql,
    tables,
    subject,
    credential,
    factor,
    now,
    storedNow,
    millis,
    active,
    native,
    sameId,
    revision,
    decodeCredential,
    readAuthority,
    lookup,
    joinedSubject,
    joinedFactor,
    joinedCredential,
    selected,
    mapped: sqlMapping,
  };
});

export const makePasskeyNativeState = Effect.fnUntraced(function* (
  tables: NativeSqlTables,
  mapping: PasskeyNativeMapping,
) {
  const state = yield* makePasskeyNativeReadState(tables, mapping.read, mapping.clock);
  const ceremony = yield* makePasskeyNativeFlow(tables, mapping);

  return { ...state, mapping, ceremony, flow: ceremony.flow, access: ceremony.access };
});

export type PasskeyNativeReadState = Effect.Success<ReturnType<typeof makePasskeyNativeReadState>>;
export type PasskeyNativeState = Effect.Success<ReturnType<typeof makePasskeyNativeState>>;
