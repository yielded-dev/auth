/* oxlint-disable no-explicit-any -- foreign query builders and mapping callbacks are validated at acquisition. */
import {
  type PasskeyCredential,
  type PasskeyUnavailable,
  PasskeyRevision,
  snapshotPasskeySync,
} from "@yielded/auth/Passkey";
import { type Crypto, Effect, Schema } from "effect";
import type { PlatformError } from "effect/PlatformError";
import type { SqlError } from "effect/sql/SqlError";

import type { QueryFailure, QueryOperations, SqlColumn } from "../query-operations";
import type { makeTransactionKernel } from "../transaction-kernel";
import type { makePasskeyStateKernel } from "./state";

export type PasskeyLookupResult =
  | { readonly _tag: "Snapshot"; readonly credential: PasskeyCredential | undefined }
  | { readonly _tag: "MappedReads" };

/** Standalone lookup is an advisory snapshot. Mutations use the locked reader
 * and revalidate the captured authority before committing. */
export const makePasskeyLookup = (
  operations: QueryOperations,
  state: Pick<
    ReturnType<typeof makePasskeyStateKernel>,
    | "col"
    | "copiedRow"
    | "credentialKey"
    | "credentialSnapshot"
    | "handleKey"
    | "invariant"
    | "mappedColumns"
    | "unavailable"
  >,
  transactions: Pick<
    ReturnType<typeof makeTransactionKernel>,
    "makeTransactionRows" | "reportTransactionFailure"
  >,
) => {
  const { asc, eq, sql } = operations;

  const {
    col,
    copiedRow,
    credentialKey,
    credentialSnapshot,
    handleKey,
    mappedColumns,
    unavailable,
  } = state;

  const invariant: (value: unknown) => asserts value = state.invariant;
  const { sameDriverValue } = transactions.makeTransactionRows(unavailable);
  const mappedReads: PasskeyLookupResult = { _tag: "MappedReads" };

  const snapshot = (credential?: PasskeyCredential): PasskeyLookupResult => ({
    _tag: "Snapshot",
    credential,
  });

  const hasDecoder = (
    column: SqlColumn,
  ): column is SqlColumn & Required<Pick<SqlColumn, "mapFromDriverValue">> =>
    typeof column.mapFromDriverValue === "function";

  return Effect.fn("passkey.lookupSnapshot")(
    function* (
      database: any,
      mapping: any,
      rpId: string,
      protocolCredentialId: string,
    ): Effect.fn.Return<
      PasskeyLookupResult,
      QueryFailure | SqlError | PlatformError | PasskeyUnavailable,
      Crypto.Crypto
    > {
      const ownership = mapping.credentialOwnership;
      const subject = mapping.subject;
      const credential = mapping.credential;
      const handle = mapping.handleOwnership;
      const authority = mapping.authority;

      const subjectColumns: ReadonlyArray<string> = [
        subject.id,
        subject.status,
        subject.securityRevision,
      ];

      const roles = [
        {
          descriptor: ownership,
          names: mappedColumns(ownership),
          condition: ownership.ownedCondition,
        },
        {
          descriptor: subject,
          names: subjectColumns,
          condition: subject.activeCondition,
        },
        {
          descriptor: credential,
          names: mappedColumns(credential),
          condition: credential.activeCondition,
        },
        { descriptor: handle, names: mappedColumns(handle), condition: handle.ownedCondition },
        {
          descriptor: authority,
          names: mappedColumns(authority),
          condition: authority.activeCondition,
        },
      ];

      const joins = [
        [col(subject.table, subject.id), col(ownership.table, ownership.subjectId)],
        [
          col(credential.table, credential.credentialId),
          col(ownership.table, ownership.credentialId),
        ],
        [col(handle.table, handle.handleKey), col(credential.table, credential.handleKey)],
        [col(authority.table, authority.subjectId), col(subject.table, subject.id)],
      ] as const;

      // An opaque custom ID mapping need not have join-compatible SQL types or
      // codecs. Its existing point reads remain the authority in that case.
      if (
        joins.some(
          ([left, right]) =>
            left.getSQLType === undefined ||
            right.getSQLType === undefined ||
            left.getSQLType() !== right.getSQLType() ||
            (left.dimensions ?? 0) !== (right.dimensions ?? 0),
        ) ||
        roles.some(({ descriptor, names }) =>
          names.some((name) => !hasDecoder(col(descriptor.table, name))),
        )
      )
        return mappedReads;

      const tupleKey = yield* credentialKey(rpId, protocolCredentialId);

      const sources = roles.map(({ descriptor, names, condition }, index) => {
        const fields = Object.fromEntries(
          names.map((name, field) => {
            const column = col(descriptor.table, name);
            const alias = `c${field}`;

            if (!hasDecoder(column)) throw unavailable();

            // Keep the column itself: the compiler also owns dialect codecs
            // such as PostgreSQL int8 -> number normalization.
            return [alias, sql`${column}`.mapWith(column).as(alias)];
          }),
        );

        const source = database
          .select({
            ...fields,
            present: sql`1`.mapWith(Number).as("present"),
            active: sql`case when ${condition} then 1 else 0 end`.mapWith(Number).as("active"),
          })
          .from(descriptor.table)
          .where(
            index === 0
              ? eq(col(ownership.table, ownership.credentialKey), tupleKey)
              : index === 4
                ? authority.activeCondition
                : undefined,
          )
          .as(`passkey_lookup_${index}`);

        const columns = Object.fromEntries(names.map((name, field) => [name, source[`c${field}`]]));

        return { source, columns, names };
      });

      const [o, s, c, h, a] = sources;

      const selection = Object.fromEntries(
        sources.flatMap(({ source, names }, index) => [
          [`r${index}present`, source.present],
          [`r${index}active`, source.active],
          ...names.map((_name, field) => [`r${index}c${field}`, source[`c${field}`]]),
        ]),
      );

      const rows = yield* database
        .select(selection)
        .from(o!.source)
        .leftJoin(s!.source, eq(s!.columns[subject.id], o!.columns[ownership.subjectId]))
        .leftJoin(
          c!.source,
          eq(c!.columns[credential.credentialId], o!.columns[ownership.credentialId]),
        )
        .leftJoin(h!.source, eq(h!.columns[handle.handleKey], c!.columns[credential.handleKey]))
        .leftJoin(a!.source, eq(a!.columns[authority.subjectId], s!.columns[subject.id]))
        .orderBy(asc(a!.columns[authority.credentialId]))
        .limit(65) as Effect.Effect<
        ReadonlyArray<Record<string, unknown>>,
        QueryFailure | SqlError
      >;

      const first = rows[0];

      if (first === undefined) return snapshot();
      const credentialFields = Object.keys(selection).filter((name) => !name.startsWith("r4"));

      invariant(
        rows.every((selected) =>
          credentialFields.every((name) => sameDriverValue(first[name], selected[name])),
        ),
      );

      const row = (index: number, selected = first) =>
        Object.fromEntries(
          sources[index]!.names.map((name, field) => [name, selected[`r${index}c${field}`]]),
        );

      const present = (index: number, selected = first) => selected[`r${index}present`] === 1;
      const active = (index: number) => first[`r${index}active`] === 1;

      const bindsLikeJoin = (
        target: SqlColumn,
        value: unknown,
        source: SqlColumn,
        stored: unknown,
      ) => {
        const binding = (column: SqlColumn, input: unknown) =>
          database
            .select({ value: sql`${sql.param(input, column)}` })
            .from(sql`(select 1) as passkey_binding`)
            .toSQL();

        // Rendering applies the compiler's parameter normalization and casts.
        // This does not execute another query.
        return sameDriverValue(binding(target, value), binding(source, stored));
      };

      const tuple = row(0);

      invariant(
        tuple[ownership.rpId] === rpId &&
          tuple[ownership.protocolCredentialId] === protocolCredentialId,
      );
      if (!ownership.isOwnedState(tuple[ownership.state])) return snapshot();
      const native = ownership.decodeSubjectId(copiedRow(tuple));
      const subjectId = mapping.subjectIds.toSubject(native);
      const nativeId = mapping.subjectIds.toNative(subjectId);

      invariant(mapping.subjectIds.equals(nativeId, native));
      invariant(mapping.subjectIds.toSubject(nativeId) === subjectId);
      if (!bindsLikeJoin(joins[0][0], nativeId, joins[0][1], tuple[ownership.subjectId]))
        return mappedReads;
      if (!present(1)) return snapshot();
      const subjectRow = row(1);

      if (!subject.isActiveStatus(subjectRow[subject.status])) return snapshot();
      invariant(mapping.subjectIds.equals(subject.decodeId(copiedRow(subjectRow)), nativeId));
      if (!active(1)) return snapshot();

      const securityRevision = yield* Schema.decodeUnknownEffect(
        PasskeyRevision.fields.securityRevision,
      )(subjectRow[subject.securityRevision]).pipe(Effect.mapError(unavailable));

      invariant(active(0));
      if (
        !bindsLikeJoin(
          joins[1][0],
          tuple[ownership.credentialId],
          joins[1][1],
          tuple[ownership.credentialId],
        )
      )
        return mappedReads;
      if (!present(2)) return snapshot();
      const credentialRow = row(2);

      if (!credential.isActiveStatus(credentialRow[credential.status])) return snapshot();
      if (
        !mapping.subjectIds.equals(credential.decodeSubjectId(copiedRow(credentialRow)), nativeId)
      )
        return snapshot();
      const decoded = credential.decode(copiedRow(credentialRow));
      const expectedHandleKey = yield* handleKey(rpId, decoded.userHandle);

      invariant(
        credentialRow[credential.credentialKey] === tupleKey &&
          credentialRow[credential.handleKey] === expectedHandleKey,
      );
      if (
        !bindsLikeJoin(
          joins[2][0],
          expectedHandleKey,
          joins[2][1],
          credentialRow[credential.handleKey],
        )
      )
        return mappedReads;
      if (!present(3)) return snapshot();
      const handleRow = row(3);

      if (!handle.isOwnedState(handleRow[handle.state])) return snapshot();
      invariant(
        handleRow[handle.rpId] === rpId && handleRow[handle.userHandle] === decoded.userHandle,
      );
      if (!mapping.subjectIds.equals(handle.decodeSubjectId(copiedRow(handleRow)), nativeId))
        return snapshot();
      invariant(active(3) && active(2));
      if (!bindsLikeJoin(joins[3][0], nativeId, joins[3][1], subjectRow[subject.id]))
        return mappedReads;
      invariant(rows.length <= 64);

      const factors = rows
        .filter((selected) => present(4, selected))
        .map((selected) => {
          const factor = row(4, selected);

          invariant(authority.isActiveStatus(factor[authority.status]));

          return {
            credentialId: factor[authority.credentialId],
            revision: factor[authority.revision],
          };
        });

      const revisionValue = yield* Schema.decodeUnknownEffect(PasskeyRevision)({
        subjectId,
        securityRevision,
        credentials: factors,
      }).pipe(Effect.mapError(unavailable));

      const revision = snapshotPasskeySync(PasskeyRevision, revisionValue);

      invariant(
        new Set(revision.credentials.map((factor) => factor.credentialId)).size === factors.length,
      );

      return snapshot(
        credentialSnapshot(
          mapping,
          credentialRow,
          tuple,
          decoded,
          revision,
          rpId,
          protocolCredentialId,
        ),
      );
    },
    (effect) =>
      effect.pipe(
        (operation) => transactions.reportTransactionFailure(operation, unavailable),
        Effect.mapError(unavailable),
        Effect.catchDefect(() => Effect.fail(unavailable())),
      ),
  );
};
