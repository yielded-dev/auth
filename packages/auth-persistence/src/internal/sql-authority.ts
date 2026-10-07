import type { LifecycleHooks } from "@yielded/auth/Hooks";
import { TokenDigest } from "@yielded/auth/Schema";
import {
  SessionUnavailable,
  SecurityRevision,
  type AuthenticationAuthority,
} from "@yielded/auth/Sessions";
import { Context, Effect, Option, Schema } from "effect";
import { SqlClient } from "effect/sql";

import { PersistenceConfigurationError } from "./configuration";
import type { AuthenticationAuthorityMapping } from "./models/session-model";
import { makeNativeSqlTables } from "./native-sql-table";
import { invariant } from "./oauth/state";
import type { SessionAuthorityStore, SessionTransactionOwner } from "./session-store";
import { makeAuthenticationAuthorityWorkflow } from "./session-workflow";
import { exactSqlText, executeSqlChange } from "./sql-change";
import type { SqlTableModel } from "./sql-oauth-model";
import { validateSqlStorage } from "./sql-storage-validation";
import { requireStandalone } from "./standalone";

class CurrentSqlAuthority extends Context.Service<CurrentSqlAuthority, object>()(
  "@yielded/auth-persistence/CurrentSqlAuthority",
) {}

/** Native direct-SQL bridge for the shared authentication/session policy. */
export const makeAuthenticationAuthorityServices = Effect.fnUntraced(function* <Claims, N>(
  mapping: AuthenticationAuthorityMapping<
    Claims,
    SqlTableModel,
    SqlTableModel,
    SqlTableModel,
    SqlTableModel,
    N
  >,
): Effect.fn.Return<
  { readonly authenticationAuthority: AuthenticationAuthority["Service"] },
  SessionUnavailable | PersistenceConfigurationError,
  LifecycleHooks | SqlClient.SqlClient
> {
  const sql = (yield* SqlClient.SqlClient).withoutTransforms();

  const dialect = sql.onDialectOrElse({
    pg: () => "pg" as const,
    sqlite: () => "sqlite" as const,
    orElse: () => undefined,
  });

  if (dialect === undefined)
    return yield* PersistenceConfigurationError.make({
      reason: "Authentication authority requires PostgreSQL or SQLite",
    });
  yield* validateSqlStorage(mapping).pipe(Effect.mapError(() => SessionUnavailable.make({})));
  const tables = makeNativeSqlTables(sql);
  const subject = tables(mapping.subject.table);
  const credential = tables(mapping.credential.table);
  const s = mapping.subject;
  const c = mapping.credential;
  const lock = (locking: boolean) => (locking && dialect === "pg" ? sql`for update` : sql``);

  const store: SessionAuthorityStore<Claims> = {
    readAuthority: (id, requested, locking) =>
      Effect.gen(function* () {
        const native = yield* mapping.subjectId.toNative(id);
        const subjectPredicate = sql`${subject.column(s.id)} = ${subject.value(s.id, native)}`;

        const credentials = sql.and([
          sql`${credential.column(c.subjectId)} = ${credential.value(c.subjectId, native)}`,
          requested.length === 0
            ? sql`false`
            : sql.or(
                requested.map((id) =>
                  exactSqlText(
                    sql,
                    credential.column(c.credentialId),
                    credential.value(c.credentialId, id),
                  ),
                ),
              ),
        ]);

        const rows =
          yield* sql`with authority_subject as ${locking && dialect === "pg" ? sql`materialized` : sql``} (select * from ${subject.name} where ${subjectPredicate} ${lock(locking)}), authority_credentials as ${locking && dialect === "pg" ? sql`materialized` : sql``} (select * from ${credential.name} where ${credentials} and exists(select 1 from authority_subject) order by ${credential.column(c.credentialId)} ${lock(locking)}) select ${subject.as("a").fields("subject_")}, ${credential.as("c").fields("credential_")} from authority_subject as a left join authority_credentials as c on true`;

        if (rows.length === 0) return { subject: undefined, credentials: [], flow: undefined };
        const owner = subject.decode(rows[0]!, "subject_");

        invariant(mapping.subjectId.equals(owner[s.id] as N, native));

        return {
          subject: {
            active: s.isActiveStatus(owner[s.status]),
            securityRevision: yield* Schema.decodeUnknownEffect(SecurityRevision)(
              owner[s.securityRevision],
            ),
            requirement: s.decodeRequirement(owner),
          },
          credentials: yield* Effect.forEach(rows, (raw) =>
            Effect.gen(function* () {
              const row = credential.decode(raw, "credential_");

              if (row[c.credentialId] === null) return undefined;
              invariant(mapping.subjectId.equals(row[c.subjectId] as N, native));

              return {
                credentialId: yield* Schema.decodeUnknownEffect(Schema.String)(row[c.credentialId]),
                revision: yield* Schema.decodeUnknownEffect(SecurityRevision)(row[c.revision]),
                active: c.status === undefined || c.isActiveStatus?.(row[c.status]) === true,
              };
            }),
          ).pipe(Effect.map((values) => values.filter((value) => value !== undefined))),
          flow: undefined,
        };
      }),
    ...(mapping.pending === undefined
      ? {}
      : (() => {
          const mapped = mapping.pending;
          const p = mapped.pending;
          const f = mapped.flow;
          const pending = tables(p.table);
          const flow = tables(f.table);

          return {
            pending: {
              lockPending: (digest: TokenDigest) =>
                Effect.gen(function* () {
                  const rows =
                    yield* sql`select ${pending.fields("pending_")} from ${pending.name} where ${exactSqlText(sql, pending.column(p.digest), pending.value(p.digest, digest))} ${lock(true)}`;

                  invariant(rows.length <= 1);
                  if (rows[0] === undefined) return undefined;
                  const row = pending.decode(rows[0], "pending_");
                  const record = yield* p.decode(row);

                  const flows =
                    yield* sql`select ${flow.fields("flow_")} from ${flow.name} where ${exactSqlText(sql, flow.column(f.flowId), flow.value(f.flowId, record.evidence.flowId))} ${lock(true)}`;

                  invariant(flows.length <= 1);

                  const stored =
                    flows[0] === undefined ? undefined : flow.decode(flows[0], "flow_");

                  return {
                    record,
                    failedAttempts: yield* Schema.decodeUnknownEffect(Schema.Int)(
                      row[p.failedAttempts],
                    ),
                    consumed: row[p.consumed] === true || row[p.consumed] === 1,
                    flow:
                      stored === undefined
                        ? undefined
                        : {
                            pending: stored[f.state] === f.pendingStateValue,
                            pendingDigest:
                              stored[f.pendingDigest] === null
                                ? undefined
                                : yield* Schema.decodeUnknownEffect(TokenDigest)(
                                    stored[f.pendingDigest],
                                  ),
                            dedupUntil: yield* f.decodeInstant(stored[f.dedupUntil]),
                          },
                  };
                }),
              consumePending: (
                input: Parameters<
                  NonNullable<SessionAuthorityStore<Claims>["pending"]>["consumePending"]
                >[0],
                dedupUntil: Parameters<
                  NonNullable<SessionAuthorityStore<Claims>["pending"]>["consumePending"]
                >[1],
              ) =>
                Effect.gen(function* () {
                  invariant(
                    (yield* executeSqlChange(
                      sql,
                      sql`${pending.update({ [p.consumed]: true })} where ${exactSqlText(sql, pending.column(p.digest), pending.value(p.digest, input.digest))} and ${exactSqlText(sql, pending.column(p.version), pending.value(p.version, input.version))} and ${pending.column(p.consumed)} = ${pending.value(p.consumed, false)}`,
                    )) === 1,
                  );
                  invariant(
                    (yield* executeSqlChange(
                      sql,
                      sql`${flow.update({ [f.state]: f.establishedStateValue, [f.pendingDigest]: null, [f.dedupUntil]: f.encodeInstant(dedupUntil) })} where ${exactSqlText(sql, flow.column(f.flowId), flow.value(f.flowId, input.flowId))} and ${exactSqlText(sql, flow.column(f.pendingDigest), flow.value(f.pendingDigest, input.digest))}`,
                    )) === 1,
                  );
                }),
            },
          };
        })()),
  };

  const marker = {};

  const owner: SessionTransactionOwner<SessionAuthorityStore<Claims>> = {
    read: store,
    isCurrent: Effect.serviceOption(CurrentSqlAuthority).pipe(
      Effect.map((value) => Option.isSome(value) && value.value === marker),
    ),
    transaction: (body) =>
      sql.withTransaction(body(store)).pipe(Effect.provideService(CurrentSqlAuthority, marker)),
  };

  const authenticationAuthority = yield* makeAuthenticationAuthorityWorkflow(
    mapping,
    {
      mode: "interactive",
      locking: dialect === "pg",
      standaloneGuard: requireStandalone(() => SessionUnavailable.make({}), sql.transactionService),
    },
    owner,
  );

  return { authenticationAuthority };
});
