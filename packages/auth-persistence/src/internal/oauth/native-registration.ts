import type { LifecycleHooks } from "@yielded/auth/Hooks";
import * as M from "@yielded/auth/OAuth";
import { Crypto, Effect, Option, Schema } from "effect";
import { SqlClient } from "effect/sql";
import type { Fragment } from "effect/sql/Statement";

import { sqlBatchAssertion } from "../d1-planning";
import type {
  OAuthRegistrationAuthority,
  OAuthRegistrationIntentMapping,
  OAuthRegistrationMapping,
} from "../models/oauth-model";
import type { NativeSqlTables } from "../native-sql-table";
import { conditionalSqlInsert } from "../session-native-record";
import { exactSqlText, executeSqlChange } from "../sql-change";
import { cleanupSqlRows } from "../sql-cleanup";
import {
  appendSqlBatchStatement,
  CurrentSqlCommit,
  makeSqlCommitExecutor,
  registerSqlBatchPostcondition,
  registerSqlPostcondition,
  SqlBatchCommit,
} from "../sql-commit";
import type { SqlExpression, TableModel } from "../table-model";
import { makeOAuthNativeMutation } from "./native-mutation";
import { prepareOAuthNative } from "./native-sign-in";
import { invariant, oauthIdentityKey, storage, unavailable } from "./state";

// Physical metadata is validated at the driver boundary.
export type OAuthNativeRegistrationIntentMapping = OAuthRegistrationIntentMapping<
  TableModel,
  TableModel,
  unknown,
  SqlExpression
>;

export type OAuthNativeRegistrationMapping<Registration> = OAuthRegistrationMapping<
  Registration,
  TableModel,
  TableModel,
  TableModel,
  TableModel,
  TableModel,
  unknown,
  SqlExpression
>;

const makeIntent = Effect.fnUntraced(function* (
  tables: NativeSqlTables,
  mapping: Pick<OAuthNativeRegistrationIntentMapping, "intent" | "clock" | "ownership">,
  batch: boolean,
) {
  const sql = (yield* SqlClient.SqlClient).withoutTransforms();
  const intent = tables(mapping.intent.table);
  const ownership = tables(mapping.ownership.table);
  const i = mapping.intent;
  const o = mapping.ownership;
  const stored = storage(M.OAuthRegistrationInspection);
  const intentStored = storage(M.OAuthRegistrationIntent);
  const now = tables.expression(mapping.clock.engineNowMillis);

  const exact = (key: string, value: unknown) =>
    exactSqlText(sql, intent.column(key), intent.value(key, value));

  const key = (moduleId: string, reference: string) =>
    sql.and([exact(i.moduleId, moduleId), exact(i.reference, reference)]);

  const horizon = (value: M.OAuthRegistrationIntent) =>
    sql`${now} >= ${value.issuedAtMillis} and ${now} < ${value.expiresAtMillis}`;

  const unowned = (identityKey: string) =>
    sql`not exists(select 1 from ${ownership.name} where ${exactSqlText(sql, ownership.column(o.identityKey), ownership.value(o.identityKey, identityKey))})`;

  const read = Effect.fnUntraced(function* (access: M.OAuthRegistrationAccess) {
    const rows =
      yield* sql`select ${intent.fields("intent_")}, ${now} as engine_now from ${intent.name} where ${key(access.moduleId, access.reference)}`;

    invariant(rows.length <= 1);
    if (rows[0] === undefined) return undefined;
    const row = intent.decode(rows[0], "intent_");
    const encoded = row[i.snapshot];

    invariant(typeof encoded === "string");
    const inspection = stored.decode(encoded);
    const value = inspection.intent;
    const context = value.context;
    const identityKey = yield* oauthIdentityKey(value.identity);

    invariant(
      row[i.moduleId] === context.moduleId &&
        row[i.reference] === value.reference &&
        row[i.flowId] === context.flowId &&
        row[i.identityKey] === identityKey &&
        mapping.clock.decodeInstant(row[i.expiresAt]) === value.expiresAtMillis &&
        mapping.clock.decodeInstant(row[i.retentionUntil]) === value.retentionUntilMillis,
    );
    const engineNow = yield* Schema.decodeEffect(Schema.Int)(Number(rows[0].engine_now));

    if (
      access.moduleId !== context.moduleId ||
      access.flowId !== context.flowId ||
      access.reference !== value.reference ||
      access.requestBindingVerifier !== context.requestBindingVerifier ||
      access.requestBindingExpiresAtMillis !== context.requestBindingExpiresAtMillis ||
      access.credentialDigest !== value.credentialDigest ||
      engineNow < value.issuedAtMillis ||
      engineNow >= value.expiresAtMillis
    )
      return undefined;

    return { inspection, encoded, identityKey, engineNow };
  });

  const finish = (name: string, condition: Fragment) =>
    batch
      ? registerSqlBatchPostcondition({ name, statement: sqlBatchAssertion(sql, condition) })
      : registerSqlPostcondition({
          name,
          check: Effect.gen(function* () {
            invariant((yield* sql`select 1 where ${condition}`).length === 1);
          }),
        });

  const change = Effect.fnUntraced(function* (statement: Fragment) {
    if (batch) {
      yield* appendSqlBatchStatement(sql`${statement}`);
      yield* appendSqlBatchStatement(sqlBatchAssertion(sql, sql`changes() = 1`));
    } else invariant((yield* executeSqlChange(sql, statement)) === 1);
  });

  const cleanup = (moduleId: string, limit: number) =>
    cleanupSqlRows(
      [
        {
          table: intent,
          keys: [i.moduleId, i.reference],
          due: sql`${exact(i.moduleId, moduleId)} and ${tables.expression(mapping.clock.toMillis(intent.column(i.retentionUntil)))} <= ${now}`,
          order: [intent.column(i.retentionUntil), intent.column(i.reference)],
        },
      ],
      limit,
      batch,
    );

  return {
    sql,
    now,
    intent,
    stored,
    intentStored,
    exact,
    key,
    horizon,
    unowned,
    read,
    finish,
    change,
    cleanup,
  };
});

export const makeNativeOAuthRegistrationIntentServices = Effect.fnUntraced(function* (
  tables: NativeSqlTables,
  mapping: OAuthNativeRegistrationIntentMapping,
  batch?: SqlBatchCommit["Service"],
): Effect.fn.Return<
  { readonly oauthRegistrationIntents: M.OAuthRegistrationIntents["Service"] },
  M.OAuthUnavailable,
  SqlClient.SqlClient | LifecycleHooks | Crypto.Crypto
> {
  const executor = yield* makeSqlCommitExecutor(unavailable);
  const crypto = yield* Crypto.Crypto;
  const external = yield* Effect.serviceOption(CurrentSqlCommit);
  const state = yield* makeIntent(tables, mapping, batch !== undefined);
  const { sql, intent, unowned, horizon, stored } = state;
  const i = mapping.intent;

  const run = <A, E, R>(effect: Effect.Effect<A, E, R>) => {
    const work = Effect.provideService(effect, Crypto.Crypto, crypto);

    return batch === undefined
      ? executor.run(work, "statement")
      : executor.batch(work).pipe(Effect.provideService(SqlBatchCommit, batch));
  };

  const service: M.OAuthRegistrationIntents["Service"] = {
    issue: (original, prepare) =>
      run(
        Effect.gen(function* () {
          const value = M.snapshotOAuthSync(M.OAuthRegistrationIntent, original.intent);
          const context = value.context;
          const rejected = () => prepareOAuthNative({ _tag: "Rejected" } as const, prepare);

          if (
            value.identity.provider !== context.provider ||
            value.identity.issuer !== context.issuer ||
            value.verifiedAtMillis < context.issuedAtMillis ||
            value.verifiedAtMillis > value.issuedAtMillis ||
            value.issuedAtMillis >= value.expiresAtMillis ||
            value.expiresAtMillis > context.requestBindingExpiresAtMillis ||
            value.retentionUntilMillis < value.expiresAtMillis
          )
            return yield* rejected();
          const identityKey = yield* oauthIdentityKey(value.identity);

          const eligible = sql.and([
            unowned(identityKey),
            horizon(value),
            tables.expression(mapping.eligible(value)),
          ]);

          const snapshot = stored.encode({ intent: value, application: { _tag: "Unbound" } });

          const values = {
            ...i.encodeInsert(value),
            [i.moduleId]: context.moduleId,
            [i.reference]: value.reference,
            [i.flowId]: context.flowId,
            [i.identityKey]: identityKey,
            [i.snapshot]: snapshot,
            [i.expiresAt]: mapping.clock.encodeInstant(value.expiresAtMillis),
            [i.retentionUntil]: mapping.clock.encodeInstant(value.retentionUntilMillis),
          };

          const statement = conditionalSqlInsert(sql, intent, values, eligible);

          if (batch !== undefined) yield* state.change(statement);
          else if ((yield* executeSqlChange(sql, statement)) !== 1) return yield* rejected();
          if (Option.isSome(external))
            yield* state.finish(
              "oauth-registration-intent-issued",
              sql.and([
                eligible,
                sql`exists(select 1 from ${intent.name} where ${state.key(context.moduleId, value.reference)} and ${state.exact(i.snapshot, snapshot)})`,
              ]),
            );

          return yield* prepareOAuthNative({ _tag: "RegistrationIssued", intent: value }, prepare);
        }),
      ),
  };

  return { oauthRegistrationIntents: service };
});

export const makeNativeOAuthRegistrationServices = Effect.fnUntraced(function* <Registration>(
  tables: NativeSqlTables,
  mapping: OAuthNativeRegistrationMapping<Registration>,
  batch?: SqlBatchCommit["Service"],
): Effect.fn.Return<
  { readonly registrationAuthority: OAuthRegistrationAuthority<Registration> },
  M.OAuthUnavailable,
  SqlClient.SqlClient | LifecycleHooks | Crypto.Crypto
> {
  const executor = yield* makeSqlCommitExecutor(unavailable);
  const crypto = yield* Crypto.Crypto;
  const external = yield* Effect.serviceOption(CurrentSqlCommit);
  const state = yield* makeIntent(tables, mapping, batch !== undefined);
  const mutation = yield* makeOAuthNativeMutation(tables, mapping, batch !== undefined);
  const { sql, now, intent, horizon, stored } = state;
  const i = mapping.intent;
  const c = mapping.credential;
  const a = mapping.authority;
  const s = mapping.subject;
  const credential = tables(c.table);
  const authority = tables(a.table);
  const subject = tables(s.table);
  const application = Schema.fromJsonString(mapping.registration);

  const run = <A, E, R>(
    effect: Effect.Effect<A, E, R>,
    mode: "transaction" | "statement" = "transaction",
  ) => {
    const work = Effect.provideService(effect, Crypto.Crypto, crypto);

    return batch === undefined
      ? executor.run(work, mode)
      : executor.batch(work).pipe(Effect.provideService(SqlBatchCommit, batch));
  };

  const read = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    executor.read(Effect.provideService(effect, Crypto.Crypto, crypto));

  const service: OAuthRegistrationAuthority<Registration> = {
    read: (access) =>
      read(
        Effect.map(
          state.read(M.snapshotOAuthSync(M.OAuthRegistrationAccess, access)),
          (value) => value?.inspection,
        ),
      ),
    inspect: (input) =>
      read(
        Effect.gen(function* () {
          const payload = yield* Schema.encodeEffect(application)(input.registration);

          invariant(new TextEncoder().encode(payload).length <= 1048576);
          const registration = yield* Schema.decodeEffect(application)(payload);

          const result = yield* mapping.inspect({
            intent: M.snapshotOAuthSync(M.OAuthRegistrationIntent, input.intent),
            registration,
          });

          return {
            ...result,
            fingerprint: yield* Schema.decodeEffect(M.OAuthRegistrationFingerprint)(
              result.fingerprint,
            ),
          };
        }),
      ),
    register: (original, prepare) =>
      read(
        Effect.gen(function* () {
          const access = M.snapshotOAuthSync(M.OAuthRegistrationAccess, original.access);
          const expected = M.snapshotOAuthSync(M.OAuthRegistrationIntent, original.intent);
          const found = yield* state.read(access);

          const decide = (decision: M.OAuthRegistrationDecision) =>
            run(prepareOAuthNative(decision, prepare), "statement");

          const rejected = () => prepareOAuthNative({ _tag: "Rejected" } as const, prepare);

          if (
            found === undefined ||
            state.intentStored.encode(found.inspection.intent) !==
              state.intentStored.encode(expected)
          )
            return decide({ _tag: "Rejected" });

          const binding = M.snapshotOAuthSync(M.OAuthRegistrationInspection, {
            intent: expected,
            application: {
              _tag: "Registered",
              commandId: original.commandId,
              fingerprint: original.fingerprint,
              payload: original.payload,
              requestId: original.requestId,
            },
          }).application;

          invariant(binding._tag === "Registered");
          // Replay comparison precedes application callbacks, allocation and writes.
          const previous = found.inspection.application;

          if (previous._tag !== "Unbound") {
            if (
              previous.commandId !== binding.commandId ||
              previous.fingerprint !== binding.fingerprint ||
              previous.payload !== binding.payload ||
              previous.requestId !== binding.requestId
            )
              return decide({ _tag: "Conflict" });

            return decide(
              previous._tag === "Registered"
                ? { _tag: "Registered", replayed: true }
                : { _tag: "Rejected" },
            );
          }

          return run(
            Effect.gen(function* () {
              invariant(new TextEncoder().encode(binding.payload).length <= 1048576);
              const registration = yield* Schema.decodeEffect(application)(binding.payload);

              invariant(
                (yield* Schema.encodeEffect(application)(registration)) === binding.payload,
              );
              if (
                (yield* Schema.encodeEffect(application)(original.registration)) !== binding.payload
              )
                return yield* rejected();
              const inspection = yield* mapping.inspect({ intent: expected, registration });

              if (inspection.fingerprint !== binding.fingerprint) return yield* rejected();
              const policyInput = { intent: expected, registration };

              const eligible = sql.and([
                state.unowned(found.identityKey),
                tables.expression(mapping.eligibility.admission(policyInput)),
                horizon(expected),
              ]);

              let admitted =
                inspection.eligible &&
                (batch === undefined || (yield* sql`select 1 where ${eligible}`).length === 1);

              let final: Fragment = horizon(expected);

              if (admitted) {
                const nativeId = yield* mapping.allocateSubjectId;
                const subjectId = yield* mapping.subjectId.toSubject(nativeId);

                invariant(
                  mapping.subjectId.equals(nativeId, yield* mapping.subjectId.toNative(subjectId)),
                );

                const credentialId = yield* Schema.decodeEffect(
                  M.OAuthCredentialSnapshot.fields.credentialId,
                )(yield* mapping.allocateCredentialId);

                const revision = yield* Schema.decodeEffect(
                  M.OAuthCredentialSnapshot.fields.credentialRevision,
                )(yield* mapping.allocateRevision);

                const subjectValues = {
                  ...mapping.encodeSubjectInsert(
                    { ...policyInput, requestId: binding.requestId },
                    { subjectId: nativeId, securityRevision: revision },
                  ),
                  [s.id]: nativeId,
                  [s.securityRevision]: revision,
                };

                invariant(s.isActiveStatus(subjectValues[s.status]));
                // A newly inserted subject is the first lock. The exact unbound intent
                // CAS below arbitrates concurrent registration; a loser rolls back all
                // local rows and never repeats provisioning automatically.
                const creation = conditionalSqlInsert(sql, subject, subjectValues, eligible);

                if (batch !== undefined) yield* state.change(creation);
                else admitted = (yield* executeSqlChange(sql, creation)) === 1;
                if (admitted) {
                  const policy = { ...policyInput, nativeSubjectId: nativeId };

                  invariant((mapping.eligibility.guards?.length ?? 0) <= 32);
                  for (const guard of mapping.eligibility.guards ?? []) {
                    const table = tables(guard.table);

                    const rows =
                      yield* sql`select ${table.column(guard.orderBy)} from ${table.name} where ${tables.expression(guard.condition(policy))} order by ${table.column(guard.orderBy)} limit 65 ${batch === undefined ? sql.onDialectOrElse({ sqlite: () => sql``, orElse: () => sql`for update` }) : sql``}`;

                    invariant(rows.length > 0 && rows.length <= 64);
                  }

                  invariant(
                    (yield* mutation.ensureOwnership(expected.identity, nativeId)) ===
                      found.identityKey,
                  );

                  const values = {
                    ...c.encodeInsert({
                      moduleId: expected.context.moduleId,
                      subjectId: nativeId,
                      identityKey: found.identityKey,
                      credentialId,
                      credentialRevision: revision,
                    }),
                    [c.moduleId]: expected.context.moduleId,
                    [c.subjectId]: nativeId,
                    [c.identityKey]: found.identityKey,
                    [c.credentialId]: credentialId,
                    [c.credentialRevision]: revision,
                  };

                  invariant(c.isActiveStatus(values[c.status]));
                  yield* state.change(
                    conditionalSqlInsert(
                      sql,
                      credential,
                      values,
                      sql.and([
                        tables.expression(mapping.eligibility.admission(policy)),
                        horizon(expected),
                        sql`exists(select 1 from ${mutation.ownership.name} where ${mutation.ownerCondition(found.identityKey, nativeId)})`,
                      ]),
                    ),
                  );

                  const factor = {
                    ...a.encodeInsert({ subjectId: nativeId, credentialId, revision }),
                    [a.subjectId]: nativeId,
                    [a.credentialId]: credentialId,
                    [a.revision]: revision,
                  };

                  invariant(a.isActiveStatus(factor[a.status]));
                  yield* state.change(authority.insert(factor));
                  final = sql.and([
                    horizon(expected),
                    tables.expression(mapping.eligibility.postcondition(policy)),
                    mutation.authorityCondition(nativeId, {
                      subjectId,
                      securityRevision: revision,
                      credentials: [{ credentialId, revision }],
                    }),
                    sql`exists(select 1 from ${credential.name} where ${credential.column(c.subjectId)} = ${credential.value(c.subjectId, nativeId)} and ${exactSqlText(sql, credential.column(c.credentialId), credential.value(c.credentialId, credentialId))} and ${exactSqlText(sql, credential.column(c.credentialRevision), credential.value(c.credentialRevision, revision))} and ${exactSqlText(sql, credential.column(c.identityKey), credential.value(c.identityKey, found.identityKey))} and ${tables.expression(c.activeCondition)})`,
                    sql`exists(select 1 from ${mutation.ownership.name} where ${mutation.ownerCondition(found.identityKey, nativeId)})`,
                  ]);
                }
              }

              const snapshot = stored.encode({
                intent: expected,
                application: { ...binding, _tag: admitted ? "Registered" : "Rejected" },
              });

              yield* state.change(
                sql`${intent.update({ [i.snapshot]: snapshot })} where ${state.key(access.moduleId, access.reference)} and ${state.exact(i.snapshot, found.encoded)} and ${final}`,
              );
              if (Option.isSome(external))
                yield* state.finish(
                  "oauth-registration-outcome",
                  sql.and([
                    final,
                    sql`exists(select 1 from ${intent.name} where ${state.key(access.moduleId, access.reference)} and ${state.exact(i.snapshot, snapshot)})`,
                    sql`${now} < ${expected.expiresAtMillis}`,
                  ]),
                );

              return yield* prepareOAuthNative(
                admitted ? { _tag: "Registered", replayed: false } : { _tag: "Rejected" },
                prepare,
              );
            }),
          );
        }),
      ).pipe(Effect.flatten),
    cleanup: (input, prepare) =>
      run(
        Effect.gen(function* () {
          const parsed = M.snapshotOAuthSync(M.OAuthCleanupInput, input);

          return yield* prepareOAuthNative(
            yield* state.cleanup(parsed.moduleId, parsed.limit),
            prepare,
          );
        }),
      ),
  };

  return { registrationAuthority: service };
});
