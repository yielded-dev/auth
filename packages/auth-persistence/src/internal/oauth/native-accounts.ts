import type { LifecycleHooks } from "@yielded/auth/Hooks";
import * as M from "@yielded/auth/OAuth";
import { SessionInvalidationWindow } from "@yielded/auth/Sessions";
import { Crypto, Effect, Schema } from "effect";
import type { SqlClient } from "effect/sql/SqlClient";
import type { Fragment } from "effect/sql/Statement";

import { type OAuthAccountsMapping, OAuthEligibilityFact } from "../models/oauth-model";
import type { NativeSqlTables } from "../native-sql-table";
import { exactSqlText } from "../sql-change";
import { makeSqlCommitExecutor, SqlBatchCommit } from "../sql-commit";
import type { SqlExpression, TableModel } from "../table-model";
import { makeOAuthNativeFlow } from "./native-flow";
import { makeOAuthNativeMutation } from "./native-mutation";
import { prepareOAuthNative } from "./native-sign-in";
import { makeOAuthNativeState } from "./native-state";
import {
  invariant,
  oauthIdentityKey,
  sameRevision,
  satisfies,
  unavailable,
  validAction,
} from "./state";

// Physical metadata is validated by the adapter; schema values remain typed.
export type OAuthNativeAccountsMapping = OAuthAccountsMapping<
  TableModel,
  TableModel,
  TableModel,
  TableModel,
  TableModel,
  unknown,
  SqlExpression
>;

export const makeNativeOAuthAccountsServices = Effect.fnUntraced(function* (
  tables: NativeSqlTables,
  mapping: OAuthNativeAccountsMapping,
  batch?: SqlBatchCommit["Service"],
): Effect.fn.Return<
  { readonly oauthAccountsPersistence: M.OAuthAccountsPersistence["Service"] },
  M.OAuthUnavailable,
  SqlClient | LifecycleHooks | Crypto.Crypto
> {
  const executor = yield* makeSqlCommitExecutor(unavailable);
  const crypto = yield* Crypto.Crypto;
  const state = yield* makeOAuthNativeState(tables, mapping);
  const mutation = yield* makeOAuthNativeMutation(tables, mapping, batch !== undefined);

  const flow = yield* makeOAuthNativeFlow(
    tables,
    mapping,
    M.OAuthLinkFlow,
    "link",
    (value) => value.context.revision.subjectId,
    batch !== undefined,
  );

  const { sql, now, credential, authority } = state;

  const any = (conditions: ReadonlyArray<Fragment>) =>
    conditions.length === 0 ? sql`1 = 0` : sql.or(conditions);

  const c = mapping.credential;
  const a = mapping.authority;

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

  const credentialCondition = (nativeId: unknown, key: string, id: string, revision: unknown) =>
    sql.and([
      sql`${credential.column(c.subjectId)} = ${credential.value(c.subjectId, nativeId)}`,
      exactSqlText(sql, credential.column(c.identityKey), credential.value(c.identityKey, key)),
      exactSqlText(sql, credential.column(c.credentialId), credential.value(c.credentialId, id)),
      exactSqlText(
        sql,
        credential.column(c.credentialRevision),
        credential.value(c.credentialRevision, revision),
      ),
      tables.expression(c.activeCondition),
    ]);

  const service: M.OAuthAccountsPersistence["Service"] = {
    capture: (input) =>
      read(Effect.map(state.capture(input.subjectId, false), (current) => current?.revision)),
    issue: (original, prepare) =>
      run(
        Effect.gen(function* () {
          const input = M.snapshotOAuthSync(M.OAuthLinkFlow, original);
          // Flow issue has no protected authority mutation; completion owns the one
          // subject-first recheck of this authenticated begin authorization.
          const issued = yield* flow.issue(input);

          return yield* prepareOAuthNative(
            issued ? { _tag: "Issued", flow: input } : { _tag: "Rejected" },
            prepare,
          );
        }),
        flow.mysql ? "transaction" : "statement",
      ),
    consume: (original, prepare) =>
      run(
        Effect.gen(function* () {
          const input = M.snapshotOAuthSync(M.OAuthLinkAccess, original);
          const consumed = yield* flow.consume(input);

          return yield* prepareOAuthNative(
            consumed === undefined ? { _tag: "Rejected" } : { _tag: "Consumed", flow: consumed },
            prepare,
          );
        }),
        flow.mysql ? "transaction" : "statement",
      ),
    link: (original, prepare) =>
      run(
        Effect.gen(function* () {
          const flow = M.snapshotOAuthSync(M.OAuthLinkFlow, original.flow);
          const verified = M.snapshotOAuthSync(M.OAuthVerifiedExternalIdentity, original.identity);
          const context = flow.context;
          const current = yield* mutation.capture(context.revision.subjectId, batch === undefined);
          const rejected = () => prepareOAuthNative({ _tag: "Rejected" } as const, prepare);

          if (
            current === undefined ||
            !sameRevision(context.revision, current.revision) ||
            context.provider !== verified.identity.provider ||
            context.issuer !== verified.identity.issuer ||
            current.now >= context.expiresAtMillis
          )
            return yield* rejected();

          const intent = yield* Schema.encodeEffect(
            Schema.fromJsonString(M.OAuthLinkIntentContext),
          )(context);

          if (
            !(yield* validAction(
              context.authorization,
              {
                moduleId: context.moduleId,
                action: "link-begin",
                flowId: context.flowId,
                revision: context.revision,
                intent,
              },
              mapping.subject.decodeActionRequirement(current.subject, "link-begin"),
              current.now,
              context.maximumEvidenceAgeMillis,
            ))
          )
            return yield* rejected();

          const deadline = Math.min(
            context.expiresAtMillis,
            context.authorization.validUntilMillis,
          );

          const before = sql.and([
            mutation.authorityCondition(current.nativeId, current.revision),
            sql`${now} < ${deadline}`,
          ]);

          if (batch !== undefined) yield* mutation.assert(before);
          const identityKey = yield* mutation.ensureOwnership(verified.identity, current.nativeId);

          if (identityKey === undefined)
            return yield* prepareOAuthNative({ _tag: "Conflict" }, prepare);

          const existing = yield* sql`select ${credential.fields("login_")} from ${credential.name}
        where ${exactSqlText(sql, credential.column(c.identityKey), credential.value(c.identityKey, identityKey))}`;

          invariant(existing.length <= 1);
          let credentialId: string;
          let credentialRevision: M.OAuthCredentialSnapshot["credentialRevision"];
          let revision = current.revision;

          if (existing[0] !== undefined) {
            const row = credential.decode(existing[0], "login_");

            if (
              !mapping.subjectId.equals(row[c.subjectId], current.nativeId) ||
              row[c.moduleId] !== context.moduleId ||
              !c.isActiveStatus(row[c.status])
            )
              return yield* rejected();
            credentialId = yield* Schema.decodeUnknownEffect(
              M.OAuthCredentialSnapshot.fields.credentialId,
            )(row[c.credentialId]);
            credentialRevision = yield* Schema.decodeUnknownEffect(
              M.OAuthCredentialSnapshot.fields.credentialRevision,
            )(row[c.credentialRevision]);
            if (
              !revision.credentials.some(
                (entry) =>
                  entry.credentialId === credentialId && entry.revision === credentialRevision,
              )
            )
              return yield* rejected();
          } else {
            credentialId = yield* mapping.allocateCredentialId;
            credentialRevision = yield* mapping.allocateRevision;
            invariant(
              (yield* mutation.change(
                credential.insert({
                  ...c.encodeInsert({
                    moduleId: context.moduleId,
                    subjectId: current.nativeId,
                    identityKey,
                    credentialId,
                    credentialRevision,
                  }),
                  [c.moduleId]: context.moduleId,
                  [c.subjectId]: current.nativeId,
                  [c.identityKey]: identityKey,
                  [c.credentialId]: credentialId,
                  [c.credentialRevision]: credentialRevision,
                }),
              )) === 1,
            );
            invariant(
              (yield* mutation.change(
                authority.insert({
                  ...a.encodeInsert({
                    subjectId: current.nativeId,
                    credentialId,
                    revision: credentialRevision,
                  }),
                  [a.subjectId]: current.nativeId,
                  [a.credentialId]: credentialId,
                  [a.revision]: credentialRevision,
                }),
              )) === 1,
            );
            revision = {
              ...current.revision,
              credentials: [
                ...current.revision.credentials,
                { credentialId, revision: credentialRevision },
              ].sort((left, right) => left.credentialId.localeCompare(right.credentialId)),
            };
          }
          yield* mutation.finish(
            "oauth-link-authority",
            sql.and([
              mutation.authorityCondition(current.nativeId, revision),
              sql`${now} < ${deadline}`,
              sql`exists(select 1 from ${credential.name} where ${credentialCondition(current.nativeId, identityKey, credentialId, credentialRevision)})`,
              sql`exists(select 1 from ${mutation.ownership.name} where ${mutation.ownerCondition(identityKey, current.nativeId)})`,
            ]),
          );

          const captured = yield* Schema.decodeEffect(Schema.toType(M.OAuthCredentialSnapshot))({
            moduleId: context.moduleId,
            identity: verified.identity,
            credentialId,
            credentialRevision,
            revision,
          });

          return yield* prepareOAuthNative(
            { _tag: "Linked", credential: captured, changed: existing.length === 0 },
            prepare,
          );
        }),
      ),
    readCredential: (original) =>
      read(
        Effect.suspend(() =>
          state.readCredential(M.snapshotOAuthSync(M.OAuthCredentialKey, original)),
        ),
      ),
    unlink: (original, prepare) =>
      run(
        Effect.gen(function* () {
          const captured = M.snapshotOAuthSync(M.OAuthCredentialSnapshot, original.credential);

          const authorization = M.snapshotOAuthSync(
            M.OAuthActionAuthorization,
            original.authorization,
          );

          const invalidation = M.snapshotOAuthSync(
            SessionInvalidationWindow,
            original.invalidation,
          );

          invariant(
            invalidation.trigger === "credential-change" &&
              invalidation.oldAuthenticationEvidence === "rejected" &&
              (mapping.sessionInvalidation === "same-authority-immediate"
                ? (invalidation.existingSessions === "immediate" &&
                    invalidation.maximumExposureMillis === 0) ||
                  (invalidation.existingSessions === "cache-expiry" &&
                    invalidation.maximumExposureMillis > 0)
                : invalidation.existingSessions === "original-absolute-expiry"),
          );
          const current = yield* mutation.capture(captured.revision.subjectId, batch === undefined);
          const rejected = () => prepareOAuthNative({ _tag: "Rejected" } as const, prepare);

          if (current === undefined || !sameRevision(current.revision, captured.revision))
            return yield* rejected();

          const intent = yield* Schema.encodeEffect(
            Schema.fromJsonString(M.OAuthCredentialSnapshot),
          )(captured);

          if (
            !(yield* validAction(
              authorization,
              {
                moduleId: captured.moduleId,
                action: "unlink",
                flowId: authorization.challenge.flowId,
                revision: captured.revision,
                intent,
              },
              mapping.subject.decodeActionRequirement(current.subject, "unlink"),
              current.now,
              authorization.requirement.maximumAgeMillis,
            ))
          )
            return yield* rejected();
          const key = yield* oauthIdentityKey(captured.identity);

          const target = credentialCondition(
            current.nativeId,
            key,
            captured.credentialId,
            captured.credentialRevision,
          );

          const rows =
            yield* sql`select ${credential.fields("target_")} from ${credential.name} where ${target}`;

          if (rows.length !== 1) return yield* rejected();

          const eligible = new Map<
            string,
            { readonly fact: OAuthEligibilityFact; readonly conditions: Array<Fragment> }
          >();

          invariant(mapping.eligibility.length <= 32);

          const sources = mapping.eligibility.map((source) => ({
            source,
            table: tables(source.table),
          }));

          // Each branch owns distinct projection columns. Empty scalar subqueries
          // retain each physical SQL type across derived SELECT and UNION coercion.
          invariant(sources.reduce((count, entry) => count + entry.table.keys.length, 0) <= 1024);

          const branches = sources.map(({ source, table }, branch) => {
            const fields = sources.flatMap((entry, index) =>
              entry.table.keys.map(
                (key, ordinal) =>
                  sql`${index === branch ? table.selectedColumn(key) : sql`(select ${entry.table.selectedColumn(key)} from ${entry.table.name} where 1 = 0)`} as ${sql(`method_${index}_${ordinal}`)}`,
              ),
            );

            return sql`select * from (select ${branch} as method_branch, ${sql.join(", ", false)(fields)} from ${table.name}
              where ${table.column(source.subjectId)} = ${table.value(source.subjectId, current.nativeId)} and ${tables.expression(source.condition(current.nativeId))}
              order by ${table.column(source.credentialId)} limit 65) as ${sql(`eligible_${branch}`)}`;
          });

          const candidates =
            branches.length === 0 ? [] : yield* sql`${sql.join(" union all ", false)(branches)}`;

          const counts = new Map<number, number>();

          for (const row of candidates) {
            const branch = yield* Schema.decodeEffect(Schema.Int)(Number(row.method_branch));
            const entry = sources[branch];

            invariant(entry !== undefined);
            const count = (counts.get(branch) ?? 0) + 1;

            invariant(count <= 64);
            counts.set(branch, count);
            const { source, table } = entry;
            const decoded = source.decode(table.decode(row, `method_${branch}_`));

            if (decoded === undefined) continue;
            const parsed = yield* Schema.decodeEffect(OAuthEligibilityFact)(decoded);
            const fact = { ...parsed, factors: [...new Set(parsed.factors)].sort() };

            if (
              fact.credentialId !== captured.credentialId &&
              current.revision.credentials.some(
                (item) =>
                  item.credentialId === fact.credentialId && item.revision === fact.revision,
              )
            ) {
              const condition = sql`exists(select 1 from ${table.name} where
                  ${table.column(source.subjectId)} = ${table.value(source.subjectId, current.nativeId)}
                  and ${exactSqlText(sql, table.column(source.credentialId), table.value(source.credentialId, fact.credentialId))}
                  and ${exactSqlText(sql, table.column(source.revision), table.value(source.revision, fact.revision))}
                  and ${tables.expression(source.condition(current.nativeId))})`;

              const previous = eligible.get(fact.credentialId);

              if (previous === undefined)
                eligible.set(fact.credentialId, { fact, conditions: [condition] });
              else {
                const encode = Schema.encodeEffect(
                  Schema.fromJsonString(Schema.toCodecJson(OAuthEligibilityFact)),
                );

                invariant((yield* encode(previous.fact)) === (yield* encode(fact)));
                previous.conditions.push(condition);
              }
            }
          }
          const methods = [...eligible.values()];
          const facts = methods.map((entry) => entry.fact);
          const requirement = mapping.subject.decodeAuthenticationRequirement(current.subject);

          if (!facts.some((fact) => fact.usablePrimary) || !satisfies(facts, requirement))
            return yield* prepareOAuthNative({ _tag: "LastSignInMethod" }, prepare);
          const present = (entry: (typeof methods)[number]) => any(entry.conditions);

          // Preserve a usable remaining method through application work. These
          // predicates describe eligible credential identities, not observed rows.
          const remaining = sql.and([
            any(methods.filter((entry) => entry.fact.usablePrimary).map(present)),
            any(
              requirement.alternatives.map((alternative) =>
                sql.and([
                  ...alternative.factors.map((factor) =>
                    any(
                      methods.filter((entry) => entry.fact.factors.includes(factor)).map(present),
                    ),
                  ),
                  sql`(${sql.join(" + ", false)(methods.map((entry) => sql`case when ${present(entry)} then 1 else 0 end`))}) >= ${alternative.minimumCredentials}`,
                  any(
                    methods
                      .filter(
                        (entry) =>
                          (!alternative.userVerified || entry.fact.userVerified) &&
                          (!alternative.phishingResistant || entry.fact.phishingResistant),
                      )
                      .map(present),
                  ),
                ]),
              ),
            ),
          ]);

          const required = sql.and([
            mutation.subjectCondition(current.nativeId, current.revision),
            mutation.factorCondition(current.nativeId, current.revision),
            sql`${now} < ${authorization.validUntilMillis}`,
            remaining,
          ]);

          if (batch !== undefined)
            yield* mutation.assert(
              sql.and([
                mutation.authorityCondition(current.nativeId, current.revision),
                sql`${now} < ${authorization.validUntilMillis}`,
                remaining,
              ]),
            );

          const nextSecurityRevision = mapping.subject.nextSecurityRevision(
            current.revision.securityRevision,
          );

          invariant(nextSecurityRevision !== current.revision.securityRevision);
          const subject = mutation.subject;

          invariant(
            (yield* mutation.change(sql`${subject.update({ [mapping.subject.securityRevision]: nextSecurityRevision })}
        where ${subject.column(mapping.subject.id)} = ${subject.value(mapping.subject.id, current.nativeId)} and ${required}`)) ===
              1,
          );
          invariant(
            (yield* mutation.change(sql`delete from ${credential.name} where ${target}`)) === 1,
          );
          invariant(
            (yield* mutation.change(sql`delete from ${authority.name}
        where ${authority.column(a.subjectId)} = ${authority.value(a.subjectId, current.nativeId)}
          and ${exactSqlText(sql, authority.column(a.credentialId), authority.value(a.credentialId, captured.credentialId))}
          and ${exactSqlText(sql, authority.column(a.revision), authority.value(a.revision, captured.credentialRevision))}`)) ===
              1,
          );

          const cleanup = {
            subjectId: current.nativeId,
            revision: current.revision,
            removedCredentialId: captured.credentialId,
          };

          invariant(mapping.cleanup.length <= 32);
          const absent = [];

          for (const source of mapping.cleanup) {
            const table = tables(source.table);

            const condition = sql.and([
              sql`${table.column(source.subjectId)} = ${table.value(source.subjectId, current.nativeId)}`,
              tables.expression(source.condition(cleanup)),
            ]);

            const deletion = sql`delete from ${table.name} where ${condition}`;

            // Deleting zero or many subject-scoped session/pending rows is valid.
            absent.push(sql`not exists(select 1 from ${table.name} where ${condition})`);
            yield* mutation.execute(deletion);
          }

          const referenced = sql.or([
            sql`exists(select 1 from ${credential.name} where ${exactSqlText(sql, credential.column(c.identityKey), credential.value(c.identityKey, key))})`,
            tables.expression(
              mapping.otherReferences({ identityKey: key, subjectId: current.nativeId }),
            ),
          ]);

          yield* mutation.releaseOwnership(key, current.nativeId, referenced);

          const revision = {
            ...current.revision,
            securityRevision: nextSecurityRevision,
            credentials: current.revision.credentials.filter(
              (item) => item.credentialId !== captured.credentialId,
            ),
          };

          yield* mutation.finish(
            "oauth-unlink-authority",
            sql.and([
              mutation.authorityCondition(current.nativeId, revision),
              sql`${now} < ${authorization.validUntilMillis}`,
              remaining,
              sql`not exists(select 1 from ${credential.name} where ${target})`,
              ...absent,
            ]),
          );

          return yield* prepareOAuthNative(
            {
              _tag: "Unlinked",
              result: { _tag: "Unlinked", credentialId: captured.credentialId, invalidation },
            },
            prepare,
          );
        }),
      ),
    cleanup: (original, prepare) =>
      run(
        Effect.gen(function* () {
          const input = M.snapshotOAuthSync(M.OAuthCleanupInput, original);

          return yield* prepareOAuthNative(
            yield* flow.cleanup(input.moduleId, input.limit),
            prepare,
          );
        }),
        "statement",
      ),
  };

  return { oauthAccountsPersistence: service };
});
