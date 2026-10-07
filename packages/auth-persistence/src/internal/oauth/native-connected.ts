import type { LifecycleHooks } from "@yielded/auth/Hooks";
import * as M from "@yielded/auth/OAuth";
import { Crypto, Effect, Schema } from "effect";
import * as Base64Url from "effect/encoding/Base64Url";
import type { SqlClient } from "effect/sql/SqlClient";
import type { Fragment } from "effect/sql/Statement";

import type { NativeSqlTables } from "../native-sql-table";
import { exactSqlText } from "../sql-change";
import { makeSqlCommitExecutor, SqlBatchCommit } from "../sql-commit";
import {
  connectedSummary,
  makeOAuthNativeConnectedState,
  type OAuthNativeConnectedMapping,
  validConnectedMetadata,
} from "./native-connected-state";
import { makeOAuthNativeFlow } from "./native-flow";
import { prepareOAuthNative } from "./native-sign-in";
import {
  invariant,
  oauthIdentityKey,
  sameIdentity,
  sameRevision,
  storage,
  unavailable,
  validAction,
} from "./state";

export const makeNativeOAuthConnectedServices = Effect.fnUntraced(function* (
  tables: NativeSqlTables,
  mapping: OAuthNativeConnectedMapping,
  batch?: SqlBatchCommit["Service"],
): Effect.fn.Return<
  { readonly oauthConnectedPersistence: M.OAuthConnectedPersistence["Service"] },
  M.OAuthUnavailable,
  SqlClient | LifecycleHooks | Crypto.Crypto
> {
  const executor = yield* makeSqlCommitExecutor(unavailable);
  const crypto = yield* Crypto.Crypto;
  const state = yield* makeOAuthNativeConnectedState(tables, mapping, batch !== undefined);

  const flow = yield* makeOAuthNativeFlow(
    tables,
    mapping,
    M.OAuthConnectedFlow,
    "connect",
    (value) => value.context.revision.subjectId,
    batch !== undefined,
  );

  const { sql, now, grant } = state;
  const g = mapping.grant;

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

  const sameConfiguration = (
    left: M.OAuthConnectedConfiguration,
    right: M.OAuthConnectedConfiguration,
  ) =>
    storage(M.OAuthConnectedConfiguration).encode(left) ===
    storage(M.OAuthConnectedConfiguration).encode(right);

  const policy = (input: Parameters<typeof mapping.policy.condition>[0]) =>
    tables.expression(mapping.policy.condition(input));

  const present = (
    key: M.OAuthConnectedGrantKey,
    nativeId: unknown,
    encoded: string,
    extra?: Fragment,
  ) =>
    sql`exists(select 1 from ${grant.name} where ${state.key(key, nativeId)} and ${state.exact(g.snapshot, encoded)} ${extra === undefined ? sql`` : sql`and ${extra}`})`;

  const referenced = (identityKey: string, nativeId: unknown) =>
    sql.or([
      sql`exists(select 1 from ${grant.name} where ${state.exact(g.identityKey, identityKey)} and ${grant.column(g.subjectId)} = ${grant.value(g.subjectId, nativeId)})`,
      ...(mapping.revocation.mode === "provider"
        ? (() => {
            const j = mapping.revocation.job;
            const job = tables(j.table);

            return [
              sql`exists(select 1 from ${job.name} where ${exactSqlText(sql, job.column(j.identityKey), job.value(j.identityKey, identityKey))} and ${job.column(j.subjectId)} = ${job.value(j.subjectId, nativeId)})`,
            ];
          })()
        : []),
      tables.expression(mapping.otherReferences({ identityKey, subjectId: nativeId })),
    ]);

  const service: M.OAuthConnectedPersistence["Service"] = {
    read: (input) =>
      read(
        Effect.suspend(() =>
          state.readJoined(M.snapshotOAuthSync(M.OAuthConnectedReadInput, input)),
        ),
      ),
    issue: (input, prepare) =>
      run(
        Effect.gen(function* () {
          const value = M.snapshotOAuthSync(M.OAuthConnectedFlow, input);

          return yield* prepareOAuthNative(
            (yield* flow.issue(value)) ? { _tag: "Issued", flow: value } : { _tag: "Rejected" },
            prepare,
          );
        }),
        flow.mysql ? "transaction" : "statement",
      ),
    consume: (input, prepare) =>
      run(
        Effect.gen(function* () {
          const consumed = yield* flow.consume(M.snapshotOAuthSync(M.OAuthConnectedAccess, input));

          return yield* prepareOAuthNative(
            consumed === undefined ? { _tag: "Rejected" } : { _tag: "Consumed", flow: consumed },
            prepare,
          );
        }),
        flow.mysql ? "transaction" : "statement",
      ),
    settle: (original, prepare) =>
      run(
        Effect.gen(function* () {
          const input = M.snapshotOAuthSync(M.OAuthConnectedSettlement, original);
          const token = input.grant.context;
          const current = yield* state.capture(token.subjectId, batch === undefined);
          const rejected = () => prepareOAuthNative({ _tag: "Rejected" } as const, prepare);

          if (
            current === undefined ||
            !validConnectedMetadata(token, current.now) ||
            current.now >= token.metadata.useUntilMillis
          )
            return yield* rejected();
          const context = input.flow.context;

          if (
            token.moduleId !== context.moduleId ||
            token.identity.provider !== context.provider ||
            token.identity.issuer !== context.issuer ||
            current.now >= context.expiresAtMillis ||
            token.metadata.obtainedAtMillis < context.issuedAtMillis
          )
            return yield* rejected();
          let authorization: Fragment;
          let previous: M.OAuthConnectedTarget | undefined;
          let deadline = Math.min(context.expiresAtMillis, token.metadata.useUntilMillis);

          if (input._tag === "Connect") {
            const c = input.flow.context;

            if (
              !sameRevision(current.revision, c.revision) ||
              token.grantId !== c.grantId ||
              !sameConfiguration(
                token.configuration,
                M.snapshotOAuthSync(M.OAuthConnectedConfiguration, c),
              )
            )
              return yield* rejected();
            if (
              !(yield* validAction(
                input.authorization,
                {
                  moduleId: c.moduleId,
                  action: "connected-complete",
                  flowId: c.flowId,
                  revision: c.revision,
                  intent: yield* Schema.encodeEffect(
                    Schema.fromJsonString(M.OAuthConnectedTransactionContext),
                  )(c),
                },
                mapping.subject.decodeActionRequirement(current.subject, "connected-complete"),
                current.now,
                c.maximumEvidenceAgeMillis,
              ))
            )
              return yield* rejected();
            deadline = Math.min(deadline, input.authorization.validUntilMillis);
            authorization = policy({
              subjectId: current.nativeId,
              revision: current.revision,
              kind: "action",
              operation: "settle",
              authorization: input.authorization,
              grant: token,
            });
            previous = c.reconnect;
          } else {
            if (
              mapping.credential === undefined ||
              !sameRevision(current.revision, input.credential.revision) ||
              input.credential.moduleId !== token.moduleId ||
              !sameIdentity(input.credential.identity, token.identity)
            )
              return yield* rejected();
            const c = mapping.credential;
            const credential = tables(c.table);
            const identityKey = yield* oauthIdentityKey(token.identity);

            authorization = sql.and([
              policy({
                subjectId: current.nativeId,
                revision: current.revision,
                kind: "sign-in",
                credential: input.credential,
                grant: token,
              }),
              sql`exists(select 1 from ${credential.name} where ${credential.column(c.subjectId)} = ${credential.value(c.subjectId, current.nativeId)} and ${exactSqlText(sql, credential.column(c.moduleId), credential.value(c.moduleId, token.moduleId))} and ${exactSqlText(sql, credential.column(c.identityKey), credential.value(c.identityKey, identityKey))} and ${exactSqlText(sql, credential.column(c.credentialId), credential.value(c.credentialId, input.credential.credentialId))} and ${exactSqlText(sql, credential.column(c.credentialRevision), credential.value(c.credentialRevision, input.credential.credentialRevision))} and ${tables.expression(c.activeCondition)})`,
            ]);
            previous = input.previous;
            const profile = context.access;

            if (
              profile === undefined ||
              !sameConfiguration(
                token.configuration,
                M.snapshotOAuthSync(M.OAuthConnectedConfiguration, { ...context, profile }),
              )
            )
              return yield* rejected();
          }

          const required = sql.and([
            state.authorityCondition(current.nativeId, current.revision),
            authorization,
            sql`${now} < ${deadline}`,
          ]);

          if ((yield* sql`select 1 where ${required}`).length !== 1) return yield* rejected();

          const key = {
            moduleId: token.moduleId,
            subjectId: token.subjectId,
            grantId: token.grantId,
          };

          const old = yield* state.readGrant(key, current.nativeId, batch === undefined);

          if (
            previous === undefined
              ? old !== undefined
              : old === undefined ||
                previous.grantId !== token.grantId ||
                old.value.context.grantVersion !== previous.grantVersion ||
                (input._tag === "SignIn" &&
                  old.value.context.tokenVersion !== previous.tokenVersion) ||
                !sameIdentity(old.value.context.identity, previous.identity) ||
                !sameIdentity(token.identity, previous.identity) ||
                !sameConfiguration(old.value.context.configuration, previous.configuration) ||
                token.grantVersion === previous.grantVersion
          )
            return yield* rejected();
          const identityKey = yield* state.ensureOwnership(token.identity, current.nativeId);

          if (identityKey === undefined)
            return yield* prepareOAuthNative({ _tag: "Conflict" }, prepare);
          const values = state.values(input.grant, current.nativeId, identityKey);

          if (old === undefined) {
            if (batch !== undefined) yield* state.assert(required);
            invariant((yield* state.change(grant.insert(values))) === 1);
          } else
            invariant(
              (yield* state.change(
                sql`${grant.update(values)} where ${state.key(key, current.nativeId)} and ${state.exact(g.grantVersion, old.value.context.grantVersion)} ${input._tag === "SignIn" ? sql`and ${state.exact(g.tokenVersion, old.value.context.tokenVersion)}` : sql``} and ${required}`,
              )) === 1,
            );
          yield* state.finish(
            "oauth-connected-grant",
            sql.and([
              required,
              present(
                key,
                current.nativeId,
                state.stored.encode(input.grant),
                state.exact(g.state, "Active"),
              ),
              sql`exists(select 1 from ${state.ownership.name} where ${state.ownerCondition(identityKey, current.nativeId)})`,
            ]),
          );

          return yield* prepareOAuthNative({ _tag: "Connected", grant: input.grant }, prepare);
        }),
      ),
    list: (original) =>
      read(
        Effect.gen(function* () {
          const authorization = M.snapshotOAuthSync(
            M.OAuthConnectedUseAuthorization,
            original.authorization,
          );

          const input = M.snapshotOAuthSync(M.OAuthConnectedList, {
            limit: original.limit,
            ...(original.cursor === undefined ? {} : { cursor: original.cursor }),
          });

          const current = yield* state.capture(authorization.revision.subjectId, false);

          if (current === undefined) return { items: [] };
          const required = state.use(current, authorization, "metadata");

          if (required === undefined) return { items: [] };

          const rows =
            yield* sql`select ${grant.column(g.summary)} as summary, ${grant.column(g.state)} as state from ${grant.name}
        where ${state.exact(g.moduleId, authorization.moduleId)} and ${grant.column(g.subjectId)} = ${grant.value(g.subjectId, current.nativeId)} and ${required}
        ${input.cursor === undefined ? sql`` : sql`and ${grant.column(g.grantId)} > ${grant.value(g.grantId, input.cursor)}`}
        order by ${grant.column(g.grantId)} limit ${input.limit}`;

          const items = yield* Effect.forEach(rows, (row) =>
            Effect.gen(function* () {
              invariant(typeof row.summary === "string");

              return M.snapshotOAuthSync(M.OAuthConnectedSummary, {
                ...state.summary.decode(row.summary),
                status: yield* Schema.decodeUnknownEffect(
                  M.OAuthConnectedGrantSnapshot.fields.state,
                )(row.state),
              });
            }),
          );

          return {
            items,
            ...(items.length === input.limit ? { cursor: items[items.length - 1]!.grantId } : {}),
          };
        }),
      ),
    disconnect: (original, prepare) =>
      run(
        Effect.gen(function* () {
          const key = M.snapshotOAuthSync(M.OAuthConnectedGrantKey, original.key);

          const version = M.snapshotOAuthSync(
            M.OAuthConnectedTarget.fields.grantVersion,
            original.grantVersion,
          );

          const authorization = M.snapshotOAuthSync(
            M.OAuthConnectedActionAuthorization,
            original.authorization,
          );

          const current = yield* state.capture(key.subjectId, batch === undefined);
          const rejected = () => prepareOAuthNative({ _tag: "Rejected" } as const, prepare);

          if (
            current === undefined ||
            !sameRevision(current.revision, authorization.challenge.revision)
          )
            return yield* rejected();
          if (
            !(yield* validAction(
              authorization,
              {
                moduleId: key.moduleId,
                action: "connected-disconnect",
                flowId: authorization.challenge.flowId,
                revision: current.revision,
                intent: yield* Schema.encodeEffect(
                  Schema.fromJsonString(M.OAuthConnectedDisconnectIntent),
                )({
                  key,
                  grantVersion: version,
                }),
              },
              mapping.subject.decodeActionRequirement(current.subject, "connected-disconnect"),
              current.now,
              authorization.requirement.maximumAgeMillis,
            ))
          )
            return yield* rejected();
          const old = yield* state.readGrant(key, current.nativeId, batch === undefined);

          if (old === undefined || old.value.context.grantVersion !== version)
            return yield* rejected();

          const required = sql.and([
            state.authorityCondition(current.nativeId, current.revision),
            sql`${now} < ${authorization.validUntilMillis}`,
            policy({
              subjectId: current.nativeId,
              revision: current.revision,
              kind: "action",
              operation: "disconnect",
              authorization,
              grant: old.value.context,
            }),
          ]);

          if ((yield* sql`select 1 where ${required}`).length !== 1) return yield* rejected();
          let remoteRevocation: "Pending" | "Unsupported" = "Unsupported";
          const final = [];

          if (
            mapping.revocation.mode === "provider" &&
            old.value.context.configuration.profile.revocation === "provider"
          ) {
            const j = mapping.revocation.job;
            const job = tables(j.table);

            const jobId = yield* Schema.decodeEffect(M.OAuthClaimId)(
              Base64Url.encode(yield* crypto.randomBytes(32)),
            );

            const retained = M.snapshotOAuthSync(M.OAuthConnectedRevocationJob, {
              jobId,
              grant: old.value,
            });

            const encoded = storage(M.OAuthConnectedRevocationJob).encode(retained);

            invariant(
              Number.isSafeInteger(mapping.revocation.retentionMillis) &&
                mapping.revocation.retentionMillis >= 120000,
            );
            invariant(
              (yield* state.change(
                job.insert({
                  ...j.encodeInsert({ job: retained, subjectId: current.nativeId }),
                  [j.jobId]: jobId,
                  [j.moduleId]: key.moduleId,
                  [j.subjectId]: current.nativeId,
                  [j.identityKey]: old.identityKey,
                  [j.snapshot]: encoded,
                  [j.state]: "Pending",
                  [j.claimId]: null,
                  [j.claimedAt]: null,
                  [j.claimExpiresAt]: null,
                  [j.retentionUntil]: mapping.clock.encodeInstant(
                    current.now + mapping.revocation.retentionMillis,
                  ),
                }),
              )) === 1,
            );
            final.push(
              sql`exists(select 1 from ${job.name} where ${exactSqlText(sql, job.column(j.jobId), job.value(j.jobId, jobId))} and ${exactSqlText(sql, job.column(j.snapshot), job.value(j.snapshot, encoded))})`,
            );
            remoteRevocation = "Pending";
          }
          invariant(
            (yield* state.change(
              sql`delete from ${grant.name} where ${state.key(key, current.nativeId)} and ${state.exact(g.grantVersion, version)} and ${required}`,
            )) === 1,
          );
          yield* state.releaseOwnership(
            old.identityKey,
            current.nativeId,
            referenced(old.identityKey, current.nativeId),
          );
          yield* state.finish(
            "oauth-connected-disconnected",
            sql.and([
              required,
              sql`not exists(select 1 from ${grant.name} where ${state.key(key, current.nativeId)})`,
              ...final,
            ]),
          );

          return yield* prepareOAuthNative(
            { _tag: "Disconnected", grantId: key.grantId, remoteRevocation },
            prepare,
          );
        }),
      ),
    claimRefresh: (original, prepare) =>
      run(
        Effect.gen(function* () {
          const key = M.snapshotOAuthSync(M.OAuthConnectedGrantKey, original.key);

          const authorization = M.snapshotOAuthSync(
            M.OAuthConnectedUseAuthorization,
            original.authorization,
          );

          const current = yield* state.capture(key.subjectId, batch === undefined);
          const rejected = () => prepareOAuthNative({ _tag: "Rejected" } as const, prepare);

          if (current === undefined) return yield* rejected();
          const old = yield* state.readGrant(key, current.nativeId, batch === undefined);

          if (
            old === undefined ||
            old.value.context.grantVersion !== original.grantVersion ||
            old.value.context.tokenVersion !== original.tokenVersion
          )
            return yield* rejected();
          const token = old.value.context;
          const required = state.use(current, authorization, "use", token);

          if (required === undefined || (yield* sql`select 1 where ${required}`).length !== 1)
            return yield* rejected();
          if (old.snapshot.state === "Refreshing")
            return yield* prepareOAuthNative({ _tag: "Busy" }, prepare);
          if (
            old.snapshot.state !== "Active" ||
            token.configuration.profile.refresh === "unsupported" ||
            token.metadata.refreshUseUntilMillis === undefined ||
            current.now >= token.metadata.refreshUseUntilMillis
          )
            return yield* prepareOAuthNative({ _tag: "ReauthorizationRequired" }, prepare);
          if (
            current.now <
            token.metadata.useUntilMillis - token.configuration.profile.refreshAheadMillis
          )
            return yield* prepareOAuthNative({ _tag: "Busy" }, prepare);
          invariant(
            Number.isSafeInteger(original.lifetimeMillis) &&
              original.lifetimeMillis >= 1000 &&
              original.lifetimeMillis <= 300000 &&
              original.nextTokenVersion !== token.tokenVersion,
          );

          const deadline = Math.min(
            current.now + original.lifetimeMillis,
            token.metadata.refreshUseUntilMillis,
            authorization.expiresAtMillis,
          );

          const claim = M.snapshotOAuthSync(M.OAuthConnectedRefreshClaim, {
            grant: old.value,
            claimId: original.claimId,
            nextTokenVersion: original.nextTokenVersion,
            claimedAtMillis: current.now,
            claimExpiresAtMillis: deadline,
          });

          const target = sql.and([
            state.key(key, current.nativeId),
            state.exact(g.grantVersion, token.grantVersion),
            state.exact(g.tokenVersion, token.tokenVersion),
            state.exact(g.state, "Active"),
            required,
            sql`${now} >= ${current.now} and ${now} < ${deadline}`,
          ]);

          invariant(
            (yield* state.change(
              sql`${grant.update({ [g.state]: "Refreshing", [g.refreshClaimId]: claim.claimId, [g.refreshNextTokenVersion]: claim.nextTokenVersion, [g.refreshClaimedAt]: mapping.clock.encodeInstant(claim.claimedAtMillis), [g.refreshClaimExpiresAt]: mapping.clock.encodeInstant(deadline) })} where ${target}`,
            )) === 1,
          );
          yield* state.finish(
            "oauth-refresh-claim",
            sql.and([
              required,
              sql`${now} < ${deadline}`,
              present(
                key,
                current.nativeId,
                old.encoded,
                sql.and([
                  state.exact(g.state, "Refreshing"),
                  state.exact(g.refreshClaimId, claim.claimId),
                ]),
              ),
            ]),
          );

          return yield* prepareOAuthNative({ _tag: "Claimed", claim }, prepare);
        }),
      ),
    settleRefresh: (original, prepare) =>
      run(
        Effect.gen(function* () {
          const claim = M.snapshotOAuthSync(M.OAuthConnectedRefreshClaim, original.claim);

          const authorization = M.snapshotOAuthSync(
            M.OAuthConnectedUseAuthorization,
            original.authorization,
          );

          const outcome = M.snapshotOAuthSync(M.OAuthConnectedRefreshOutcome, original.outcome);
          const token = claim.grant.context;

          const key = {
            moduleId: token.moduleId,
            subjectId: token.subjectId,
            grantId: token.grantId,
          };

          const current = yield* state.capture(token.subjectId, batch === undefined);
          const rejected = () => prepareOAuthNative({ _tag: "Rejected" } as const, prepare);

          if (
            current === undefined ||
            current.now < claim.claimedAtMillis ||
            current.now >= claim.claimExpiresAtMillis
          )
            return yield* rejected();
          const required = state.use(current, authorization, "use", token);

          if (required === undefined || (yield* sql`select 1 where ${required}`).length !== 1)
            return yield* rejected();
          const old = yield* state.readGrant(key, current.nativeId, batch === undefined);

          if (
            old === undefined ||
            old.encoded !== state.stored.encode(claim.grant) ||
            old.snapshot.state !== "Refreshing" ||
            old.row[g.refreshClaimId] !== claim.claimId ||
            old.row[g.refreshNextTokenVersion] !== claim.nextTokenVersion ||
            mapping.clock.decodeInstant(old.row[g.refreshClaimedAt]) !== claim.claimedAtMillis ||
            mapping.clock.decodeInstant(old.row[g.refreshClaimExpiresAt]) !==
              claim.claimExpiresAtMillis
          )
            return yield* rejected();
          let values: Readonly<Record<string, unknown>>;
          let deadline = Math.min(claim.claimExpiresAtMillis, authorization.expiresAtMillis);
          let encoded = old.encoded;

          if (outcome._tag === "Refreshed") {
            const next = outcome.grant.context;

            invariant(
              next.moduleId === token.moduleId &&
                next.subjectId === token.subjectId &&
                next.grantId === token.grantId &&
                next.grantVersion === token.grantVersion &&
                next.tokenVersion === claim.nextTokenVersion &&
                sameIdentity(next.identity, token.identity) &&
                sameConfiguration(next.configuration, token.configuration) &&
                next.metadata.obtainedAtMillis >= claim.claimedAtMillis &&
                validConnectedMetadata(next, current.now) &&
                (next.metadata.refreshUseUntilMillis === undefined ||
                  (token.metadata.refreshUseUntilMillis !== undefined &&
                    next.metadata.refreshUseUntilMillis <= token.metadata.refreshUseUntilMillis)),
            );
            deadline = Math.min(deadline, next.metadata.useUntilMillis);
            if (current.now >= deadline) return yield* rejected();
            values = state.values(outcome.grant, current.nativeId, old.identityKey);
            encoded = state.stored.encode(outcome.grant);
          } else
            values = {
              [g.state]: "ReauthorizationRequired",
              [g.refreshClaimId]: null,
              [g.refreshNextTokenVersion]: null,
              [g.refreshClaimedAt]: null,
              [g.refreshClaimExpiresAt]: null,
              [g.summary]: state.summary.encode({
                ...connectedSummary(token),
                status: "ReauthorizationRequired",
              }),
            };

          const target = sql.and([
            state.key(key, current.nativeId),
            state.exact(g.grantVersion, token.grantVersion),
            state.exact(g.tokenVersion, token.tokenVersion),
            state.exact(g.state, "Refreshing"),
            state.exact(g.refreshClaimId, claim.claimId),
            state.exact(g.refreshNextTokenVersion, claim.nextTokenVersion),
            required,
            sql`${now} >= ${claim.claimedAtMillis} and ${now} < ${deadline}`,
          ]);

          invariant((yield* state.change(sql`${grant.update(values)} where ${target}`)) === 1);
          yield* state.finish(
            "oauth-refresh-settled",
            sql.and([
              required,
              sql`${now} < ${deadline}`,
              present(
                key,
                current.nativeId,
                encoded,
                state.exact(
                  g.state,
                  outcome._tag === "Refreshed" ? "Active" : "ReauthorizationRequired",
                ),
              ),
            ]),
          );

          return yield* prepareOAuthNative(outcome, prepare);
        }),
      ),
    cleanup: (original, prepare) =>
      run(
        Effect.gen(function* () {
          const input = M.snapshotOAuthSync(M.OAuthCleanupInput, original);
          const flows = yield* flow.cleanup(input.moduleId, input.limit);
          let removed = flows.removed;

          if (removed < input.limit) {
            const due = sql.and([
              state.exact(g.moduleId, input.moduleId),
              sql`${tables.expression(mapping.clock.toMillis(grant.column(g.expiresAt)))} <= ${now}`,
            ]);

            const rows =
              yield* sql`select ${grant.fields("due_")} from ${grant.name} where ${due} order by ${grant.column(g.expiresAt)}, ${grant.column(g.grantId)} limit ${input.limit - removed}`;

            for (const raw of rows) {
              const row = grant.decode(raw, "due_");
              const nativeId = row[g.subjectId];
              const subjectId = yield* mapping.subjectId.toSubject(nativeId);
              const value = yield* state.decode(row, nativeId);

              invariant(
                (yield* state.change(
                  sql`delete from ${grant.name} where ${state.key({ moduleId: input.moduleId, subjectId, grantId: value.value.context.grantId }, nativeId)} and ${due}`,
                )) === 1,
              );
              yield* state.releaseOwnership(
                value.identityKey,
                nativeId,
                referenced(value.identityKey, nativeId),
              );
              removed++;
            }
          }
          if (removed < input.limit && mapping.revocation.mode === "provider") {
            const j = mapping.revocation.job;
            const job = tables(j.table);

            const due = sql.and([
              exactSqlText(sql, job.column(j.moduleId), job.value(j.moduleId, input.moduleId)),
              sql`${tables.expression(mapping.clock.toMillis(job.column(j.retentionUntil)))} <= ${now}`,
            ]);

            const rows =
              yield* sql`select ${job.fields("job_")} from ${job.name} where ${due} order by ${job.column(j.retentionUntil)}, ${job.column(j.jobId)} limit ${input.limit - removed}`;

            for (const raw of rows) {
              const row = job.decode(raw, "job_");

              const identityKey = yield* Schema.decodeUnknownEffect(Schema.String)(
                row[j.identityKey],
              );

              invariant(
                (yield* state.change(
                  sql`delete from ${job.name} where ${exactSqlText(sql, job.column(j.jobId), job.value(j.jobId, row[j.jobId]))} and ${due}`,
                )) === 1,
              );
              yield* state.releaseOwnership(
                identityKey,
                row[j.subjectId],
                referenced(identityKey, row[j.subjectId]),
              );
              removed++;
            }
          }

          return yield* prepareOAuthNative({ removed, hasMore: removed === input.limit }, prepare);
        }),
      ),
  };

  return { oauthConnectedPersistence: service };
});
