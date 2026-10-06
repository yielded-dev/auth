/* oxlint-disable no-explicit-any -- compiler table shapes are erased; domain codecs and error channels remain typed. */
import { type OAuthAccountRevision, snapshotOAuthSync } from "@yielded/auth/OAuth";
import * as M from "@yielded/auth/OAuth";
import { AuthenticationRequirement } from "@yielded/auth/Sessions";
import { DateTime, Effect, Schema } from "effect";

import type {
  OAuthConnectedAuthorityMapping,
  OAuthConnectedClientRegistrationTable,
  OAuthConnectedCohortTable,
  OAuthConnectedMapping,
  OAuthConnectedPolicyInput,
  OAuthConnectedRevocationMapping,
} from "../models/oauth-connected-model";
import type { SqlExpression as SQL, QueryFailure, QueryOperations } from "../query-operations";
import type { makeOAuthFlowKernel } from "./flow";
import { CurrentOAuthTransaction } from "./owner";
import type { OAuthOwner, Row, makeOAuthOwnerKernel } from "./owner";
import {
  digest,
  invariant,
  oauthIdentityKey,
  sameRevision,
  satisfies,
  storage,
  unavailable,
} from "./state";
type Table = object;

export type Authority = OAuthConnectedAuthorityMapping<any, any, any, any, any, any, any> & {
  readonly client: Partial<Pick<OAuthConnectedClientRegistrationTable<any>, "encodeInsert">>;
  readonly cohort: Partial<Pick<OAuthConnectedCohortTable<any>, "encodeInsert">>;
};

// Expression handles are supplied by the owning compiler, never decoded domain data.
export type Mapping = OAuthConnectedMapping<
  any,
  any,
  any,
  any,
  any,
  any,
  any,
  any,
  any,
  any,
  any,
  any,
  any
>;

export type Revocations = OAuthConnectedRevocationMapping<any, any, any, any, any, any, any, any>;

export type Current = NonNullable<
  Effect.Success<ReturnType<ReturnType<typeof makeOAuthFlowKernel>["currentSubject"]>>
>;

export interface ScopeAnchor {
  readonly id: string;
  row: Row;
}

export interface ClientAnchor {
  readonly id: string;
  row: Row;
  counter: number;
  readonly scope: ScopeAnchor;
}

export const makeOAuthConnectedStateKernel = (
  operations: QueryOperations,
  flow: Pick<ReturnType<typeof makeOAuthFlowKernel>, "currentSubject">,
  owner: Pick<ReturnType<typeof makeOAuthOwnerKernel>, "both" | "col" | "copiedRow" | "equal">,
) => {
  const { and, eq, isNull, sql } = operations;
  const { currentSubject } = flow;
  const { both, col, copiedRow, equal } = owner;

  const contextStorage = storage(M.OAuthConnectedTransactionContext);

  const flowStorage = storage(M.OAuthConnectedPendingFlow);

  const claimStorage = storage(M.OAuthConnectedClaim);

  const tokenContextStorage = storage(M.OAuthConnectedTokenContext);

  const sealedStorage = storage(M.OAuthConnectedSealedTokens);

  const grantStorage = storage(M.OAuthConnectedStoredGrant);

  const admissionStorage = storage(
    Schema.Struct({
      grant: M.OAuthConnectedStoredGrant,
      authorization: M.OAuthConnectedUseAuthorization,
    }),
  );

  const commandStorage = storage(
    Schema.Struct({
      context: M.OAuthConnectedTokenContext,
      originalDigest: Schema.String.check(Schema.isPattern(/^[A-Za-z0-9_-]{43}$/)),
      revocationJobId: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(256))),
    }),
  );

  const disconnectStorage = storage(M.OAuthConnectedDisconnectGrant);

  const refreshStorage = storage(M.OAuthConnectedRefreshClaim);

  const jobStorage = storage(M.OAuthConnectedRevocationJob);

  const summaryStorage = storage(M.OAuthConnectedSummary);

  const disconnectedStorage = storage(M.OAuthConnectedDisconnected);

  const strings = storage(Schema.Array(Schema.String));

  const safeInteger = Schema.Int.check(
    Schema.isBetween({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }),
  );

  const orderParser = Schema.decodeSync(safeInteger);

  const canonicalOrder = Schema.String.check(Schema.isPattern(/^(0|[1-9][0-9]{0,15})$/));

  const orderTextParser = Schema.decodeSync(canonicalOrder);

  const orderNumber = (value: string) => {
    const number = orderParser(Number(orderTextParser(value)));

    invariant(String(number) === value);

    return number;
  };

  const nativeOrder = (mapping: Authority, value: unknown) =>
    orderParser(mapping.order.decode(value));

  const encoder = new TextEncoder();

  const decoder = new TextDecoder("utf-8", { fatal: true });

  const key = Effect.fnUntraced(function* (domain: string, fields: ReadonlyArray<string>) {
    for (const value of fields) invariant(decoder.decode(encoder.encode(value)) === value);

    return "v1:" + (yield* digest(strings.encode([domain, ...fields])));
  });

  const clientKey = (configuration: M.OAuthConnectedConfiguration) =>
    key("effect-auth/oauth-connected-client/v1", [
      configuration.provider,
      configuration.issuer,
      configuration.profile.clientRegistrationId,
    ]);

  const cohortKey = (client: string, identity: string) =>
    key("effect-auth/oauth-connected-cohort/v1", [client, identity]);

  const initialGeneration = (cohort: string) =>
    digest(cohort).pipe(
      Effect.map((value) =>
        M.OAuthConnectedTarget.fields.cohortGeneration.make("initial:" + value),
      ),
    );

  const configuration = (flow: M.OAuthConnectedPendingFlow): M.OAuthConnectedConfiguration =>
    snapshotOAuthSync(M.OAuthConnectedConfiguration, flow.context);

  const retainedUntil = (mapping: Authority, now: number) => {
    invariant(
      Number.isSafeInteger(mapping.retentionMillis) &&
        mapping.retentionMillis >= 120000 &&
        mapping.retentionMillis <= 2592000000,
    );

    return orderParser(now + mapping.retentionMillis);
  };

  const rowCount = Effect.fn("oauthConnected.rowCount")(function* (table: Table, where: SQL) {
    const owner = yield* CurrentOAuthTransaction;

    const rows = yield* (
      owner.database
        .select({ value: sql`count(*)`.mapWith(Number) })
        .from(table)
        .where(where) as Effect.Effect<ReadonlyArray<{ value: number }>, QueryFailure>
    ).pipe(Effect.mapError(unavailable));

    invariant(rows.length === 1);

    return orderParser(rows[0]!.value);
  });

  const countCondition = (table: Table, where: SQL, count: number) =>
    sql`(select count(*) from ${table} where ${where}) = ${count}`;

  const current = Effect.fn("oauthConnected.current")(function* (
    mapping: Mapping,
    subject: OAuthAccountRevision["subjectId"],
  ) {
    const native = yield* mapping.subjectId.toNative(subject);

    return yield* currentSubject(mapping, native);
  });

  const nativeCopy = <N>(value: N): N => copiedRow({ value }).value as N;

  const policyData = (input: OAuthConnectedPolicyInput<any>): OAuthConnectedPolicyInput<any> =>
    Object.freeze({
      ...input,
      subjectId: nativeCopy(input.subjectId),
      revision: snapshotOAuthSync(M.OAuthConnectedUseAuthorization.fields.revision, input.revision),
      ...(input.kind === "sign-in"
        ? {
            credential: snapshotOAuthSync(M.OAuthCredentialSnapshot, input.credential),
            configuration: snapshotOAuthSync(M.OAuthConnectedConfiguration, input.configuration),
          }
        : {
            authorization:
              input.kind === "action"
                ? snapshotOAuthSync(M.OAuthConnectedActionAuthorization, input.authorization)
                : snapshotOAuthSync(M.OAuthConnectedUseAuthorization, input.authorization),
            ...(input.kind === "action"
              ? {
                  configuration: snapshotOAuthSync(
                    M.OAuthConnectedConfiguration,
                    input.configuration,
                  ),
                }
              : {}),
          }),
      ...(input.grant === undefined
        ? {}
        : { grant: snapshotOAuthSync(M.OAuthConnectedTokenContext, input.grant) }),
    }) as OAuthConnectedPolicyInput<any>;

  const jobTable = (mapping: Authority) => {
    const direct = (mapping as Partial<Revocations>).job;
    const configured = (mapping as Partial<Mapping>).revocation;

    return direct ?? (configured?.mode === "cohort" ? configured.job : undefined);
  };

  const policy = Effect.fn("oauthConnected.policy")(function* (
    mapping: Mapping,
    input: OAuthConnectedPolicyInput<any>,
  ) {
    const owner = yield* CurrentOAuthTransaction;

    invariant((mapping.policy.guards?.length ?? 0) <= 32);
    for (const guard of mapping.policy.guards ?? []) {
      const read = yield* owner.read(guard.table, guard.condition(policyData(input)), {
        orderBy: col(guard.table, guard.orderBy),
      });

      invariant(read.rows.length > 0);
    }
    const condition = mapping.policy.condition(policyData(input));
    const accepted = yield* owner.check(condition);

    if (accepted) owner.postconditions.push(condition);

    return accepted;
  });

  const action = Effect.fn("oauthConnected.action")(function* (
    mapping: Mapping,
    found: Current,
    authorization: M.OAuthConnectedActionAuthorization,
    operation: "issue" | "claim" | "settle" | "disconnect",
    expected: {
      readonly moduleId: string;
      readonly flowId: string;
      readonly commandId: string;
      readonly revision: OAuthAccountRevision;
      readonly intent: string;
      readonly maximumAgeMillis: number;
      readonly configuration: M.OAuthConnectedConfiguration;
      readonly grant?: M.OAuthConnectedTokenContext;
    },
  ) {
    const owner = yield* CurrentOAuthTransaction;

    const challenge = authorization.challenge,
      evidence = authorization.evidence;

    const name =
      operation === "issue"
        ? "connected-begin"
        : operation === "disconnect"
          ? "connected-disconnect"
          : "connected-complete";

    const intentDigest = yield* digest(expected.intent);

    const binding = yield* digest(
      strings.encode([
        "effect-auth/oauth-connected-action/v1",
        expected.moduleId,
        name,
        expected.flowId,
        expected.commandId,
        intentDigest,
      ]),
    );

    if (
      challenge.moduleId !== expected.moduleId ||
      challenge.action !== name ||
      challenge.flowId !== expected.flowId ||
      challenge.commandId !== expected.commandId ||
      challenge.intentDigest !== intentDigest ||
      challenge.bindingDigest !== binding ||
      evidence.flowId !== expected.flowId ||
      evidence.bindingDigest !== binding ||
      !sameRevision(challenge.revision, expected.revision) ||
      !sameRevision(evidence.revision, expected.revision) ||
      !sameRevision(found.revision, expected.revision)
    )
      return false;
    const now = yield* owner.now(mapping.clock);

    const requirement = snapshotOAuthSync(
      AuthenticationRequirement,
      mapping.subject.decodeActionRequirement(copiedRow(found.row), name),
    );

    const revisions = new Map(
      found.revision.credentials.map((item) => [item.credentialId, item.revision]),
    );

    if (
      evidence.proofs.some(
        (proof) =>
          !revisions.has(proof.credentialId) || DateTime.toEpochMillis(proof.verifiedAt) > now,
      )
    )
      return false;
    for (const required of [authorization.requirement, requirement]) {
      const age = Math.min(expected.maximumAgeMillis, required.maximumAgeMillis);

      const fresh = evidence.proofs.filter(
        (proof) => now - DateTime.toEpochMillis(proof.verifiedAt) < age,
      );

      if (!satisfies(fresh, required)) return false;
      owner.postconditions.push(
        sql`${mapping.clock.engineNowMillis} >= ${now} and ${both(...fresh.map((proof) => sql`${mapping.clock.engineNowMillis} < ${DateTime.toEpochMillis(proof.verifiedAt) + age}`))}`,
      );
    }

    return yield* policy(mapping, {
      subjectId: found.nativeId,
      revision: found.revision,
      kind: "action",
      operation,
      authorization,
      configuration: expected.configuration,
      ...(expected.grant === undefined ? {} : { grant: expected.grant }),
    });
  });

  const useAuthority = Effect.fn("oauthConnected.useAuthority")(function* (
    mapping: Mapping,
    authorization: M.OAuthConnectedUseAuthorization,
    kind: "metadata" | "use",
    grant?: M.OAuthConnectedTokenContext,
  ) {
    const owner = yield* CurrentOAuthTransaction;
    const found = yield* current(mapping, authorization.revision.subjectId);
    const now = yield* owner.now(mapping.clock);

    if (
      found === undefined ||
      authorization.purpose !== kind ||
      !sameRevision(found.revision, authorization.revision) ||
      now >= authorization.expiresAtMillis ||
      (grant !== undefined &&
        (grant.moduleId !== authorization.moduleId ||
          grant.subjectId !== authorization.revision.subjectId ||
          (authorization.grantId !== undefined && authorization.grantId !== grant.grantId) ||
          (authorization.profileKey !== undefined &&
            authorization.profileKey !== grant.configuration.profile.key)))
    )
      return undefined;
    if (
      !(yield* policy(mapping, {
        subjectId: found.nativeId,
        revision: found.revision,
        kind,
        authorization,
        ...(grant === undefined ? {} : { grant }),
      }))
    )
      return undefined;
    owner.postconditions.push(
      sql`${mapping.clock.engineNowMillis} >= ${now} and ${mapping.clock.engineNowMillis} < ${authorization.expiresAtMillis}`,
    );

    return found;
  });

  const scopeKey = (provider: string, issuer: string) =>
    key("effect-auth/oauth-connected-provider-issuer/v1", [provider, issuer]).pipe(
      Effect.map((value) => "scope:" + value),
    );

  const scopeCache = new WeakMap<OAuthOwner, Map<Table, Map<string, ScopeAnchor>>>();

  const clientCache = new WeakMap<OAuthOwner, Map<Table, Map<string, ClientAnchor>>>();

  const anchors = Effect.fn("oauthConnected.anchors")(function* <A>(
    cache: WeakMap<OAuthOwner, Map<Table, Map<string, A>>>,
    table: Table,
  ) {
    const owner = yield* CurrentOAuthTransaction;
    let tables = cache.get(owner);

    if (tables === undefined) {
      tables = new Map();
      cache.set(owner, tables);
    }
    let rows = tables.get(table);

    if (rows === undefined) {
      rows = new Map();
      tables.set(table, rows);
    }

    return rows;
  });

  /** Empty registration ID is impossible in the public profile label schema. The
   * distinct 52-byte key domain shares the physical table, never a client counter. */
  const scope = Effect.fn("oauthConnected.scope")(function* (
    mapping: Authority,
    config: M.OAuthConnectedConfiguration,
    create: boolean,
  ) {
    const owner = yield* CurrentOAuthTransaction;

    const c = mapping.client,
      id = yield* scopeKey(config.provider, config.issuer),
      cache = yield* anchors(scopeCache, c.table);

    const existing = cache.get(id);

    if (existing !== undefined) return existing;
    const read = yield* owner.read(c.table, equal(c.table, { [c.clientKey]: id }), { limit: 1 });

    if (read.rows.length === 0) {
      const related = [
        mapping.flow,
        mapping.grant,
        mapping.cohort,
        ...(jobTable(mapping) === undefined ? [] : [jobTable(mapping)!]),
      ];

      invariant(
        yield* owner.check(
          both(
            sql`not exists(select 1 from ${c.table} where ${owner.exact(c.table, { [c.provider]: config.provider, [c.issuer]: config.issuer })})`,
            ...related.map(
              (v) =>
                sql`not exists(select 1 from ${v.table} where not exists(select 1 from ${c.table} where ${col(c.table, c.clientKey)} = ${col(v.table, v.clientKey)}))`,
            ),
          ),
        ),
      );
      if (!create) return undefined;
      invariant(c.encodeInsert !== undefined);

      const inserted = yield* owner.insert(
        c.table,
        {
          ...c.encodeInsert(snapshotOAuthSync(M.OAuthConnectedConfiguration, config)),
          [c.clientKey]: id,
          [c.provider]: config.provider,
          [c.issuer]: config.issuer,
          [c.clientRegistrationId]: "",
          [c.counter]: mapping.order.encode(0),
          [c.version]: owner.marker,
        },
        { [c.clientKey]: id },
        true,
      );

      read.rows = inserted.rows;
    }
    const row = read.rows[0]!;

    invariant(
      row[c.provider] === config.provider &&
        row[c.issuer] === config.issuer &&
        row[c.clientRegistrationId] === "" &&
        nativeOrder(mapping, row[c.counter]) === 0,
    );
    const found = { id, row };

    cache.set(id, found);

    return found;
  });

  const touchScope = Effect.fn("oauthConnected.touchScope")(function* (
    mapping: Authority,
    found: ScopeAnchor,
  ) {
    const owner = yield* CurrentOAuthTransaction;
    const c = mapping.client;

    yield* owner.update(
      c.table,
      { [c.clientKey]: found.id, [c.version]: found.row[c.version] },
      { [c.version]: owner.marker },
    );
    found.row = { ...found.row, [c.version]: owner.marker };
  });

  const readScope = Effect.fn("oauthConnected.readScope")(function* (
    mapping: Authority,
    provider: string,
    issuer: string,
  ) {
    const owner = yield* CurrentOAuthTransaction;

    const c = mapping.client,
      id = yield* scopeKey(provider, issuer),
      cache = yield* anchors(scopeCache, c.table),
      cached = cache.get(id);

    if (cached !== undefined) return cached;

    const read = yield* owner.read(c.table, equal(c.table, { [c.clientKey]: id }), { limit: 1 }),
      row = read.rows[0];

    invariant(
      row !== undefined &&
        row[c.provider] === provider &&
        row[c.issuer] === issuer &&
        row[c.clientRegistrationId] === "" &&
        nativeOrder(mapping, row[c.counter]) === 0,
    );
    const found = { id, row };

    cache.set(id, found);

    return found;
  });

  const lockClientById = Effect.fn("oauthConnected.lockClientById")(function* (
    mapping: Authority,
    id: string,
  ) {
    const owner = yield* CurrentOAuthTransaction;

    const c = mapping.client,
      cache = yield* anchors(clientCache, c.table),
      cached = cache.get(id);

    if (cached !== undefined) return cached;

    const discovery = yield* owner.read(c.table, equal(c.table, { [c.clientKey]: id }), {
        limit: 1,
        observe: false,
        lock: false,
      }),
      initial = discovery.rows[0];

    invariant(initial !== undefined);
    const scope = yield* readScope(mapping, initial[c.provider], initial[c.issuer]);

    const read = yield* owner.read(c.table, equal(c.table, { [c.clientKey]: id }), { limit: 1 }),
      row = read.rows[0];

    invariant(
      row !== undefined &&
        row[c.clientRegistrationId] !== "" &&
        id ===
          (yield* key("effect-auth/oauth-connected-client/v1", [
            row[c.provider],
            row[c.issuer],
            row[c.clientRegistrationId],
          ])) &&
        scope.id === (yield* scopeKey(row[c.provider], row[c.issuer])),
    );
    const found = { id, row, counter: nativeOrder(mapping, row[c.counter]), scope };

    cache.set(id, found);

    return found;
  });

  const heldScope = Effect.fnUntraced(function* (
    mapping: Authority,
    provider: string,
    issuer: string,
  ) {
    const cache = yield* anchors(scopeCache, mapping.client.table);

    return cache.get(yield* scopeKey(provider, issuer));
  });

  /** Cleanup obtains every scope then every client before entering any tuple. */
  const prelockClients = Effect.fn("oauthConnected.prelockClients")(function* (
    mapping: Authority,
    ids: ReadonlyArray<string>,
    releaseScopes: ReadonlyArray<{ readonly provider: string; readonly issuer: string }> = [],
  ) {
    const owner = yield* CurrentOAuthTransaction;

    const unique = [...new Set(ids)].sort(),
      c = mapping.client;

    invariant(unique.length <= 4000);
    const scopes = new Map<string, { provider: string; issuer: string; required: boolean }>();

    for (const value of releaseScopes)
      scopes.set(yield* scopeKey(value.provider, value.issuer), { ...value, required: false });
    for (const id of unique) {
      const read = yield* owner.read(c.table, equal(c.table, { [c.clientKey]: id }), {
          limit: 1,
          lock: false,
          observe: false,
        }),
        row = read.rows[0];

      invariant(row !== undefined);
      scopes.set(yield* scopeKey(row[c.provider], row[c.issuer]), {
        provider: row[c.provider],
        issuer: row[c.issuer],
        required: true,
      });
    }
    for (const [id, { provider, issuer, required }] of [...scopes].sort(([a], [b]) =>
      a < b ? -1 : a > b ? 1 : 0,
    )) {
      if (required) yield* readScope(mapping, provider, issuer);
      else {
        const read = yield* owner.read(c.table, equal(c.table, { [c.clientKey]: id }), {
            limit: 1,
          }),
          row = read.rows[0];

        if (row !== undefined) {
          invariant(
            row[c.provider] === provider &&
              row[c.issuer] === issuer &&
              row[c.clientRegistrationId] === "" &&
              nativeOrder(mapping, row[c.counter]) === 0,
          );
          (yield* anchors(scopeCache, c.table)).set(id, { id, row });
        }
      }
    }
    for (const id of unique) yield* lockClientById(mapping, id);
  });

  const client = Effect.fn("oauthConnected.client")(function* (
    mapping: Authority,
    config: M.OAuthConnectedConfiguration,
    create: boolean,
  ) {
    const owner = yield* CurrentOAuthTransaction;

    const c = mapping.client,
      id = yield* clientKey(config),
      where = { [c.clientKey]: id };

    const heldScope = yield* scope(mapping, config, create);

    if (heldScope === undefined) return undefined;

    const cache = yield* anchors(clientCache, c.table),
      cached = cache.get(id);

    if (cached !== undefined) return cached;
    let read = yield* owner.read(c.table, equal(c.table, where), { limit: 1 });

    if (read.rows.length === 0) {
      const related = [
        mapping.flow,
        mapping.grant,
        mapping.cohort,
        ...(jobTable(mapping) === undefined ? [] : [jobTable(mapping)!]),
      ];

      invariant(
        yield* owner.check(
          both(
            ...related.map(
              (v) =>
                sql`not exists(select 1 from ${v.table} where ${eq(col(v.table, v.clientKey), id)})`,
            ),
          ),
        ),
      );
    }
    if (read.rows.length === 0 && create) {
      const inserted = yield* owner.insert(
        c.table,
        {
          ...(invariant(c.encodeInsert !== undefined),
          c.encodeInsert(snapshotOAuthSync(M.OAuthConnectedConfiguration, config))),
          ...where,
          [c.provider]: config.provider,
          [c.issuer]: config.issuer,
          [c.clientRegistrationId]: config.profile.clientRegistrationId,
          [c.counter]: mapping.order.encode(0),
          [c.version]: owner.marker,
        },
        where,
        true,
      );

      read.rows = inserted.rows;
    }
    const row = read.rows[0];

    if (row === undefined) return undefined;
    invariant(
      row[c.provider] === config.provider &&
        row[c.issuer] === config.issuer &&
        row[c.clientRegistrationId] === config.profile.clientRegistrationId,
    );
    const found = { id, row, counter: nativeOrder(mapping, row[c.counter]), scope: heldScope };

    cache.set(id, found);

    return found;
  });

  const nextOrder = Effect.fn("oauthConnected.nextOrder")(function* (
    mapping: Authority,
    found: NonNullable<Effect.Success<ReturnType<typeof client>>>,
  ) {
    const owner = yield* CurrentOAuthTransaction;

    const next = orderParser(found.counter + 1),
      c = mapping.client;

    yield* owner.update(
      c.table,
      { [c.clientKey]: found.id, [c.counter]: mapping.order.encode(found.counter) },
      { [c.counter]: mapping.order.encode(next), [c.version]: owner.marker },
    );
    found.counter = next;

    return next;
  });

  const cohort = Effect.fn("oauthConnected.cohort")(function* (
    mapping: Authority,
    clientId: string,
    identityId: string,
    create: boolean,
  ) {
    const owner = yield* CurrentOAuthTransaction;

    const c = mapping.cohort,
      id = yield* cohortKey(clientId, identityId),
      where = { [c.cohortKey]: id };

    let read = yield* owner.read(c.table, equal(c.table, where), { limit: 1 });

    if (read.rows.length === 0) {
      const related = [
        mapping.flow,
        mapping.grant,
        ...(jobTable(mapping) === undefined ? [] : [jobTable(mapping)!]),
      ];

      invariant(
        yield* owner.check(
          both(
            ...related.map(
              (v) =>
                sql`not exists(select 1 from ${v.table} where ${eq(col(v.table, v.cohortKey), id)})`,
            ),
          ),
        ),
      );
    }
    if (read.rows.length === 0 && create) {
      const inserted = yield* owner.insert(
        c.table,
        {
          ...(invariant(c.encodeInsert !== undefined),
          c.encodeInsert({ clientKey: clientId, identityKey: identityId })),
          ...where,
          [c.clientKey]: clientId,
          [c.identityKey]: identityId,
          [c.generation]: yield* initialGeneration(id),
          [c.cutoff]: mapping.order.encode(0),
          [c.state]: "Open",
          [c.version]: owner.marker,
        },
        where,
        true,
      );

      read.rows = inserted.rows;
    }
    const row = read.rows[0];

    if (row === undefined)
      return {
        id,
        row: undefined,
        generation: yield* initialGeneration(id),
        cutoff: 0,
        blocked: false,
      };
    invariant(
      row[c.clientKey] === clientId &&
        row[c.identityKey] === identityId &&
        ["Open", "Blocked"].includes(row[c.state]),
    );

    const generation = snapshotOAuthSync(
      M.OAuthConnectedTarget.fields.cohortGeneration,
      row[c.generation],
    );

    return {
      id,
      row,
      generation,
      cutoff: nativeOrder(mapping, row[c.cutoff]),
      blocked: row[c.state] === "Blocked",
    };
  });

  const readGrant = Effect.fn("oauthConnected.readGrant")(function* (
    mapping: Authority,
    moduleId: string,
    grantId: string,
    lock = true,
  ) {
    const owner = yield* CurrentOAuthTransaction;
    const g = mapping.grant;

    const read = yield* owner.read(
      g.table,
      equal(g.table, { [g.moduleId]: moduleId, [g.grantId]: grantId }),
      { limit: 1, lock, admissionOnly: lock, observe: false },
    );

    const row = read.rows[0];

    if (row === undefined) return undefined;
    if (lock) owner.observations.push(read);
    const context = tokenContextStorage.decode(row[g.context]);
    const native = yield* mapping.subjectId.toNative(context.subjectId);

    invariant(
      context.moduleId === moduleId &&
        context.grantId === grantId &&
        mapping.subjectId.equals(native, row[g.subjectId]) &&
        row[g.identityKey] === (yield* oauthIdentityKey(context.identity)) &&
        row[g.clientKey] === (yield* clientKey(context.configuration)) &&
        row[g.cohortKey] === (yield* cohortKey(row[g.clientKey], row[g.identityKey])) &&
        row[g.profileKey] === context.configuration.profile.key &&
        row[g.grantVersion] === context.grantVersion &&
        row[g.tokenVersion] === context.tokenVersion &&
        row[g.cohortGeneration] === context.cohortGeneration,
    );

    return {
      row,
      context,
      native,
      sealed: row[g.sealed] === null ? undefined : sealedStorage.decode(row[g.sealed]),
    };
  });

  const unknownWork = (mapping: Authority, clientId: string | SQL, cutoff?: number) => {
    const f = mapping.flow;

    return both(
      eq(col(f.table, f.clientKey), clientId),
      eq(col(f.table, f.work), "Unresolved"),
      isNull(col(f.table, f.cohortKey)),
      cutoff === undefined
        ? undefined
        : sql`${col(f.table, f.claimOrder)} <= ${mapping.order.encode(cutoff)}`,
    );
  };

  const cohortWork = (mapping: Authority, id: string | SQL) => {
    const f = mapping.flow,
      g = mapping.grant;

    return both(
      sql`not exists(select 1 from ${f.table} where ${and(eq(col(f.table, f.cohortKey), id), eq(col(f.table, f.work), "Unresolved"))})`,
      sql`not exists(select 1 from ${g.table} where ${and(eq(col(g.table, g.cohortKey), id), eq(col(g.table, g.refreshWork), "Unresolved"))})`,
    );
  };

  return {
    contextStorage,
    flowStorage,
    claimStorage,
    tokenContextStorage,
    sealedStorage,
    grantStorage,
    admissionStorage,
    commandStorage,
    disconnectStorage,
    refreshStorage,
    jobStorage,
    summaryStorage,
    disconnectedStorage,
    orderNumber,
    nativeOrder,
    clientKey,
    cohortKey,
    initialGeneration,
    configuration,
    retainedUntil,
    rowCount,
    countCondition,
    current,
    nativeCopy,
    jobTable,
    policy,
    action,
    useAuthority,
    scopeKey,
    scope,
    touchScope,
    readScope,
    lockClientById,
    heldScope,
    prelockClients,
    client,
    nextOrder,
    cohort,
    readGrant,
    unknownWork,
    cohortWork,
  };
};
