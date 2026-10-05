import * as M from "@yielded/auth/OAuth";
import { asc, eq, getTableColumns, inArray, lte, sql, type Table } from "drizzle-orm";
import { Effect } from "effect";

import { checkCleanupRows, cleanupQueryFits } from "./oauth-cleanup";
import * as C from "./oauth-connected-custody";
import * as F from "./oauth-connected-flow";
import { connectedReferenceCondition } from "./oauth-connected-reference";
import * as S from "./oauth-connected-state";
import {
  both,
  col,
  equal,
  matchesNativeRow,
  CurrentOAuthTransaction,
  type Row,
} from "./oauth-owner";
import { invariant, oauthIdentityKey } from "./oauth-state";

export interface Candidates {
  readonly flows: ReadonlyArray<Row>;
  readonly jobs: ReadonlyArray<Row>;
  readonly grants: ReadonlyArray<Row>;
  readonly cohorts: ReadonlyArray<Row>;
  readonly tuples: ReadonlyArray<Row>;
}

export const discover = Effect.fn("oauthConnected.collectionCandidates")(function* (
  mapping: S.Mapping,
  moduleId: string,
  limit: number,
  at: number,
) {
  const owner = yield* CurrentOAuthTransaction;

  const f = mapping.flow,
    g = mapping.grant,
    j = S.jobTable(mapping),
    h = mapping.cohort,
    t = mapping.ownership.tuple;

  const options = { limit: limit + 1, takeOnly: true, observe: false, lock: false };

  const reads: Array<{
    readonly name: keyof Candidates;
    readonly read: Parameters<typeof owner.readMany>[0][number];
  }> = [
    {
      name: "flows",
      read: {
        table: f.table,
        where: both(
          eq(col(f.table, f.moduleId), moduleId),
          sql`((${col(f.table, f.state)} in ('Prepared','Pending') and ${col(f.table, f.expiresAt)} <= ${mapping.clock.encodeInstant(at)}) or (${col(f.table, f.state)} = 'Claimed' and ${col(f.table, f.claimExpiresAt)} <= ${mapping.clock.encodeInstant(at)}) or (${col(f.table, f.state)} not in ('Prepared','Pending','Claimed') and ${col(f.table, f.work)} <> 'Unresolved' and ${col(f.table, f.retentionUntil)} <= ${mapping.clock.encodeInstant(at)}))`,
        ),
        options: { ...options, orderBy: asc(col(f.table, f.flowId)) },
      },
    },
  ];

  if (j !== undefined)
    reads.push({
      name: "jobs",
      read: {
        table: j.table,
        where: both(
          eq(col(j.table, j.moduleId), moduleId),
          eq(col(j.table, j.state), "Confirmed"),
          lte(col(j.table, j.retentionUntil), mapping.clock.encodeInstant(at)),
        ),
        options: { ...options, orderBy: asc(col(j.table, j.jobId)) },
      },
    });
  reads.push({
    name: "grants",
    read: {
      table: g.table,
      where: both(
        eq(col(g.table, g.moduleId), moduleId),
        sql`${col(g.table, g.state)} in ('Disconnected','ReauthorizationRequired')`,
        sql`${col(g.table, g.sealed)} is null`,
        sql`${col(g.table, g.refreshWork)} <> 'Unresolved'`,
        lte(col(g.table, g.retentionUntil), mapping.clock.encodeInstant(at)),
        sql`${col(g.table, g.revocationJobId)} is null`,
        sql`not exists(select 1 from ${mapping.admission.table} where ${col(mapping.admission.table, mapping.admission.moduleId)} = ${col(g.table, g.moduleId)} and ${col(mapping.admission.table, mapping.admission.grantId)} = ${col(g.table, g.grantId)})`,
        sql`not exists(select 1 from ${mapping.command.table} where ${col(mapping.command.table, mapping.command.moduleId)} = ${col(g.table, g.moduleId)} and ${col(mapping.command.table, mapping.command.grantId)} = ${col(g.table, g.grantId)})`,
        j === undefined
          ? undefined
          : sql`not exists(select 1 from ${j.table} where ${col(j.table, j.moduleId)} = ${col(g.table, g.moduleId)} and ${col(j.table, j.grantId)} = ${col(g.table, g.grantId)})`,
      ),
      options: { ...options, orderBy: asc(col(g.table, g.grantId)) },
    },
  });
  if (j !== undefined)
    reads.push({
      name: "cohorts",
      read: {
        table: h.table,
        where: both(
          equal(h.table, { [h.state]: "Blocked" }),
          C.clearableCondition(
            mapping,
            sql`${col(h.table, h.cohortKey)}`,
            sql`${col(h.table, h.clientKey)}`,
          ),
        ),
        options: { ...options, orderBy: asc(col(h.table, h.cohortKey)) },
      },
    });
  if (mapping.externalReference !== undefined)
    reads.push({
      name: "tuples",
      read: {
        table: t.table,
        where: both(
          eq(col(t.table, t.state), "Owned"),
          sql`not (${connectedReferenceCondition(mapping, sql`${col(t.table, t.identityKey)}`, { provider: sql`${col(t.table, t.provider)}`, issuer: sql`${col(t.table, t.issuer)}` })})`,
          sql`not (${mapping.externalReference({ identityKey: sql`${col(t.table, t.identityKey)}`, subjectId: sql`${col(t.table, t.subjectId)}` })})`,
        ),
        options: { ...options, orderBy: asc(col(t.table, t.identityKey)) },
      },
    });
  const selected = yield* owner.readMany(reads.map(({ read }) => read));

  const result: Record<keyof Candidates, ReadonlyArray<Row>> = {
    flows: [],
    jobs: [],
    grants: [],
    cohorts: [],
    tuples: [],
  };

  for (const [index, { name }] of reads.entries()) result[name] = selected[index]!.rows;

  return result;
});

export const collect = Effect.fn("oauthConnected.collect")(function* (
  mapping: S.Mapping,
  moduleId: string,
  limit: number,
  discovered: Candidates,
) {
  const owner = yield* CurrentOAuthTransaction;

  let visited = 0,
    removed = 0,
    hasMore = false;

  if (limit === 0) return { visited, removed, hasMore: true };
  if (!owner.batch) {
    const result = yield* collectNative(mapping, moduleId, limit, discovered);

    if (result !== undefined) return result;
  }

  const g = mapping.grant,
    j = S.jobTable(mapping),
    h = mapping.cohort;

  if (j !== undefined) {
    const candidates = { rows: discovered.jobs };

    hasMore = candidates.rows.length > limit;
    for (const candidate of candidates.rows.slice(0, limit)) {
      visited++;

      const job = S.jobStorage.decode(candidate[j.snapshot]),
        token = job.context.token;

      const client = yield* S.client(mapping, token.configuration, false);

      invariant(client !== undefined);
      const tuple = yield* F.inspectTuple(mapping, token.identity);
      const cohort = yield* S.cohort(mapping, client.id, tuple.key, false);

      invariant(cohort.row !== undefined);
      const grant = yield* S.readGrant(mapping, token.moduleId, token.grantId);

      const read = yield* owner.read(j.table, equal(j.table, { [j.jobId]: job.context.jobId }), {
          limit: 1,
        }),
        row = read.rows[0];

      if (row === undefined) continue;
      const native = yield* mapping.subjectId.toNative(token.subjectId);

      invariant(
        row[j.snapshot] === S.jobStorage.encode(job) &&
          row[j.moduleId] === moduleId &&
          row[j.identityKey] === tuple.key &&
          row[j.clientKey] === client.id &&
          row[j.cohortKey] === cohort.id &&
          row[j.grantId] === token.grantId &&
          mapping.subjectId.equals(row[j.subjectId], native),
      );

      const now = yield* owner.now(mapping.clock),
        until = mapping.clock.decodeInstant(row[j.retentionUntil]);

      if (row[j.state] !== "Confirmed" || now < until) continue;
      if (grant?.row[g.revocationJobId] === job.context.jobId) {
        invariant(
          matchesNativeRow(g.table, grant.row, {
            [g.moduleId]: token.moduleId,
            [g.grantId]: token.grantId,
          }),
        );
        const summary = S.summaryStorage.decode(grant.row[g.summary]);

        yield* owner.update(
          g.table,
          { [g.moduleId]: token.moduleId, [g.grantId]: token.grantId },
          {
            [g.revocationJobId]: null,
            [g.summary]: S.summaryStorage.encode({ ...summary, remoteRevocation: "Confirmed" }),
            [g.version]: owner.marker,
          },
        );
      }
      yield* owner.remove(j.table, {
        [j.jobId]: job.context.jobId,
        [j.state]: "Confirmed",
        [j.version]: row[j.version],
      });
      owner.postconditions.push(sql`${mapping.clock.engineNowMillis} >= ${until}`);
      removed++;
    }
  }
  if (visited < limit) {
    const candidates = { rows: discovered.grants };
    const remaining = limit - visited;

    if (candidates.rows.length > remaining) hasMore = true;
    for (const candidate of candidates.rows.slice(0, remaining)) {
      visited++;
      const context = S.tokenContextStorage.decode(candidate[g.context]);
      const client = yield* S.client(mapping, context.configuration, false);

      invariant(client !== undefined);
      const tuple = yield* F.inspectTuple(mapping, context.identity);
      const cohort = yield* S.cohort(mapping, client.id, tuple.key, false);

      invariant(cohort.row !== undefined);
      const grant = yield* S.readGrant(mapping, moduleId, context.grantId);

      if (grant === undefined) continue;

      const now = yield* owner.now(mapping.clock),
        until = mapping.clock.decodeInstant(grant.row[g.retentionUntil]);

      if (
        !["Disconnected", "ReauthorizationRequired"].includes(grant.row[g.state]) ||
        grant.row[g.sealed] !== null ||
        grant.row[g.refreshWork] === "Unresolved" ||
        grant.row[g.revocationJobId] !== null ||
        now < until
      )
        continue;

      const a = mapping.admission,
        d = mapping.command;

      const references = both(
        sql`not exists(select 1 from ${a.table} where ${equal(a.table, { [a.moduleId]: moduleId, [a.grantId]: context.grantId })})`,
        sql`not exists(select 1 from ${d.table} where ${equal(d.table, { [d.moduleId]: moduleId, [d.grantId]: context.grantId })})`,
        ...(j === undefined
          ? []
          : [
              sql`not exists(select 1 from ${j.table} where ${equal(j.table, { [j.moduleId]: moduleId, [j.grantId]: context.grantId })})`,
            ]),
      );

      if (!(yield* owner.check(references))) continue;
      yield* owner.remove(g.table, {
        [g.moduleId]: moduleId,
        [g.grantId]: context.grantId,
        [g.version]: grant.row[g.version],
      });
      owner.postconditions.push(references, sql`${mapping.clock.engineNowMillis} >= ${until}`);
      removed++;
    }
  }
  // Clearing is global remote authority, independent of the module which happens
  // to run cleanup. No subject filter may hide a former owner's unresolved work.
  if (visited < limit && j !== undefined) {
    const candidates = { rows: discovered.cohorts };
    const remaining = limit - visited;

    if (candidates.rows.length > remaining) hasMore = true;
    for (const candidate of candidates.rows.slice(0, remaining)) {
      visited++;
      const id = candidate[h.clientKey];
      const client = yield* S.lockClientById(mapping, id);
      const cohort = yield* S.cohort(mapping, id, candidate[h.identityKey], false);

      invariant(cohort.id === candidate[h.cohortKey] && cohort.row !== undefined);
      yield* C.clear(mapping, client, cohort);
    }
  }
  if (visited < limit && mapping.externalReference !== undefined) {
    const t = mapping.ownership.tuple,
      remaining = limit - visited;

    if (discovered.tuples.length > remaining) hasMore = true;
    for (const candidate of discovered.tuples.slice(0, remaining)) {
      visited++;
      const scope = yield* S.heldScope(mapping, candidate[t.provider], candidate[t.issuer]);

      if (scope === undefined) continue;

      const identity = {
        provider: candidate[t.provider],
        issuer: candidate[t.issuer],
        subject: candidate[t.externalSubject],
      };

      invariant((yield* oauthIdentityKey(identity)) === candidate[t.identityKey]);

      const tuple = yield* F.inspectTuple(mapping, identity),
        row = tuple.row;

      if (row === undefined || row[t.state] !== "Owned") continue;
      const native = row[t.subjectId];

      invariant(native !== null);

      const noRefs = both(
        sql`not (${connectedReferenceCondition(mapping, tuple.key)})`,
        sql`not (${mapping.externalReference({ identityKey: tuple.key, subjectId: S.nativeCopy(native) })})`,
      );

      if (!(yield* owner.check(noRefs))) continue;
      yield* S.touchScope(mapping, scope);
      yield* owner.update(
        t.table,
        { [t.identityKey]: tuple.key, [t.state]: "Owned", [t.subjectId]: native },
        {
          [t.state]: "Unowned",
          [t.subjectId]: null,
          [t.reservation]: null,
          [t.version]: owner.marker,
        },
      );
      if (mapping.ownership.mode === "separate")
        yield* owner.remove(mapping.ownership.external.table, {
          [mapping.ownership.external.identityKey]: tuple.key,
        });
      owner.postconditions.push(noRefs);
    }
  }

  return { visited, removed, hasMore };
});

/** Native collection keeps the existing priority/budget but locks each bounded
 * identity set once. Cleanup's caller already owns all scope and client anchors. */
const collectNative = Effect.fn("oauthConnected.collectNative")(function* (
  mapping: S.Mapping,
  moduleId: string,
  limit: number,
  discovered: Candidates,
) {
  const owner = yield* CurrentOAuthTransaction;

  const g = mapping.grant,
    j = S.jobTable(mapping),
    h = mapping.cohort,
    t = mapping.ownership.tuple,
    c = mapping.client;

  let visited = 0,
    removed = 0,
    hasMore = false;

  const take = (rows: ReadonlyArray<Row>) => {
    if (visited === limit) return [];
    const remaining = limit - visited;

    hasMore ||= rows.length > remaining;
    const selected = rows.slice(0, remaining);

    visited += selected.length;

    return selected;
  };

  const jobs = j === undefined ? [] : take(discovered.jobs);
  const grants = take(discovered.grants);
  const clearing = j === undefined ? [] : take(discovered.cohorts);
  const releasing = mapping.externalReference === undefined ? [] : take(discovered.tuples);

  // Native identity equality discovers aliases; canonical rows alone can enter
  // keyed observations. Unsupported encoders keep the ordinary point path.
  let canonicalKeys = true;

  const readSet = Effect.fnUntraced(function* (
    table: Table,
    key: string,
    requested: ReadonlyArray<string>,
    base = sql`1 = 1`,
    presentOnly = false,
  ) {
    const ids = [...new Set(requested)].sort(),
      rows = new Map<string, Row>();

    const keys = ids.map((id) => ({ [key]: id }));
    const selected = yield* owner.readKeys(table, keys, { base, observe: false });

    if (selected !== undefined) {
      if (!selected.canonical) {
        canonicalKeys = false;

        return rows;
      }
      for (const row of selected.rows) {
        invariant(ids.includes(row[key]) && !rows.has(row[key]));
        rows.set(row[key], row);
      }
      yield* owner.observeKeys(
        table,
        presentOnly ? selected.rows.map((row) => ({ [key]: row[key] })) : keys,
        selected.rows,
        base,
      );

      return rows;
    }

    const size = Math.max(1, Math.min(100, Math.floor((owner.maxParameters - 2) / 4)));

    for (let offset = 0; offset < ids.length; offset += size) {
      const chunk = ids.slice(offset, offset + size);

      const read = yield* owner.read(table, both(base, inArray(col(table, key), chunk)), {
        limit: chunk.length,
        observe: false,
        // A custom collation may resolve two distinct encoded IDs to one row.
        // Keep that mapping on the singular path rather than treating an alias
        // as an absent row in the keyed snapshot.
        condition: both(
          ...chunk.map(
            (id) =>
              sql`case when ${equal(table, { [key]: id })} then case when ${owner.exact(table, { [key]: id })} then 1 else 0 end else 1 end = 1`,
          ),
        ),
        // JS identity order is also used by the individual authority locks.
        orderBy: sql`case ${col(table, key)} ${sql.join(
          chunk.map((id, i) => sql`when ${id} then ${sql.raw(String(i))}`),
          sql` `,
        )} end`,
      });

      if (read.rows.length > 0 && !read.conditionHolds) {
        canonicalKeys = false;

        return rows;
      }
      for (const row of read.rows) {
        invariant(chunk.includes(row[key]) && !rows.has(row[key]));
        rows.set(row[key], row);
      }
      for (const id of chunk) {
        const row = rows.get(id);

        if (!presentOnly || row !== undefined)
          yield* owner.observe(
            table,
            both(base, equal(table, { [key]: id })),
            row === undefined ? [] : [row],
          );
      }
    }

    return rows;
  });

  // Raw bulk DML still updates every prior observation, including caller-owned
  // ones. Only values validated from locked rows enter these expected sets.
  const change = Effect.fnUntraced(function* (
    table: Table,
    key: string,
    updates: ReadonlyMap<string, Row | null>,
    base = sql`1 = 1`,
    guards: ReadonlyMap<string, Row> = new Map(),
  ) {
    const entries = [...updates];

    const changes = entries.map(([id, after]) => {
      const before = owner.observations
        .filter((observation) => observation.table === table)
        .flatMap((observation) => observation.rows)
        .find((row) => row[key] === id && (table !== g.table || row[g.moduleId] === moduleId));

      invariant(before !== undefined && matchesNativeRow(table, before, guards.get(id) ?? {}));

      return {
        key: { [key]: id, ...(table === g.table ? { [g.moduleId]: moduleId } : {}) },
        before,
        after,
      };
    });

    if (yield* owner.changeRows(table, changes, base)) return;
    const fields = Object.keys(entries[0]?.[1] ?? {});

    const binds =
      Object.keys(getTableColumns(table)).length +
      2 * fields.length +
      Object.keys(guards.values().next().value ?? {}).length +
      2;

    const size = Math.max(1, Math.min(64, Math.floor(Math.min(800, owner.maxParameters) / binds)));

    const build = (chunk: typeof entries) => {
      const ids = chunk.map(([id]) => id);

      const exact = ids.map((id) => {
        const row = owner.observations
          .filter((observation) => observation.table === table)
          .flatMap((observation) => observation.rows)
          .find((row) => row[key] === id && (table !== g.table || row[g.moduleId] === moduleId));

        invariant(row !== undefined);

        return sql`${owner.exact(table, row)}`;
      });

      const where = both(
        base,
        sql`(${sql.join(exact, sql` or `)})`,
        guards.size === 0
          ? undefined
          : sql`(${sql.join(
              ids.map((id) => equal(table, { [key]: id, ...guards.get(id) })),
              sql` or `,
            )})`,
      );

      if (chunk[0]![1] === null) {
        invariant(chunk.every(([, value]) => value === null));

        return owner.database.delete(table).where(where);
      } else {
        invariant(chunk.every(([, value]) => value !== null));

        const values = Object.fromEntries(
          fields.map((field) => [
            field,
            chunk.every(([, value]) => Object.is(value![field], chunk[0]![1]![field]))
              ? chunk[0]![1]![field]
              : sql`case ${col(table, key)} ${sql.join(
                  chunk.map(
                    ([id, value]) =>
                      sql`when ${id} then ${sql.param(value![field], col(table, field))}`,
                  ),
                  sql` `,
                )} else ${col(table, field)} end`,
          ]),
        );

        return owner.database.update(table).set(values).where(where);
      }
    };

    for (let offset = 0; offset < entries.length;) {
      let chunk = entries.slice(offset, offset + size);
      let query = build(chunk);

      while (chunk.length > 1 && !cleanupQueryFits(query, owner.maxParameters)) {
        chunk = chunk.slice(0, Math.ceil(chunk.length / 2));
        query = build(chunk);
      }
      invariant(cleanupQueryFits(query, owner.maxParameters));
      yield* owner.write(query);
      offset += chunk.length;
    }
    for (const observation of owner.observations)
      if (observation.table === table)
        observation.rows = observation.rows.flatMap((row) => {
          // The grant key is module-scoped; a caller may hold other modules too.
          if (table === g.table && row[g.moduleId] !== moduleId) return [row];
          const values = updates.get(row[key]);

          return values === undefined ? [row] : values === null ? [] : [{ ...row, ...values }];
        });
  });

  const contexts = [];

  for (const row of jobs) contexts.push({ job: S.jobStorage.decode(row[j!.snapshot]) });

  const tokens = [
    ...contexts.map(({ job }) => job.context.token),
    ...grants.map((row) => S.tokenContextStorage.decode(row[g.context])),
  ];

  if (tokens.some((token) => token.moduleId !== moduleId)) return undefined;
  const targets = [];

  for (const token of tokens) {
    const client = yield* S.client(mapping, token.configuration, false);

    invariant(client !== undefined);
    const identity = yield* oauthIdentityKey(token.identity);

    targets.push({ token, client, identity, cohort: yield* S.cohortKey(client.id, identity) });
  }
  const clearTargets = [];

  for (const row of clearing) {
    const client = yield* S.lockClientById(mapping, row[h.clientKey]);
    const cohort = yield* S.cohortKey(client.id, row[h.identityKey]);

    invariant(cohort === row[h.cohortKey]);
    clearTargets.push({ client, identity: row[h.identityKey], cohort });
  }
  const releaseTargets = [];

  for (const row of releasing) {
    const scope = yield* S.heldScope(mapping, row[t.provider], row[t.issuer]);

    if (scope === undefined) continue;

    const identity = {
      provider: row[t.provider],
      issuer: row[t.issuer],
      subject: row[t.externalSubject],
    };

    const key = yield* oauthIdentityKey(identity);

    invariant(key === row[t.identityKey]);
    releaseTargets.push({ scope, identity, key });
  }

  const identities = [
    ...targets.map((target) => ({ key: target.identity, identity: target.token.identity })),
    ...releaseTargets,
  ];

  const tupleRows = yield* readSet(
    t.table,
    t.identityKey,
    identities.map((value) => value.key),
  );

  if (!canonicalKeys) return undefined;

  const externalRows =
    mapping.ownership.mode === "separate"
      ? yield* readSet(
          mapping.ownership.external.table,
          mapping.ownership.external.identityKey,
          identities.map((value) => value.key),
        )
      : new Map<string, Row>();

  if (!canonicalKeys) return undefined;
  const owned = new Map<string, Row>();

  for (const { key, identity } of identities) {
    const row = tupleRows.get(key),
      external = externalRows.get(key);

    F.validateTuple(mapping, identity, row, external === undefined ? [] : [external]);
    if (mapping.ownership.mode === "separate" && row?.[t.state] === "Owned")
      owned.set(key, { [t.identityKey]: key });
  }
  // Existing inspectTuple retains this condition even when later releasing the
  // tuple; retain that same final contract for separate-ownership mappings.
  if (mapping.ownership.mode === "separate") {
    const o = mapping.ownership.external;

    invariant(
      (yield* checkCleanupRows(
        t.table,
        [...owned.values()],
        (fields) =>
          sql`exists(select 1 from ${o.table} where ${both(eq(col(o.table, o.identityKey), fields[t.identityKey]!), o.ownedCondition)})`,
      )).every(Boolean),
    );
  }

  const cohortRows = yield* readSet(
    h.table,
    h.cohortKey,
    [...targets, ...clearTargets].map((value) => value.cohort),
  );

  if (!canonicalKeys) return undefined;
  for (const target of [...targets, ...clearTargets]) {
    const row = cohortRows.get(target.cohort);

    invariant(row !== undefined);
    S.decodeCohort(mapping, target.client.id, target.identity, target.cohort, row);
  }

  const grantRows = yield* readSet(
    g.table,
    g.grantId,
    targets.map((value) => value.token.grantId),
    equal(g.table, { [g.moduleId]: moduleId }),
    true,
  );

  if (!canonicalKeys) return undefined;
  for (const target of targets) {
    const row = grantRows.get(target.token.grantId);

    if (row !== undefined)
      yield* S.decodeGrant(mapping, target.token.moduleId, target.token.grantId, row);
  }

  const jobRows =
    j === undefined
      ? new Map<string, Row>()
      : yield* readSet(
          j.table,
          j.jobId,
          contexts.map(({ job }) => job.context.jobId),
        );

  if (!canonicalKeys) return undefined;
  const now = jobs.length + grants.length === 0 ? 0 : yield* owner.now(mapping.clock);
  let horizon = 0;
  const jobGuards = new Map<string, Row>();

  const summaryUpdates = new Map<string, Row>(),
    deletedJobs = new Map<string, null>();

  for (let index = 0; index < contexts.length; index++) {
    const { job } = contexts[index]!,
      target = targets[index]!,
      token = job.context.token;

    const row = jobRows.get(job.context.jobId);

    if (row === undefined) continue;
    const native = yield* mapping.subjectId.toNative(token.subjectId);

    invariant(
      row[j!.snapshot] === S.jobStorage.encode(job) &&
        row[j!.moduleId] === moduleId &&
        row[j!.identityKey] === target.identity &&
        row[j!.clientKey] === target.client.id &&
        row[j!.cohortKey] === target.cohort &&
        row[j!.grantId] === token.grantId &&
        mapping.subjectId.equals(row[j!.subjectId], native),
    );
    const until = mapping.clock.decodeInstant(row[j!.retentionUntil]);

    if (row[j!.state] !== "Confirmed" || now < until) continue;
    const grant = grantRows.get(token.grantId);

    if (grant?.[g.revocationJobId] === job.context.jobId) {
      const summary = S.summaryStorage.decode(grant[g.summary]);

      const values = {
        [g.revocationJobId]: null,
        [g.summary]: S.summaryStorage.encode({ ...summary, remoteRevocation: "Confirmed" }),
        [g.version]: owner.marker,
      };

      summaryUpdates.set(token.grantId, values);
      grantRows.set(token.grantId, { ...grant, ...values });
    }
    jobGuards.set(job.context.jobId, { [j!.state]: "Confirmed", [j!.version]: row[j!.version] });
    deletedJobs.set(job.context.jobId, null);
    jobRows.delete(job.context.jobId);
    horizon = Math.max(horizon, until);
    removed++;
  }
  yield* change(g.table, g.grantId, summaryUpdates, equal(g.table, { [g.moduleId]: moduleId }));
  if (j !== undefined) yield* change(j.table, j.jobId, deletedJobs, sql`1 = 1`, jobGuards);

  const removable = [];

  for (const target of targets.slice(contexts.length)) {
    const row = grantRows.get(target.token.grantId);

    if (row === undefined) continue;
    const until = mapping.clock.decodeInstant(row[g.retentionUntil]);

    if (
      !["Disconnected", "ReauthorizationRequired"].includes(row[g.state]) ||
      row[g.sealed] !== null ||
      row[g.refreshWork] === "Unresolved" ||
      row[g.revocationJobId] !== null ||
      now < until
    )
      continue;

    removable.push({ id: target.token.grantId, until });
  }

  const grantAccepted = yield* checkCleanupRows(
    g.table,
    removable.map(({ id }) => ({ [g.moduleId]: moduleId, [g.grantId]: id })),
    (fields) =>
      both(
        ...[mapping.admission, mapping.command, ...(j === undefined ? [] : [j])].map(
          (table) =>
            sql`not exists(select 1 from ${table.table} where ${both(
              eq(col(table.table, table.moduleId), fields[g.moduleId]!),
              eq(col(table.table, table.grantId), fields[g.grantId]!),
            )})`,
        ),
      ),
  );

  const deletedGrants = new Map<string, null>(),
    grantGuards = new Map<string, Row>();

  for (let index = 0; index < removable.length; index++)
    if (grantAccepted[index]) {
      const value = removable[index]!;

      if (deletedGrants.has(value.id)) continue;
      grantGuards.set(value.id, { [g.version]: grantRows.get(value.id)![g.version] });
      deletedGrants.set(value.id, null);
      horizon = Math.max(horizon, value.until);
      removed++;
    }
  yield* change(
    g.table,
    g.grantId,
    deletedGrants,
    equal(g.table, { [g.moduleId]: moduleId }),
    grantGuards,
  );
  if (removed > 0) owner.postconditions.push(sql`${mapping.clock.engineNowMillis} >= ${horizon}`);

  const blocked = clearTargets.filter(
    (value) => cohortRows.get(value.cohort)![h.state] === "Blocked",
  );

  const clearAccepted = yield* checkCleanupRows(
    h.table,
    blocked.map((value) => ({ [h.cohortKey]: value.cohort, [h.clientKey]: value.client.id })),
    (fields) => C.clearableCondition(mapping, fields[h.cohortKey]!, fields[h.clientKey]!),
  );

  const clientGuards = new Map<string, Row>();

  const clientUpdates = new Map<string, Row>(),
    cohortUpdates = new Map<string, Row>();

  for (let index = 0; index < blocked.length; index++)
    if (clearAccepted[index]) {
      const { client, cohort } = blocked[index]!;

      if (!clientGuards.has(client.id))
        clientGuards.set(client.id, { [c.counter]: mapping.order.encode(client.counter) });
      const next = S.orderNumber(String(client.counter + 1));

      client.counter = next;
      clientUpdates.set(client.id, {
        [c.counter]: mapping.order.encode(next),
        [c.version]: owner.marker,
      });
      cohortUpdates.set(cohort, {
        [h.generation]: M.OAuthConnectedTarget.fields.cohortGeneration.make(owner.marker + ":open"),
        [h.cutoff]: mapping.order.encode(next),
        [h.state]: "Open",
        [h.version]: owner.marker,
      });
    }
  yield* change(c.table, c.clientKey, clientUpdates, sql`1 = 1`, clientGuards);
  yield* change(h.table, h.cohortKey, cohortUpdates);

  const ownedReleases = releaseTargets.filter(
    (value) => tupleRows.get(value.key)?.[t.state] === "Owned",
  );

  const releaseAccepted = yield* checkCleanupRows(
    t.table,
    ownedReleases.map(({ key }) => {
      const row = tupleRows.get(key)!;

      invariant(row[t.subjectId] !== null);

      return {
        [t.identityKey]: key,
        [t.provider]: row[t.provider],
        [t.issuer]: row[t.issuer],
        [t.subjectId]: S.nativeCopy(row[t.subjectId]),
      };
    }),
    (fields) =>
      both(
        sql`not (${connectedReferenceCondition(mapping, fields[t.identityKey]!, {
          provider: fields[t.provider]!,
          issuer: fields[t.issuer]!,
        })})`,
        sql`not (${mapping.externalReference!({ identityKey: fields[t.identityKey]!, subjectId: fields[t.subjectId]! })})`,
      ),
  );

  const scopeGuards = new Map<string, Row>(),
    tupleGuards = new Map<string, Row>();

  const scopeUpdates = new Map<string, Row>(),
    tupleUpdates = new Map<string, Row>(),
    externalDeletes = new Map<string, null>();

  for (let index = 0; index < ownedReleases.length; index++)
    if (releaseAccepted[index]) {
      const { key, scope } = ownedReleases[index]!;

      if (!scopeGuards.has(scope.id))
        scopeGuards.set(scope.id, { [c.version]: scope.row[c.version] });
      tupleGuards.set(key, { [t.state]: "Owned", [t.subjectId]: tupleRows.get(key)![t.subjectId] });
      scopeUpdates.set(scope.id, { [c.version]: owner.marker });
      tupleUpdates.set(key, {
        [t.state]: "Unowned",
        [t.subjectId]: null,
        [t.reservation]: null,
        [t.version]: owner.marker,
      });
      externalDeletes.set(key, null);
      scope.row = { ...scope.row, [c.version]: owner.marker };
    }
  yield* change(c.table, c.clientKey, scopeUpdates, sql`1 = 1`, scopeGuards);
  yield* change(t.table, t.identityKey, tupleUpdates, sql`1 = 1`, tupleGuards);
  if (mapping.ownership.mode === "separate")
    yield* change(
      mapping.ownership.external.table,
      mapping.ownership.external.identityKey,
      externalDeletes,
    );

  return { visited, removed, hasMore };
});
