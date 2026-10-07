import {
  PhoneAdmissionReceipt,
  PhoneAdmissionCounter,
  PhoneStoredState,
  phoneStateScope,
  validPhoneAdmissionInput,
  phoneAdmissionReplay,
  phoneAdmissionDecision,
  phoneAdmissionExpiry,
  phoneSignInSnapshot,
  digest,
  randomId,
} from "@yielded/auth-persistence/Adapter";
import {
  PhoneCustody,
  PhoneLifecycleTarget,
  PhoneLifecyclePolicy,
  type PhoneMutationDecision,
  PhoneOtpUnavailable,
  type PhoneMutation,
} from "@yielded/auth/PhoneOtp";
import type { SubjectId } from "@yielded/auth/Schema";
import { AuthenticationRequirement, SecurityRevision } from "@yielded/auth/Sessions";
/* oxlint-disable no-explicit-any -- existing storage kernels erase foreign table shapes; domain errors remain typed. */
import { sql, inArray, or, type SQL } from "drizzle-orm";
import { Array, Context, Effect, Schema } from "effect";

import { type TransactionScope, both, makeTransactionRows } from "./transaction-owner";

export class CurrentPhoneTransaction extends Context.Service<
  CurrentPhoneTransaction,
  TransactionScope<PhoneOtpUnavailable>
>()("effect-auth/drizzle/CurrentPhoneTransaction") {}

export const unavailable = () => PhoneOtpUnavailable.make({});

export const invariant: (value: unknown) => asserts value = (value) => {
  if (!value) throw unavailable();
};

export const { equal, copiedRow, col } = makeTransactionRows(unavailable);

const readStored = <A extends Schema.Top>(mapping: any, payload: string, schema: A): A["Type"] => {
  const stored = Schema.decodeSync(PhoneStoredState)(payload);

  invariant(stored.moduleId === mapping.moduleId && Schema.is(schema)(stored.record));

  return stored.record;
};

const rejected: PhoneMutationDecision = { _tag: "Rejected" };

const stateRead = Effect.fn("PhoneNative.stateRead")(function* (mapping: any, key: string) {
  const owner = yield* CurrentPhoneTransaction;

  const table = mapping.state;

  const found = yield* owner.read(table.table, equal(table.table, { [table.scope]: key }), {
    admit: false,
    limit: 1,
  });

  const committed: {
    value?: (typeof PhoneStoredState.Type)["record"];
    version?: string;
    inserted?: Record<string, unknown>;
  } = {};

  yield* owner.admit(owner.matchRows(found.table, found.where, found.rows));
  owner.postconditions.push(() => {
    if (committed.value === undefined)
      return both(...owner.matchRows(found.table, found.where, found.rows));

    const payload = Schema.encodeSync(PhoneStoredState)({
      moduleId: mapping.moduleId,
      record: committed.value,
    });

    const values = {
      ...(found.rows[0] ?? committed.inserted),
      [table.scope]: key,
      [table.state]: payload,
      [table.version]: committed.version,
    };

    return both(...owner.matchRows(found.table, found.where, [values]));
  });

  return { ...found, committed };
});

const stateWrite = Effect.fn("PhoneNative.stateWrite")(function* (
  mapping: any,
  key: string,
  value: (typeof PhoneStoredState.Type)["record"],
  captured: Effect.Success<ReturnType<typeof stateRead>>,
) {
  const owner = yield* CurrentPhoneTransaction;
  const table = mapping.state;
  const version = yield* randomId;

  const payload = Schema.encodeSync(PhoneStoredState)({
    moduleId: mapping.moduleId,
    record: value,
  });

  const values = { [table.state]: payload, [table.version]: version };

  yield* owner.admit(owner.matchRows(captured.table, captured.where, captured.rows));
  if (captured.rows.length === 0) {
    const inserted = {
      ...copiedRow(table.encodeInsert({ scope: key, state: payload, version })),
      [table.scope]: key,
      ...values,
    };

    yield* owner.write(owner.database.insert(table.table).values(inserted));
    captured.committed.inserted = inserted;
  } else
    yield* owner.write(
      owner.database
        .update(table.table)
        .set(values)
        .where(owner.exact(table.table, captured.rows[0]!)),
    );
  Object.assign(captured.committed, { value, version });
});

const custodyRead = Effect.fn("PhoneNative.custodyRead")(function* (
  mapping: any,
  phoneNumber: string,
) {
  const key = yield* phoneStateScope(mapping.moduleId, "custody", phoneNumber),
    observation = yield* stateRead(mapping, key);

  const custody =
    observation.rows.length === 0
      ? null
      : readStored(mapping, observation.rows[0]![mapping.state.state], PhoneCustody);

  invariant(custody === null || custody.phoneNumber === phoneNumber);

  return { key, observation, custody };
});

export const capturePhone = Effect.fn("PhoneNative.capture")(function* (
  mapping: any,
  input: {
    readonly action: "register" | "verify" | "change";
    readonly phoneNumber: any;
    readonly subjectId?: SubjectId;
    readonly sourcePhoneNumber?: any;
  },
  forLookup = false,
) {
  const owner = yield* CurrentPhoneTransaction;

  const result: {
    securityRevision?: string;
    identifier?: Record<string, unknown>;
    verifiedCredential?: Record<string, unknown>;
    retiredCredential?: Record<string, unknown>;
  } = {};

  const destination = yield* custodyRead(mapping, input.phoneNumber);

  const source =
    input.sourcePhoneNumber === undefined
      ? null
      : yield* custodyRead(mapping, input.sourcePhoneNumber);

  const id = input.subjectId ?? destination.custody?.subjectId;

  const subject =
    id === undefined
      ? null
      : yield* owner.read(
          mapping.subject.table,
          equal(mapping.subject.table, { [mapping.subject.id]: mapping.subjectIds.toNative(id) }),
          {
            admit: false,
            limit: 1,
            ...(owner.batch ? {} : { condition: mapping.subject.activeCondition }),
          },
        );

  if (subject !== null) {
    yield* owner.admit(owner.matchRows(subject.table, subject.where, subject.rows));
    owner.postconditions.push(() =>
      both(
        ...owner.matchRows(
          subject.table,
          subject.where,
          subject.rows.map((row) =>
            result.securityRevision === undefined
              ? row
              : {
                  ...row,
                  [mapping.subject.securityRevision]: result.securityRevision,
                },
          ),
        ),
      ),
    );
  }
  const row = subject?.rows[0];

  const active =
    row !== undefined &&
    (owner.batch
      ? yield* owner.check(
          sql`exists(select 1 from ${mapping.subject.table} where ${both(owner.exact(mapping.subject.table, row), mapping.subject.activeCondition)})`,
        )
      : subject?.conditionHolds === true);

  const targetIdentifier = yield* owner.read(
    mapping.identifier.table,
    equal(mapping.identifier.table, {
      [mapping.identifier.namespace]: "phone",
      [mapping.identifier.value]: input.phoneNumber,
    }),
    {
      admit: false,
      limit: 1,
      ...(owner.batch || !forLookup || id === undefined
        ? {}
        : {
            condition: both(
              equal(mapping.identifier.table, {
                [mapping.identifier.subjectId]: mapping.subjectIds.toNative(id),
              }),
              mapping.identifier.activeCondition,
            ),
          }),
    },
  );

  yield* owner.admit(
    owner.matchRows(targetIdentifier.table, targetIdentifier.where, targetIdentifier.rows),
  );
  owner.postconditions.push(() =>
    both(
      ...owner.matchRows(
        targetIdentifier.table,
        targetIdentifier.where,
        result.identifier === undefined ? targetIdentifier.rows : [result.identifier],
      ),
    ),
  );

  let eligible =
    input.action === "register"
      ? destination.custody === null && targetIdentifier.rows.length === 0
      : active &&
        input.subjectId === id &&
        ((destination.custody === null && targetIdentifier.rows.length === 0) ||
          (destination.custody?.subjectId === id && destination.custody?.state === "unverified"));

  if (input.action === "change")
    eligible =
      eligible &&
      input.sourcePhoneNumber !== input.phoneNumber &&
      source?.custody?.subjectId === id &&
      source?.custody?.state === "verified";
  const credentials = [];

  for (const custody of [destination.custody, source?.custody])
    if (
      custody !== null &&
      custody !== undefined &&
      custody.state === "verified" &&
      custody.subjectId === id
    ) {
      const c = mapping.credential;

      const found = yield* owner.read(
        c.table,
        equal(c.table, {
          [c.id]: custody.credentialId,
          [c.subjectId]: mapping.subjectIds.toNative(id),
        }),
        { admit: false, limit: 1, ...(owner.batch ? {} : { condition: c.activeCondition }) },
      );

      yield* owner.admit(owner.matchRows(found.table, found.where, found.rows));
      owner.postconditions.push(() =>
        both(
          ...owner.matchRows(
            found.table,
            found.where,
            found.rows.map((row) => {
              const change =
                result.retiredCredential?.[c.id] === row[c.id]
                  ? result.retiredCredential
                  : result.verifiedCredential?.[c.id] === row[c.id]
                    ? result.verifiedCredential
                    : undefined;

              return change === undefined ? row : { ...row, ...change };
            }),
          ),
        ),
      );
      const cr = found.rows[0];

      if (
        cr === undefined ||
        cr[c.revision] !== custody.credentialRevision ||
        !(owner.batch
          ? yield* owner.check(
              sql`exists(select 1 from ${c.table} where ${both(owner.exact(c.table, cr), c.activeCondition)})`,
            )
          : found.conditionHolds === true)
      )
        eligible = false;
      else
        credentials.push({
          credentialId: custody.credentialId,
          revision: custody.credentialRevision,
        });
    }

  const target: PhoneLifecycleTarget = {
    phoneNumber: input.phoneNumber,
    custody: destination.custody,
    source: source?.custody ?? null,
    revision: active
      ? {
          subjectId: id!,
          securityRevision: SecurityRevision.make(row![mapping.subject.securityRevision]),
          credentials,
        }
      : null,
    eligible,
  };

  return { target, destination, source, subject, subjectRow: row, targetIdentifier, result };
});

export const lookupPhone = Effect.fn("PhoneNative.lookup")(function* (
  mapping: any,
  input: { readonly moduleId: string; readonly phoneNumber: any },
) {
  invariant(input.moduleId === mapping.moduleId);

  const captured = yield* capturePhone(
    mapping,
    { action: "verify", phoneNumber: input.phoneNumber },
    true,
  );

  const { custody, revision } = captured.target;

  const owner = yield* CurrentPhoneTransaction,
    i = mapping.identifier,
    row = captured.targetIdentifier.rows[0];

  const identifierCurrent =
    custody !== null &&
    custody.subjectId !== null &&
    row !== undefined &&
    row[i.revision] === custody.custodyRevision &&
    (owner.batch
      ? yield* owner.check(
          sql`exists(select 1 from ${i.table} where ${both(owner.exact(i.table, row), equal(i.table, { [i.subjectId]: mapping.subjectIds.toNative(custody.subjectId) }), i.activeCondition)})`,
        )
      : captured.targetIdentifier.conditionHolds === true);

  return yield* phoneSignInSnapshot(input, custody, revision, identifierCurrent);
});

export const admitPhone = Effect.fn("PhoneNative.admit")(function* (
  mapping: any,
  input: {
    readonly moduleId: string;
    readonly action: "request" | "attempt";
    readonly requestId: string;
    readonly fingerprint: string;
    readonly networkKey: string;
    readonly replayLifetimeMillis: number;
  },
) {
  invariant(input.moduleId === mapping.moduleId && validPhoneAdmissionInput(input));

  const owner = yield* CurrentPhoneTransaction,
    now = yield* owner.now(mapping),
    policy = mapping.admission;

  const key = yield* phoneStateScope(
      mapping.moduleId,
      "admission",
      input.action + "/" + input.requestId,
    ),
    receipt = yield* stateRead(mapping, key);

  if (receipt.rows.length !== 0) {
    const saved = readStored(mapping, receipt.rows[0]![mapping.state.state], PhoneAdmissionReceipt);

    if (saved.expiresAtMillis > now)
      owner.postconditions.push(sql`${mapping.engineNowMillis} < ${saved.expiresAtMillis}`);

    return phoneAdmissionReplay(saved, input, yield* digest(input.networkKey), now);
  }

  const entries = [
    {
      key: yield* phoneStateScope(
        mapping.moduleId,
        "network",
        input.action + "/" + (yield* digest(input.networkKey)),
      ),
      limit: input.action === "request" ? policy.networkRequests : policy.networkAttempts,
    },
    ...(input.action === "request"
      ? [
          {
            key: yield* phoneStateScope(mapping.moduleId, "messages", "global"),
            limit: policy.maximumMessages,
          },
        ]
      : []),
  ].sort((a, b) => a.key.localeCompare(b.key));

  const updates = [];

  for (const entry of entries) {
    const observed = yield* stateRead(mapping, entry.key),
      previous =
        observed.rows.length === 0
          ? undefined
          : readStored(mapping, observed.rows[0]![mapping.state.state], PhoneAdmissionCounter);

    updates.push({ ...entry, observed, previous });
  }
  const { window, counts, accepted } = phoneAdmissionDecision(now, policy, updates);

  if (accepted)
    for (const [index, update] of updates.entries())
      yield* stateWrite(
        mapping,
        update.key,
        { window, count: counts[index]! + 1 },
        update.observed,
      );
  yield* stateWrite(
    mapping,
    key,
    {
      fingerprint: input.fingerprint,
      network: yield* digest(input.networkKey),
      accepted,
      expiresAtMillis: now + Math.min(policy.requestRetentionMillis, input.replayLifetimeMillis),
    },
    receipt,
  );
  owner.postconditions.push(
    sql`${mapping.engineNowMillis} >= ${window * policy.windowMillis} and ${mapping.engineNowMillis} < ${(window + 1) * policy.windowMillis}`,
  );

  return accepted;
});

export const preparePhoneMutation = Effect.fn("PhoneNative.prepareMutation")(function* (
  mapping: any,
  input: PhoneMutation,
) {
  const owner = yield* CurrentPhoneTransaction;

  invariant(
    input.moduleId === mapping.moduleId &&
      Schema.encodeSync(Schema.fromJsonString(PhoneLifecyclePolicy))(input.policy) ===
        Schema.encodeSync(Schema.fromJsonString(PhoneLifecyclePolicy))(mapping.policy),
  );

  const captured = yield* capturePhone(mapping, {
    action: input.action,
    phoneNumber: input.target.phoneNumber,
    ...(input.target.revision === null ? {} : { subjectId: input.target.revision.subjectId }),
    ...(input.target.source === null ? {} : { sourcePhoneNumber: input.target.source.phoneNumber }),
  });

  if (
    !captured.target.eligible ||
    Schema.encodeSync(Schema.fromJsonString(PhoneLifecycleTarget))(captured.target) !==
      Schema.encodeSync(Schema.fromJsonString(PhoneLifecycleTarget))(input.target)
  )
    return { decision: rejected };
  const binding = input.completion.input.binding;

  if (
    input.completion.input.moduleId !== `${mapping.moduleId}/lifecycle` ||
    input.completion.input.purpose !== "phone-lifecycle" ||
    binding.identifier.namespace !== "phone" ||
    binding.identifier.value !== input.target.phoneNumber
  )
    return { decision: rejected };
  if (
    input.action === "register"
      ? binding._tag !== "Identifier"
      : binding._tag === "Identifier" ||
        binding.revision.subjectId !== input.target.revision?.subjectId ||
        binding.revision.securityRevision !== input.target.revision?.securityRevision
  )
    return { decision: rejected };
  if (
    (input.action === "verify" && binding._tag !== "Subject") ||
    (input.action === "change" && binding._tag !== "IdentifierChange")
  )
    return { decision: rejected };

  const commandKey = yield* phoneStateScope(mapping.moduleId, "command", input.commandId),
    command = yield* stateRead(mapping, commandKey);

  if (command.rows.length !== 0) return { decision: rejected };

  const now = yield* owner.now(mapping),
    guards: SQL[] = [];

  const credentialGuards: { id: string; condition: SQL }[] = [];

  if (input.action !== "register") {
    const authorization = input.authorization;

    if (authorization === undefined) return { decision: rejected };
    const { challenge, evidence } = authorization;
    const revision = captured.target.revision!;

    if (
      challenge.moduleId !== mapping.moduleId ||
      challenge.action !== input.action ||
      challenge.commandId !== input.commandId ||
      challenge.phoneNumber !== input.target.phoneNumber ||
      challenge.sourcePhoneNumber !== input.target.source?.phoneNumber ||
      challenge.flowId !== binding.flowId ||
      challenge.bindingDigest !== binding.contextDigest ||
      challenge.flowId !== evidence.flowId ||
      challenge.bindingDigest !== evidence.bindingDigest ||
      challenge.revision.subjectId !== revision.subjectId ||
      challenge.revision.securityRevision !== revision.securityRevision ||
      evidence.revision.subjectId !== revision.subjectId ||
      evidence.revision.securityRevision !== revision.securityRevision
    )
      return { decision: rejected };
    const c = mapping.credential;

    const expected = [...evidence.revision.credentials].sort((a, b) =>
      a.credentialId.localeCompare(b.credentialId),
    );

    // D1 keeps its per-key assertion schedule and bounded statement parameters.
    // Native transactions lock the authority vector in driver-sized groups.
    const vectors = [];

    if (!owner.batch && expected.length > 0) {
      const subject = equal(c.table, {
        [c.subjectId]: mapping.subjectIds.toNative(revision.subjectId),
      });

      const baseParameters = owner.database
        .select({ active: sql`case when ${c.activeCondition} then 1 else 0 end` })
        .from(c.table)
        .where(subject)
        .limit(65)
        .toSQL().params.length;

      const size = Math.max(
        1,
        Math.min(64, Math.floor((owner.maxParameters - baseParameters - 1) / 3)),
      );

      for (const group of Array.chunksOf(expected, size))
        vectors.push(
          yield* owner.read(
            c.table,
            both(
              subject,
              inArray(
                col(c.table, c.id),
                group.map((item) => item.credentialId),
              ),
            ),
            {
              admit: false,
              limit: group.length,
              orderBy: sql`case ${sql.join(
                group.map(
                  (item, index) =>
                    sql`when ${equal(c.table, { [c.id]: item.credentialId })} then ${index}`,
                ),
                sql` `,
              )} else ${group.length} end`,
              condition: c.activeCondition,
            },
          ),
        );
    }

    for (const item of expected) {
      const vector = vectors.find((read) =>
        read.rows.some((candidate) => candidate[c.id] === item.credentialId),
      );

      const matched = vector?.rows.find((candidate) => candidate[c.id] === item.credentialId);

      // Custom collations may resolve an input ID to a differently encoded
      // stored ID. Preserve the original database lookup in that case.
      const found =
        matched === undefined
          ? yield* owner.read(
              c.table,
              equal(c.table, {
                [c.id]: item.credentialId,
                [c.subjectId]: mapping.subjectIds.toNative(revision.subjectId),
              }),
              {
                admit: false,
                limit: 1,
                ...(owner.batch ? {} : { condition: c.activeCondition }),
              },
            )
          : vector!;

      yield* owner.admit(owner.matchRows(found.table, found.where, found.rows));
      const row = matched ?? found.rows[0];

      if (row === undefined || row[c.revision] !== item.revision) return { decision: rejected };
      const condition = sql`exists(select 1 from ${c.table} where ${both(owner.exact(c.table, row), c.activeCondition)})`;

      if (!(owner.batch ? yield* owner.check(condition) : found.conditionHolds === true))
        return { decision: rejected };
      credentialGuards.push({ id: item.credentialId, condition });
    }
    const proofs = evidence.proofs;

    if (
      proofs.length === 0 ||
      proofs.some(
        (p) => !evidence.revision.credentials.some((c) => c.credentialId === p.credentialId),
      )
    )
      return { decision: rejected };

    const requirements = [
      authorization.requirement,
      authorization.actionRequirement,
      ...(mapping.subject.decodeActionRequirement === undefined
        ? []
        : [
            Schema.decodeSync(AuthenticationRequirement)(
              mapping.subject.decodeActionRequirement(
                copiedRow(captured.subjectRow!),
                input.action,
              ),
            ),
          ]),
      Schema.decodeSync(AuthenticationRequirement)(
        mapping.subject.decodeRequirement(copiedRow(captured.subjectRow!)),
      ),
    ];

    const age = Math.min(
        input.policy.maximumEvidenceAgeMillis,
        ...requirements.map((r) => r.maximumAgeMillis),
      ),
      factors = new Set(proofs.flatMap((p) => p.factors)),
      credentials = new Set(proofs.map((p) => p.credentialId));

    for (const requirement of requirements)
      if (
        !requirement.alternatives.some(
          (a) =>
            a.factors.every((f) => factors.has(f)) &&
            credentials.size >= a.minimumCredentials &&
            proofs.some(
              (p) =>
                (!a.userVerified || p.userVerified) &&
                (!a.phishingResistant || p.phishingResistant),
            ),
        )
      )
        return { decision: rejected };
    for (const proof of proofs) {
      const at = proof.verifiedAt.epochMilliseconds;

      if (at > now || now - at >= age) return { decision: rejected };
      guards.push(
        sql`${mapping.engineNowMillis} >= ${at} and ${mapping.engineNowMillis} < ${at + age}`,
      );
    }
  }

  const subjectId =
      input.action === "register"
        ? mapping.subjectIds.toSubject(mapping.subjectIds.allocate())
        : captured.target.revision!.subjectId,
    nativeId = mapping.subjectIds.toNative(subjectId),
    securityRevision = SecurityRevision.make(yield* randomId),
    credentialRevision = SecurityRevision.make(yield* randomId),
    custodyRevision = SecurityRevision.make(yield* randomId),
    credentialId = captured.target.custody?.credentialId ?? (yield* randomId);

  invariant(mapping.subjectIds.toSubject(nativeId) === subjectId);

  const custody: PhoneCustody = {
    phoneNumber: input.target.phoneNumber,
    subjectId,
    credentialId,
    credentialRevision,
    custodyRevision,
    verifiedAtMillis: now,
    state: "verified",
  };

  const decision: PhoneMutationDecision = {
    _tag: "Accepted",
    credential: {
      moduleId: mapping.moduleId,
      phoneNumber: input.target.phoneNumber,
      custodyRevision,
      verifiedAtMillis: now,
      credentialId,
      credentialRevision,
      revision: {
        subjectId,
        securityRevision,
        credentials: [{ credentialId, revision: credentialRevision }],
      },
    },
  };

  const mutate = Effect.gen(function* () {
    const subject = mapping.subject;

    if (input.action === "register") {
      const values = {
        ...copiedRow(
          subject.encodeInsert({
            id: nativeId,
            securityRevision,
            phoneNumber: input.target.phoneNumber,
          }),
        ),
        [subject.id]: nativeId,
        [subject.securityRevision]: securityRevision,
      };

      yield* owner.write(owner.database.insert(subject.table).values(values));
      owner.postconditions.push(
        ...owner.matchRows(subject.table, equal(subject.table, { [subject.id]: nativeId }), [
          values,
        ]),
      );
    } else {
      yield* owner.admit(
        owner.matchRows(captured.subject!.table, captured.subject!.where, captured.subject!.rows),
      );
      yield* owner.write(
        owner.database
          .update(subject.table)
          .set({ [subject.securityRevision]: securityRevision })
          .where(owner.exact(subject.table, captured.subjectRow!)),
      );
      captured.result.securityRevision = securityRevision;
    }

    const i = mapping.identifier,
      c = mapping.credential;

    if (captured.source?.custody) {
      const old = captured.source.custody;

      const ir = yield* owner.read(
        i.table,
        equal(i.table, {
          [i.namespace]: "phone",
          [i.value]: old.phoneNumber,
          [i.subjectId]: nativeId,
        }),
        { admit: false, limit: 1, ...(owner.batch ? {} : { condition: i.activeCondition }) },
      );

      invariant(ir.rows.length === 1 && ir.rows[0]![i.revision] === old.custodyRevision);
      invariant(
        owner.batch
          ? yield* owner.check(
              sql`exists(select 1 from ${i.table} where ${both(owner.exact(i.table, ir.rows[0]!), i.activeCondition)})`,
            )
          : ir.conditionHolds === true,
      );
      yield* owner.admit(owner.matchRows(ir.table, ir.where, ir.rows));

      const retiredIdentifier = {
        [i.status]: i.encodeStatus(false),
        [i.revision]: yield* randomId,
      };

      yield* owner.write(
        owner.database
          .update(i.table)
          .set(retiredIdentifier)
          .where(owner.exact(i.table, ir.rows[0]!)),
      );
      owner.postconditions.push(
        ...owner.matchRows(ir.table, ir.where, [{ ...ir.rows[0], ...retiredIdentifier }]),
      );

      const retiredCredential = {
        [c.id]: old.credentialId,
        [c.subjectId]: nativeId,
        [c.status]: c.encodeStatus(false),
        [c.revision]: yield* randomId,
      };

      yield* owner.write(
        owner.database
          .update(c.table)
          .set(retiredCredential)
          .where(
            equal(c.table, {
              [c.id]: old.credentialId,
              [c.subjectId]: nativeId,
            }),
          ),
      );
      captured.result.retiredCredential = retiredCredential;
      owner.postconditions.push(
        ...owner.matchRows(
          c.table,
          equal(c.table, {
            [c.id]: old.credentialId,
            [c.subjectId]: nativeId,
          }),
          [retiredCredential],
        ),
      );
      yield* stateWrite(
        mapping,
        captured.source.key,
        {
          ...old,
          state: "retired",
          custodyRevision: SecurityRevision.make(yield* randomId),
          credentialRevision: SecurityRevision.make(yield* randomId),
        },
        captured.source.observation,
      );
    }
    yield* owner.admit(
      owner.matchRows(
        captured.targetIdentifier.table,
        captured.targetIdentifier.where,
        captured.targetIdentifier.rows,
      ),
    );

    const identifierValues = {
      [i.namespace]: "phone",
      [i.value]: input.target.phoneNumber,
      [i.subjectId]: nativeId,
      [i.revision]: custodyRevision,
      [i.verifiedAt]: mapping.encodeInstant(now),
      [i.status]: i.encodeStatus(true),
    };

    if (captured.targetIdentifier.rows.length === 0) {
      const values = {
        ...copiedRow(
          i.encodeInsert({
            phoneNumber: input.target.phoneNumber,
            subjectId: nativeId,
            revision: custodyRevision,
            verifiedAtMillis: now,
            active: true,
          }),
        ),
        ...identifierValues,
      };

      yield* owner.write(owner.database.insert(i.table).values(values));
      captured.result.identifier = values;
    } else {
      const row = captured.targetIdentifier.rows[0]!;

      invariant(
        yield* owner.check(
          sql`exists(select 1 from ${i.table} where ${both(owner.exact(i.table, row), equal(i.table, { [i.subjectId]: nativeId }))})`,
        ),
      );
      yield* owner.write(
        owner.database.update(i.table).set(identifierValues).where(owner.exact(i.table, row)),
      );
      captured.result.identifier = { ...row, ...identifierValues };
    }

    const credential = yield* owner.read(c.table, equal(c.table, { [c.id]: credentialId }), {
      admit: false,
      limit: 1,
    });

    yield* owner.admit(owner.matchRows(credential.table, credential.where, credential.rows));

    const credentialValues = {
      [c.id]: credentialId,
      [c.subjectId]: nativeId,
      [c.revision]: credentialRevision,
      [c.status]: c.encodeStatus(true),
    };

    if (credential.rows.length === 0) {
      const values = {
        ...copiedRow(
          c.encodeInsert({
            credentialId,
            subjectId: nativeId,
            revision: credentialRevision,
            active: true,
          }),
        ),
        ...credentialValues,
      };

      yield* owner.write(owner.database.insert(c.table).values(values));
      owner.postconditions.push(...owner.matchRows(credential.table, credential.where, [values]));
    } else {
      invariant(
        yield* owner.check(
          sql`exists(select 1 from ${c.table} where ${both(owner.exact(c.table, credential.rows[0]!), equal(c.table, { [c.subjectId]: nativeId }))})`,
        ),
      );
      yield* owner.write(
        owner.database
          .update(c.table)
          .set(credentialValues)
          .where(owner.exact(c.table, credential.rows[0]!)),
      );
      owner.postconditions.push(
        ...owner.matchRows(credential.table, credential.where, [
          { ...credential.rows[0], ...credentialValues },
        ]),
      );
    }
    captured.result.verifiedCredential = credentialValues;
    yield* stateWrite(mapping, captured.destination.key, custody, captured.destination.observation);
    yield* stateWrite(
      mapping,
      commandKey,
      { commandId: input.commandId, action: input.action },
      command,
    );
    owner.postconditions.push(
      ...guards,
      sql`exists(select 1 from ${i.table} where ${both(equal(i.table, { [i.namespace]: "phone", [i.value]: input.target.phoneNumber, [i.subjectId]: nativeId, [i.revision]: custodyRevision, [i.verifiedAt]: mapping.encodeInstant(now) }), i.activeCondition)})`,
      ...(captured.source?.custody === null || captured.source?.custody === undefined
        ? []
        : [
            sql`not exists(select 1 from ${i.table} where ${both(equal(i.table, { [i.namespace]: "phone", [i.value]: captured.source.custody.phoneNumber }), i.activeCondition)})`,
            sql`not exists(select 1 from ${c.table} where ${both(equal(c.table, { [c.id]: captured.source.custody.credentialId }), c.activeCondition)})`,
          ]),
      ...credentialGuards
        .filter((g) => g.id !== captured.source?.custody?.credentialId && g.id !== credentialId)
        .map((g) => g.condition),
      sql`exists(select 1 from ${c.table} where ${both(equal(c.table, { [c.id]: credentialId, [c.subjectId]: nativeId, [c.revision]: credentialRevision }), c.activeCondition)})`,
      sql`exists(select 1 from ${mapping.subject.table} where ${both(equal(mapping.subject.table, { [mapping.subject.id]: nativeId, [mapping.subject.securityRevision]: securityRevision }), mapping.subject.activeCondition)})`,
    );

    return true;
  });

  return {
    decision,
    mutate,
    appliedCondition: sql`exists(select 1 from ${mapping.state.table} where ${equal(mapping.state.table, { [mapping.state.scope]: commandKey })})`,
  };
});

/** Bounded cursor cleanup never removes custody or semantic-command tombstones. */
export const cleanupPhoneAdmission = Effect.fn("PhoneNative.cleanupAdmission")(function* (
  mapping: any,
  input: { readonly moduleId: string; readonly limit: number; readonly after?: string },
) {
  invariant(
    input.moduleId === mapping.moduleId &&
      Number.isSafeInteger(input.limit) &&
      input.limit >= 1 &&
      input.limit <= 1000,
  );

  const owner = yield* CurrentPhoneTransaction,
    now = yield* owner.now(mapping),
    state = mapping.state;

  // The page predicate matches every later row. Observing it would require the
  // page to be the whole table, so cleanup could not advance. Discover without
  // an observation, then guard each candidate by its scope.
  const page = yield* owner.read(
    state.table,
    input.after === undefined ? sql`1=1` : sql`${col(state.table, state.scope)} > ${input.after}`,
    {
      admit: false,
      limit: input.limit,
      takeOnly: true,
      orderBy: col(state.table, state.scope),
    },
  );

  let deleted = 0;
  const rows = [...page.rows];

  if (!owner.batch) {
    const expired: Array<{ readonly row: Record<string, any>; readonly expiresAt: number }> = [];

    // The page is already locked. Keep its identities in one bounded relation,
    // including survivors and rows belonging to another module.
    for (const row of rows) {
      const stored = Schema.decodeSync(PhoneStoredState)(row[state.state]);

      if (stored.moduleId !== mapping.moduleId) continue;
      const record = stored.record;

      const expiresAt = phoneAdmissionExpiry(record, mapping.admission);

      if (expiresAt !== undefined && expiresAt <= now) expired.push({ row, expiresAt });
    }
    // Scope, encoded state and version retain the decoded eligibility decision.
    // Grouped deletes validate the actual removed rows; the final fence also
    // catches skipped deletes and rows reinserted by triggers.
    const chunkSize = Math.max(1, Math.min(64, Math.floor(owner.maxParameters / 4)));
    const horizon = expired.reduce((latest, entry) => Math.max(latest, entry.expiresAt), 0);
    const current = sql`${mapping.engineNowMillis} >= ${horizon}`;

    const changed = yield* owner.changeRows(
      state.table,
      expired.map(({ row }) => ({
        key: { [state.scope]: row[state.scope] },
        before: row,
        after: null,
      })),
      current,
    );

    if (expired.length > 0) owner.postconditions.push(current);

    for (let offset = 0; !changed && offset < expired.length; offset += chunkSize) {
      const selected = expired.slice(offset, offset + chunkSize);

      yield* owner.write(
        owner.database.delete(state.table).where(
          or(
            ...selected.map(({ row, expiresAt }) =>
              both(
                owner.exact(state.table, {
                  [state.scope]: row[state.scope],
                  [state.state]: row[state.state],
                  [state.version]: row[state.version],
                }),
                sql`${mapping.engineNowMillis} >= ${expiresAt}`,
              ),
            ),
          ),
        ),
      );
    }

    owner.postconditions.push(
      ...owner.matchKeys(
        state.table,
        rows.map((row) => ({ [state.scope]: row[state.scope] })),
        rows.filter((row) => !expired.some((entry) => entry.row === row)),
      ),
    );

    return {
      deleted: expired.length,
      nextCursor: rows.length === input.limit ? String(rows[rows.length - 1]![state.scope]) : null,
    };
  }

  for (const candidate of rows) {
    const current = yield* owner.read(
      state.table,
      equal(state.table, { [state.scope]: candidate[state.scope] }),
      { admit: false, limit: 1 },
    );

    yield* owner.admit(owner.matchRows(current.table, current.where, current.rows));
    const row = current.rows[0];

    if (row === undefined) continue;
    const stored = Schema.decodeSync(PhoneStoredState)(row[state.state]);

    if (stored.moduleId !== mapping.moduleId) continue;
    const record = stored.record;

    const expiresAt = phoneAdmissionExpiry(record, mapping.admission);

    if (expiresAt !== undefined && expiresAt <= now) {
      yield* owner.write(owner.database.delete(state.table).where(owner.exact(state.table, row)));
      owner.postconditions.push(...owner.matchRows(current.table, current.where, []));
      deleted++;
    } else owner.postconditions.push(...owner.matchRows(current.table, current.where, [row]));
  }

  return {
    deleted,
    nextCursor: rows.length === input.limit ? String(rows[rows.length - 1]![state.scope]) : null,
  };
});
