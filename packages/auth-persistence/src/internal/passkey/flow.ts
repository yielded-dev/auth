/* oxlint-disable no-explicit-any -- existing mapped-row bridge; public adapters preserve table, ID, and Effect types. */

import {
  PasskeyClaim,
  type PasskeyAccess,
  type PasskeyAssertionVerified,
  type PasskeyCeremony,
  type PasskeyCredential,
  type PasskeyEvidence,
  type PasskeyMethodPolicy,
  snapshotPasskeySync,
} from "@yielded/auth/Passkey";
import type { SubjectId } from "@yielded/auth/Schema";
import { Array, DateTime, Effect } from "effect";

import type { PasskeyFlowState } from "../models/passkey-model";
import type { QueryOperations, SqlExpression as SQL } from "../query-operations";
import type { makeTransactionKernel } from "../transaction-kernel";
import type { makePasskeyAdmissionKernel } from "./admission";
import type { CredentialRead, SubjectRead, makePasskeyCredentialsKernel } from "./credentials";
import type { makePasskeyRegistrationCustodyKernel } from "./registration-custody";
import { CurrentPasskeyTransaction } from "./state";
import type { makePasskeyStateKernel } from "./state";

export interface FlowRead {
  readonly row: Record<string, any>;
  readonly ceremony: PasskeyCeremony;
  readonly policy: PasskeyMethodPolicy;
  readonly state: PasskeyFlowState;
  readonly nowMillis: number;
  readonly conditionHolds?: boolean;
  readonly claim?: PasskeyClaim;
  readonly credential?: PasskeyCredential;
}

export const makePasskeyFlowKernel = (
  operations: QueryOperations,
  admission: Pick<
    ReturnType<typeof makePasskeyAdmissionKernel>,
    | "admissionCondition"
    | "chargeScopes"
    | "guardAdmission"
    | "guardChargeSet"
    | "insertCharges"
    | "lockAdmission"
    | "readCharges"
  >,
  credentials: Pick<
    ReturnType<typeof makePasskeyCredentialsKernel>,
    "readCredential" | "readModule" | "readPolicyGuards" | "readRevision" | "readSubject"
  >,
  registrationCustody: Pick<
    ReturnType<typeof makePasskeyRegistrationCustodyKernel>,
    "releaseRegistrationCustody" | "scrubRegistrationIntent" | "cleanupRegistrationCustody"
  >,
  state: Pick<
    ReturnType<typeof makePasskeyStateKernel>,
    | "ceremonyStorage"
    | "col"
    | "credentialStorage"
    | "equal"
    | "existsExact"
    | "invariant"
    | "mappedColumns"
    | "policyStorage"
    | "profileStorage"
    | "sameCredential"
    | "sameRevision"
    | "semanticCredentialColumns"
    | "subjectScope"
    | "targetScope"
  >,
  transactions: Pick<ReturnType<typeof makeTransactionKernel>, "both">,
) => {
  const { or, sql } = operations;

  const {
    admissionCondition,
    chargeScopes,
    guardAdmission,
    guardChargeSet,
    insertCharges,
    lockAdmission,
    readCharges,
  } = admission;

  const { readCredential, readModule, readPolicyGuards, readRevision, readSubject } = credentials;

  const { releaseRegistrationCustody, scrubRegistrationIntent, cleanupRegistrationCustody } =
    registrationCustody;

  const {
    ceremonyStorage,
    col,
    credentialStorage,
    equal,
    existsExact,
    mappedColumns,
    policyStorage,
    profileStorage,
    sameCredential,
    sameRevision,
    semanticCredentialColumns,
    subjectScope,
    targetScope,
  } = state;

  const invariant: (value: unknown) => asserts value = state.invariant;
  const { both } = transactions;

  const assertionPurposes = ["sign-in", "pending", "step-up", "action"] as const;

  const contextPurpose = {
    SignIn: "sign-in",
    Pending: "pending",
    StepUp: "step-up",
    Action: "action",
    Enrollment: "enrollment",
    Registration: "registration",
  } as const;

  const knownSubject = (ceremony: PasskeyCeremony): SubjectId | undefined =>
    "target" in ceremony.context
      ? ceremony.context.target.revision.subjectId
      : ceremony.context._tag === "Enrollment"
        ? ceremony.context.revision.subjectId
        : undefined;

  const compatiblePolicy = (
    ceremony: PasskeyCeremony,
    original: PasskeyMethodPolicy,
    current: PasskeyMethodPolicy,
  ) => {
    const selected = current.profiles.find(
      (profile) => profile.profileId === ceremony.profile.profileId,
    );

    const issued = original.profiles.find(
      (profile) => profile.profileId === ceremony.profile.profileId,
    );

    return (
      ceremony.generation === current.generation &&
      ceremony.generation === original.generation &&
      selected !== undefined &&
      issued !== undefined &&
      profileStorage.encode(selected) === profileStorage.encode(ceremony.profile) &&
      profileStorage.encode(issued) === profileStorage.encode(ceremony.profile) &&
      ceremony.claimLifetimeMillis === original.claimLifetimeMillis &&
      ceremony.expiresAtMillis > ceremony.issuedAtMillis &&
      ceremony.expiresAtMillis <= ceremony.requestBindingExpiresAtMillis &&
      ceremony.expiresAtMillis - ceremony.issuedAtMillis <= original.lifetimeMillis &&
      ceremony.expiresAtMillis - ceremony.issuedAtMillis <= current.lifetimeMillis &&
      ceremony.retentionUntilMillis === ceremony.issuedAtMillis + original.retentionMillis &&
      contextPurpose[ceremony.context._tag] === ceremony.purpose &&
      new Set(ceremony.allowedCredentials.map((item) => item.id)).size ===
        ceremony.allowedCredentials.length
    );
  };

  const liveCondition = (mapping: any, ceremony: PasskeyCeremony, claim?: PasskeyClaim) => {
    const now = mapping.clock.engineNowMillis;

    return both(
      sql`${now} >= ${ceremony.issuedAtMillis}`,
      sql`${now} < ${ceremony.expiresAtMillis}`,
      sql`${now} < ${ceremony.requestBindingExpiresAtMillis}`,
      "target" in ceremony.context
        ? sql`${now} < ${ceremony.context.target.expiresAtMillis}`
        : undefined,
      claim === undefined
        ? undefined
        : both(
            sql`${now} >= ${claim.claimedAtMillis}`,
            sql`${now} < ${claim.claimExpiresAtMillis}`,
          ),
    );
  };

  const matchesAccess = (ceremony: PasskeyCeremony, access: PasskeyAccess) =>
    ceremony.moduleId === access.moduleId &&
    ceremony.generation === access.generation &&
    ceremony.purpose === access.purpose &&
    ceremony.flowId === access.flowId &&
    ceremony.requestBindingVerifier === access.requestBindingVerifier &&
    ceremony.requestBindingExpiresAtMillis === access.requestBindingExpiresAtMillis;

  const decodeFlow = Effect.fn("passkey.decodeFlow")(function* (
    mapping: any,
    flowId: string,
    row: Record<string, any>,
    nowMillis: number,
    conditionHolds?: boolean,
  ) {
    const table = mapping.flow;

    const timing = {
      nowMillis,
      ...(conditionHolds === undefined ? {} : { conditionHolds }),
    };

    const ceremony = ceremonyStorage.decode(row[table.snapshot]);
    const policy = policyStorage.decode(row[table.policySnapshot]);

    const state = Object.keys(table.states).find(
      (name) => table.states[name] === row[table.state],
    ) as PasskeyFlowState | undefined;

    invariant(
      state !== undefined && ceremony.moduleId === mapping.moduleId && ceremony.flowId === flowId,
    );
    invariant(
      row[table.moduleId] === ceremony.moduleId &&
        row[table.flowId] === ceremony.flowId &&
        row[table.commandId] === ceremony.commandId,
    );
    invariant(
      row[table.purpose] === ceremony.purpose && row[table.generation] === ceremony.generation,
    );
    invariant(
      row[table.requestBindingVerifier] === ceremony.requestBindingVerifier &&
        mapping.clock.decodeInstant(row[table.requestBindingExpiresAt]) ===
          ceremony.requestBindingExpiresAtMillis,
    );
    invariant(
      mapping.clock.decodeInstant(row[table.issuedAt]) === ceremony.issuedAtMillis &&
        mapping.clock.decodeInstant(row[table.expiresAt]) === ceremony.expiresAtMillis &&
        mapping.clock.decodeInstant(row[table.retentionUntil]) === ceremony.retentionUntilMillis,
    );
    invariant(compatiblePolicy(ceremony, policy, policy));

    const credential =
      row[table.credentialSnapshot] === null
        ? undefined
        : credentialStorage.decode(row[table.credentialSnapshot]);

    const subject = credential?.revision.subjectId ?? knownSubject(ceremony);

    invariant(
      row[table.subjectScope] === (subject === undefined ? null : yield* subjectScope(subject)) &&
        row[table.targetScope] === (yield* targetScope(ceremony)),
    );
    if (state === "Pending") {
      invariant(
        row[table.claimId] === null &&
          row[table.claimedAt] === null &&
          row[table.claimExpiresAt] === null &&
          credential === undefined,
      );

      return { row, ceremony, policy, state, ...timing };
    }

    const claim =
      row[table.claimId] === null
        ? undefined
        : snapshotPasskeySync(PasskeyClaim, {
            ceremony,
            claimId: row[table.claimId],
            claimedAtMillis: mapping.clock.decodeInstant(row[table.claimedAt]),
            claimExpiresAtMillis: mapping.clock.decodeInstant(row[table.claimExpiresAt]),
          });

    invariant(state !== "Claimed" || claim !== undefined);
    if (claim !== undefined)
      invariant(
        claim.claimExpiresAtMillis ===
          Math.min(claim.claimedAtMillis + ceremony.claimLifetimeMillis, ceremony.expiresAtMillis),
      );

    return {
      row,
      ceremony,
      policy,
      state,
      ...timing,
      ...(claim === undefined ? {} : { claim }),
      ...(credential === undefined ? {} : { credential }),
    };
  });

  const readFlow = Effect.fn("passkey.readFlow")(function* (
    mapping: any,
    flowId: string,
    condition?: SQL,
  ) {
    const owner = yield* CurrentPasskeyTransaction;
    const table = mapping.flow;

    const found = yield* owner.read(
      table.table,
      equal(table.table, {
        [table.moduleId]: mapping.moduleId,
        [table.flowId]: flowId,
      }),
      {
        limit: 1,
        columns: mappedColumns(table),
        clock: mapping.clock,
        ...(condition === undefined ? {} : { condition }),
      },
    );

    const row = found.rows[0];

    if (row === undefined) return undefined;
    invariant(found.nowMillis !== undefined);

    return yield* decodeFlow(mapping, flowId, row, found.nowMillis, found.conditionHolds);
  });

  const terminalFlow = Effect.fn("passkey.terminalFlow")(function* (
    mapping: any,
    read: FlowRead,
    state: "Verified" | "Rejected" | "Ambiguous",
  ) {
    const owner = yield* CurrentPasskeyTransaction;
    const table = mapping.flow;

    yield* owner.update(
      table.table,
      { [table.moduleId]: mapping.moduleId, [table.flowId]: read.ceremony.flowId },
      {
        [table.state]: table.states[state],
        [table.version]: owner.marker,
      },
    );
    owner.postconditions.push(
      yield* existsExact(table.table, {
        [table.moduleId]: mapping.moduleId,
        [table.flowId]: read.ceremony.flowId,
        [table.state]: table.states[state],
        [table.version]: owner.marker,
      }),
    );

    return state;
  });

  const targetRevision = (ceremony: PasskeyCeremony) =>
    "target" in ceremony.context
      ? ceremony.context.target.revision
      : ceremony.context._tag === "Enrollment"
        ? ceremony.context.revision
        : undefined;

  const currentTarget = Effect.fn("passkey.currentTarget")(function* (
    mapping: any,
    subject: SubjectRead | undefined,
    ceremony: PasskeyCeremony,
  ) {
    const target = targetRevision(ceremony);

    if (target === undefined) return true;
    if (
      subject === undefined ||
      subject.subjectId !== target.subjectId ||
      subject.securityRevision !== target.securityRevision
    )
      return false;

    const current = yield* readRevision(
      mapping.read,
      subject,
      target.credentials.map((item) => item.credentialId),
    );

    return current !== undefined && sameRevision(current, target);
  });

  /** The caller owns module, admission, subject and policy locks. Enrollment
   * and registration already acquire them while authorizing their write. */
  const issueFlow = Effect.fn("passkey.issueFlow")(function* (
    mapping: any,
    ceremony: PasskeyCeremony,
    suppliedPolicy: PasskeyMethodPolicy,
    current: PasskeyMethodPolicy,
    subjectId?: SubjectId,
  ) {
    const owner = yield* CurrentPasskeyTransaction;

    if (
      ceremony.moduleId !== mapping.moduleId ||
      !compatiblePolicy(ceremony, suppliedPolicy, current) ||
      policyStorage.encode(suppliedPolicy) !== policyStorage.encode(current)
    )
      return { _tag: "Rejected" } as const;
    if (
      ceremony.context._tag === "SignIn" &&
      (!ceremony.profile.primarySignIn ||
        ceremony.profile.userVerification !== "required" ||
        ceremony.profile.residentKey !== "required")
    )
      return { _tag: "Rejected" } as const;
    const table = mapping.flow;

    const sameIdentity = yield* owner.read(
      table.table,
      both(
        equal(table.table, { [table.moduleId]: mapping.moduleId }),
        or(
          equal(table.table, { [table.commandId]: ceremony.commandId }),
          equal(table.table, { [table.flowId]: ceremony.flowId }),
        ),
      ),
      { limit: 2, columns: [table.moduleId, table.commandId, table.flowId] },
    );

    if (sameIdentity.rows.length !== 0) return { _tag: "Rejected" } as const;
    const kinds = (yield* chargeScopes(ceremony, subjectId)).map((item) => item.kind);

    if (
      !(yield* owner.check(
        both(
          liveCondition(mapping, ceremony),
          yield* admissionCondition(mapping, [current], ceremony, subjectId, kinds, true, false),
        ),
      ))
    )
      return { _tag: "Rejected" } as const;

    const values = {
      ...table.encodeInsert({ ceremony, policy: suppliedPolicy, marker: owner.marker }),
      [table.moduleId]: ceremony.moduleId,
      [table.flowId]: ceremony.flowId,
      [table.commandId]: ceremony.commandId,
      [table.purpose]: ceremony.purpose,
      [table.state]: table.states.Pending,
      [table.version]: owner.marker,
      [table.generation]: ceremony.generation,
      [table.snapshot]: ceremonyStorage.encode(ceremony),
      [table.policySnapshot]: policyStorage.encode(suppliedPolicy),
      [table.requestBindingVerifier]: ceremony.requestBindingVerifier,
      [table.requestBindingExpiresAt]: mapping.clock.encodeInstant(
        ceremony.requestBindingExpiresAtMillis,
      ),
      [table.issuedAt]: mapping.clock.encodeInstant(ceremony.issuedAtMillis),
      [table.expiresAt]: mapping.clock.encodeInstant(ceremony.expiresAtMillis),
      [table.retentionUntil]: mapping.clock.encodeInstant(ceremony.retentionUntilMillis),
      [table.claimId]: null,
      [table.claimedAt]: null,
      [table.claimExpiresAt]: null,
      [table.credentialSnapshot]: null,
      [table.subjectScope]: subjectId === undefined ? null : yield* subjectScope(subjectId),
      [table.targetScope]: yield* targetScope(ceremony),
    };

    // Empty-key observations now expect this exact inserted row as well.
    const inserted = yield* owner.insert(table.table, values, {
      [table.moduleId]: mapping.moduleId,
      [table.flowId]: ceremony.flowId,
    });

    sameIdentity.rows = inserted.rows;
    yield* insertCharges(mapping, ceremony, suppliedPolicy, kinds, subjectId);
    yield* guardChargeSet(mapping, ceremony, subjectId);
    yield* guardAdmission(mapping, [current], ceremony, subjectId);
    owner.postconditions.push(liveCondition(mapping, ceremony));

    return { _tag: "Issued", ceremony } as const;
  });

  const issueAssertion = Effect.fn("passkey.issueAssertion")(function* (
    mapping: any,
    ceremony: PasskeyCeremony,
    suppliedPolicy: PasskeyMethodPolicy,
  ) {
    const current = yield* readModule(mapping);

    if (current === undefined) return { _tag: "Rejected" } as const;
    yield* lockAdmission(mapping);
    const subjectId = knownSubject(ceremony);

    const subject =
      subjectId === undefined ? undefined : yield* readSubject(mapping.read, subjectId);

    yield* readPolicyGuards(mapping);
    if (!(yield* currentTarget(mapping, subject, ceremony))) return { _tag: "Rejected" } as const;

    return yield* issueFlow(mapping, ceremony, suppliedPolicy, current, subjectId);
  });

  const contextAssertion = Effect.fn("passkey.contextAssertion")(function* (
    mapping: any,
    access: PasskeyAccess,
  ) {
    const owner = yield* CurrentPasskeyTransaction;

    if (access.moduleId !== mapping.moduleId) return undefined;
    const current = yield* readModule(mapping);

    if (current === undefined) return undefined;
    yield* readPolicyGuards(mapping);
    const read = yield* readFlow(mapping, access.flowId);

    if (
      read === undefined ||
      read.state !== "Pending" ||
      !matchesAccess(read.ceremony, access) ||
      !compatiblePolicy(read.ceremony, read.policy, current)
    )
      return undefined;
    if (!(yield* owner.check(liveCondition(mapping, read.ceremony)))) return undefined;
    owner.postconditions.push(liveCondition(mapping, read.ceremony));

    return read.ceremony;
  });

  const claimAssertion = Effect.fn("passkey.claimAssertion")(function* (
    mapping: any,
    input: {
      readonly access: PasskeyAccess;
      readonly policy: PasskeyMethodPolicy;
      readonly ceremony: PasskeyCeremony;
      readonly claimId: string;
      readonly credential?: PasskeyCredential;
    },
  ) {
    const owner = yield* CurrentPasskeyTransaction;
    const current = yield* readModule(mapping);

    if (current === undefined || input.access.moduleId !== mapping.moduleId)
      return { _tag: "Rejected" } as const;
    yield* lockAdmission(mapping);
    const expectedSubject = knownSubject(input.ceremony);
    const subjectId = expectedSubject ?? input.credential?.revision.subjectId;

    const subject =
      subjectId === undefined ? undefined : yield* readSubject(mapping.read, subjectId);

    yield* readPolicyGuards(mapping);

    const requested =
      targetRevision(input.ceremony)?.credentials.map((item) => item.credentialId) ??
      input.credential?.revision.credentials.map((item) => item.credentialId);

    const credential =
      input.credential === undefined || subject === undefined
        ? undefined
        : yield* readCredential(
            mapping.read,
            subject,
            input.ceremony.profile.rpId,
            input.credential.protocolCredentialId,
            requested,
          );

    const read = yield* readFlow(
      mapping,
      input.access.flowId,
      liveCondition(mapping, input.ceremony),
    );

    if (
      read === undefined ||
      read.state !== "Pending" ||
      !matchesAccess(read.ceremony, input.access)
    )
      return { _tag: "Rejected" } as const;
    invariant(ceremonyStorage.encode(read.ceremony) === ceremonyStorage.encode(input.ceremony));

    const reject = Effect.gen(function* () {
      yield* terminalFlow(mapping, read, "Rejected");

      return { _tag: "Rejected" } as const;
    });

    if (
      !compatiblePolicy(read.ceremony, read.policy, current) ||
      policyStorage.encode(input.policy) !== policyStorage.encode(current) ||
      !(yield* currentTarget(mapping, subject, read.ceremony))
    )
      return yield* reject;
    if (
      input.credential !== undefined &&
      (credential === undefined || !sameCredential(input.credential, credential.credential))
    )
      return yield* reject;
    if (input.credential !== undefined && credential !== undefined) {
      const original = input.credential.revision;
      const actual = credential.credential.revision;
      const ids = [...new Set([...(requested ?? []), input.credential.credentialId])];

      if (
        original.subjectId !== actual.subjectId ||
        original.securityRevision !== actual.securityRevision ||
        ids.some((id) => {
          const before = original.credentials.find((item) => item.credentialId === id);
          const after = actual.credentials.find((item) => item.credentialId === id);

          // A target can include non-passkey factors absent from the minimum
          // lookup snapshot; currentTarget independently checks those originals.
          return (
            after === undefined ||
            (before === undefined
              ? id === input.credential?.credentialId || targetRevision(read.ceremony) === undefined
              : before.revision !== after.revision)
          );
        })
      )
        return yield* reject;
    }
    if (!read.conditionHolds) return yield* reject;
    yield* readCharges(mapping, read.ceremony, read.policy, expectedSubject);
    const resolved = expectedSubject === undefined && subjectId !== undefined;

    if (
      !(yield* owner.check(
        yield* admissionCondition(
          mapping,
          [read.policy, current],
          read.ceremony,
          subjectId,
          resolved ? ["subject"] : [],
          false,
          resolved,
        ),
      ))
    )
      return yield* reject;
    const claimedAtMillis = read.nowMillis;

    const claim = snapshotPasskeySync(PasskeyClaim, {
      ceremony: read.ceremony,
      claimId: input.claimId,
      claimedAtMillis,
      claimExpiresAtMillis: Math.min(
        claimedAtMillis + read.ceremony.claimLifetimeMillis,
        read.ceremony.expiresAtMillis,
      ),
    });

    const table = mapping.flow;

    yield* owner.update(
      table.table,
      { [table.moduleId]: mapping.moduleId, [table.flowId]: read.ceremony.flowId },
      {
        [table.state]: table.states.Claimed,
        [table.version]: owner.marker,
        [table.claimId]: claim.claimId,
        [table.claimedAt]: mapping.clock.encodeInstant(claim.claimedAtMillis),
        [table.claimExpiresAt]: mapping.clock.encodeInstant(claim.claimExpiresAtMillis),
        [table.credentialSnapshot]:
          input.credential === undefined ? null : credentialStorage.encode(input.credential),
        [table.subjectScope]: subjectId === undefined ? null : yield* subjectScope(subjectId),
      },
    );
    if (resolved) yield* insertCharges(mapping, read.ceremony, read.policy, ["subject"], subjectId);
    yield* guardChargeSet(mapping, read.ceremony, subjectId);
    yield* guardAdmission(mapping, [read.policy, current], read.ceremony, subjectId);
    owner.postconditions.push(liveCondition(mapping, read.ceremony, claim));

    return { _tag: "Claimed", claim } as const;
  });

  const exactClaim = (read: FlowRead, claim: PasskeyClaim) =>
    read.state === "Claimed" &&
    read.claim !== undefined &&
    read.claim.claimId === claim.claimId &&
    read.claim.claimedAtMillis === claim.claimedAtMillis &&
    read.claim.claimExpiresAtMillis === claim.claimExpiresAtMillis &&
    ceremonyStorage.encode(read.ceremony) === ceremonyStorage.encode(claim.ceremony);

  const evidenceMatches = (
    ceremony: PasskeyCeremony,
    captured: PasskeyCredential,
    credential: PasskeyCredential,
    assertion: PasskeyAssertionVerified,
    evidence: typeof PasskeyEvidence.Type,
  ) => {
    const proof = evidence.proofs[0];
    const target = targetRevision(ceremony);
    const original = target ?? captured.revision;

    const ids = [
      ...new Set([
        ...original.credentials.map((item) => item.credentialId),
        credential.credentialId,
      ]),
    ];

    const expected = {
      ...credential.revision,
      credentials: credential.revision.credentials.filter((item) =>
        ids.includes(item.credentialId),
      ),
    };

    const selected = captured.revision.credentials.find(
      (item) => item.credentialId === credential.credentialId,
    );

    return (
      evidence.proofs.length === 1 &&
      proof !== undefined &&
      proof.method === "passkey" &&
      proof.credentialId === credential.credentialId &&
      proof.factors.length === 1 &&
      proof.factors[0] === "possession" &&
      proof.userVerified === assertion.userVerified &&
      proof.phishingResistant &&
      DateTime.toEpochMillis(proof.verifiedAt) === ceremony.issuedAtMillis &&
      evidence.flowId ===
        ("target" in ceremony.context ? ceremony.context.target.flowId : ceremony.flowId) &&
      evidence.bindingDigest ===
        ("target" in ceremony.context
          ? ceremony.context.target.bindingDigest
          : ceremony.requestBindingVerifier) &&
      expected.credentials.length === ids.length &&
      sameRevision(evidence.revision, expected) &&
      original.subjectId === expected.subjectId &&
      original.securityRevision === expected.securityRevision &&
      original.credentials.every((item) =>
        expected.credentials.some(
          (current) =>
            current.credentialId === item.credentialId && current.revision === item.revision,
        ),
      ) &&
      selected !== undefined &&
      expected.credentials.some(
        (item) =>
          item.credentialId === selected.credentialId && item.revision === selected.revision,
      )
    );
  };

  const updateTelemetry = Effect.fn("passkey.updateTelemetry")(function* (
    mapping: any,
    found: CredentialRead,
    assertion: PasskeyAssertionVerified,
    dialect: "pg" | "mysql" | "sqlite",
  ) {
    const owner = yield* CurrentPasskeyTransaction;
    const table = mapping.read.credential;
    const counter = sql`${col(table.table, table.counter)}`;
    const maximum = sql`${col(table.table, table.maximumCounter)}`;

    const max = (...values: ReadonlyArray<ReturnType<QueryOperations["sql"]>>) =>
      dialect === "sqlite"
        ? sql`max(${sql.join([...values], sql`, `)})`
        : sql`greatest(${sql.join([...values], sql`, `)})`;

    const semantic = Object.fromEntries(
      semanticCredentialColumns(table).map((column) => [column, found.row[column]]),
    );

    const bs = mapping.telemetry.encodeBackupState(assertion.backupState);
    const synced = found.credential.backupEligible;
    const merged = max(counter, maximum, sql`${assertion.counter}`);

    const currentCounter = synced
      ? sql`1 = 1`
      : sql`((${counter} = 0 and ${assertion.counter} = 0) or ${counter} < ${assertion.counter})`;

    yield* owner.updateGuarded(
      table.table,
      both(owner.exact(table.table, semantic), table.activeCondition, currentCounter),
      {
        [table.counter]: synced ? merged : assertion.counter,
        [table.maximumCounter]: merged,
        [table.backupState]: bs,
      },
      {
        rows: 1,
        postcondition: yield* existsExact(
          table.table,
          { ...semantic, [table.backupState]: bs },
          both(
            synced ? sql`${counter} = ${maximum}` : sql`${counter} = ${assertion.counter}`,
            sql`${maximum} >= ${assertion.counter}`,
          ),
        ),
      },
    );
    const earliest = yield* owner.now(mapping.clock);
    const lastUsed = sql`${col(table.table, mapping.telemetry.lastUsedAt)}`;
    const millis = mapping.clock.toMillis(lastUsed);

    yield* owner.finalUpdate(
      table.table,
      owner.exact(table.table, semantic),
      {
        [mapping.telemetry.lastUsedAt]: mapping.clock.fromMillis(
          max(sql`coalesce(${millis}, 0)`, mapping.clock.engineNowMillis),
        ),
      },
      {
        rows: 1,
        postcondition: yield* existsExact(
          table.table,
          semantic,
          both(sql`${millis} >= ${earliest}`, sql`${millis} <= ${mapping.clock.engineNowMillis}`),
        ),
      },
    );
  });

  const settleAssertion = Effect.fn("passkey.settleAssertion")(function* (
    mapping: any,
    claim: PasskeyClaim,
    outcome:
      | { readonly _tag: "Rejected" | "Ambiguous" }
      | {
          readonly _tag: "Assertion";
          readonly credential: PasskeyCredential;
          readonly assertion: PasskeyAssertionVerified;
          readonly evidence: typeof PasskeyEvidence.Type;
        },
    dialect: "pg" | "mysql" | "sqlite",
  ) {
    const owner = yield* CurrentPasskeyTransaction;
    const assertedCredential = outcome._tag === "Assertion" ? outcome.credential : undefined;
    const current = yield* readModule(mapping);

    if (current === undefined || claim.ceremony.moduleId !== mapping.moduleId)
      return "Rejected" as const;
    yield* lockAdmission(mapping);

    const originalIds =
      targetRevision(claim.ceremony)?.credentials.map((item) => item.credentialId) ??
      (outcome._tag === "Assertion"
        ? outcome.credential.revision.credentials.map((item) => item.credentialId)
        : undefined);

    const subjectId =
      outcome._tag === "Assertion"
        ? outcome.credential.revision.subjectId
        : knownSubject(claim.ceremony);

    const subject =
      subjectId === undefined ? undefined : yield* readSubject(mapping.read, subjectId);

    yield* readPolicyGuards(mapping);

    const found =
      outcome._tag !== "Assertion" || subject === undefined
        ? undefined
        : yield* readCredential(
            mapping.read,
            subject,
            claim.ceremony.profile.rpId,
            outcome.credential.protocolCredentialId,
            originalIds,
          );

    const read = yield* readFlow(mapping, claim.ceremony.flowId);

    if (read === undefined || !exactClaim(read, claim)) return "Rejected" as const;
    if (outcome._tag !== "Assertion") return yield* terminalFlow(mapping, read, outcome._tag);
    invariant(assertedCredential !== undefined);
    const captured = "credential" in read ? read.credential : undefined;
    const assertion = outcome.assertion;

    if (
      captured === undefined ||
      found === undefined ||
      !compatiblePolicy(read.ceremony, read.policy, current) ||
      !sameCredential(captured, assertedCredential) ||
      !sameCredential(captured, found.credential)
    )
      return yield* terminalFlow(mapping, read, "Rejected");
    const credential = found.credential;
    const profile = read.ceremony.profile;

    if (
      assertion.protocolCredentialId !== credential.protocolCredentialId ||
      (assertion.userHandle !== undefined && assertion.userHandle !== credential.userHandle) ||
      assertion.backupEligible !== credential.backupEligible ||
      (assertion.backupState && !assertion.backupEligible) ||
      (profile.userVerification === "required" && !assertion.userVerified) ||
      !profile.algorithms.includes(credential.algorithm) ||
      (read.ceremony.allowedCredentials.length !== 0 &&
        !read.ceremony.allowedCredentials.some(
          (item) => item.id === credential.protocolCredentialId,
        )) ||
      (read.ceremony.purpose === "sign-in" &&
        (assertion.userHandle !== credential.userHandle ||
          !credential.primarySignIn ||
          !credential.enrollmentUserVerified ||
          !credential.profile.primarySignIn ||
          credential.profile.userVerification !== "required" ||
          !assertion.userVerified)) ||
      !evidenceMatches(read.ceremony, captured, credential, assertion, outcome.evidence) ||
      !(yield* owner.check(liveCondition(mapping, read.ceremony, claim)))
    )
      return yield* terminalFlow(mapping, read, "Rejected");
    yield* readCharges(mapping, read.ceremony, read.policy, credential.revision.subjectId);
    yield* guardChargeSet(mapping, read.ceremony, credential.revision.subjectId);
    yield* updateTelemetry(mapping, found, assertion, dialect);
    yield* terminalFlow(mapping, read, "Verified");
    owner.postconditions.push(liveCondition(mapping, read.ceremony, claim));

    return "Verified" as const;
  });

  const purposeCondition = (table: any, purposes: ReadonlyArray<string>) =>
    sql`${col(table.table, table.purpose)} in (${sql.join(
      purposes.map((purpose) => sql`${purpose}`),
      sql`, `,
    )})`;

  const custodyFree = (mapping: any, flowExpression: ReturnType<QueryOperations["sql"]>) => {
    if (mapping.intent === undefined) return sql`1 = 1`;
    const intent = mapping.intent;

    return sql`not exists (select 1 from ${intent.table} where ${both(
      equal(intent.table, { [intent.moduleId]: mapping.moduleId }),
      sql`${col(intent.table, intent.flowId)} = ${flowExpression}`,
      intent.custodyCondition,
    )})`;
  };

  const flowDue = (mapping: any, purposes: ReadonlyArray<string>) => {
    const flow = mapping.flow,
      charge = mapping.charge,
      now = mapping.clock.engineNowMillis;

    const state = sql`${col(flow.table, flow.state)}`;
    const retained = sql`${mapping.clock.toMillis(sql`${col(flow.table, flow.retentionUntil)}`)} <= ${now}`;

    const chargeLive = sql`exists (select 1 from ${charge.table} where ${both(
      equal(charge.table, { [charge.moduleId]: mapping.moduleId }),
      sql`${col(charge.table, charge.flowId)} = ${col(flow.table, flow.flowId)}`,
      sql`(${col(charge.table, charge.retainUntil)} is null or ${mapping.clock.toMillis(sql`${col(charge.table, charge.retainUntil)}`)} > ${now})`,
    )})`;

    return both(
      equal(flow.table, { [flow.moduleId]: mapping.moduleId }),
      purposeCondition(flow, purposes),
      sql`((${state} = ${flow.states.Pending} and ${mapping.clock.toMillis(sql`${col(flow.table, flow.expiresAt)}`)} <= ${now}) or
        (${state} = ${flow.states.Claimed} and ${mapping.clock.toMillis(sql`${col(flow.table, flow.claimExpiresAt)}`)} <= ${now}) or
        (${state} in (${flow.states.Verified}, ${flow.states.Rejected}, ${flow.states.Ambiguous}, ${flow.states.RegistrationAccepted}) and ${retained} and not (${chargeLive}) and ${custodyFree(mapping, sql`${col(flow.table, flow.flowId)}`)}))`,
    );
  };

  const chargeDue = (mapping: any, purposes: ReadonlyArray<string>) => {
    const charge = mapping.charge;

    return both(
      equal(charge.table, { [charge.moduleId]: mapping.moduleId }),
      purposeCondition(charge, purposes),
      sql`${col(charge.table, charge.admittedAt)} is not null and ${mapping.clock.toMillis(sql`${col(charge.table, charge.retainUntil)}`)} <= ${mapping.clock.engineNowMillis}`,
      custodyFree(mapping, sql`${col(charge.table, charge.flowId)}`),
    );
  };

  /** Flow transitions and row removals share one bound. Prepared hasMore is
   * predicted from this owner's staged changes, then asserted after final writes. */
  const cleanupCeremonies = Effect.fn("passkey.cleanupCeremonies")(function* (
    mapping: any,
    input: { readonly moduleId: string; readonly nowMillis: number; readonly limit: number },
    purposes: ReadonlyArray<string>,
  ) {
    const owner = yield* CurrentPasskeyTransaction;

    invariant(
      input.moduleId === mapping.moduleId &&
        Number.isSafeInteger(input.nowMillis) &&
        input.nowMillis >= 0 &&
        Number.isSafeInteger(input.limit) &&
        input.limit >= 1 &&
        input.limit <= 1000,
    );
    yield* readModule(mapping);
    yield* lockAdmission(mapping);
    yield* readPolicyGuards(mapping);

    const flow = mapping.flow,
      charge = mapping.charge;

    const flowChunkSize = Math.max(1, Math.min(1000, owner.maxParameters - 32));
    const chargeChunkSize = Math.max(1, Math.min(1000, Math.floor((owner.maxParameters - 1) / 2)));

    type CleanupRow = Record<string, any>;

    const flowIdentity = (rows: ReadonlyArray<CleanupRow>) =>
      rows.length === 0
        ? sql`1 = 0`
        : both(
            equal(flow.table, { [flow.moduleId]: mapping.moduleId }),
            operations.inArray(
              col(flow.table, flow.flowId),
              rows.map((row) => row[flow.flowId]),
            ),
          );

    const chargeIdentity = (rows: ReadonlyArray<CleanupRow>) =>
      rows.length === 0
        ? sql`1 = 0`
        : both(
            equal(charge.table, { [charge.moduleId]: mapping.moduleId }),
            sql`(${col(charge.table, charge.flowId)}, ${col(charge.table, charge.kind)}) in (${sql.join(
              rows.map(
                (row) =>
                  sql`(${sql.param(row[charge.flowId], col(charge.table, charge.flowId))}, ${sql.param(row[charge.kind], col(charge.table, charge.kind))})`,
              ),
              sql`, `,
            )})`,
          );

    // Reusing a small identity set keeps each D1 exact-row guard bounded, even
    // when the caller selects the maximum 1,000 rows. This does not reread SQL.
    const observeRows = Effect.fnUntraced(function* (
      table: any,
      rows: ReadonlyArray<CleanupRow>,
      identity: (rows: ReadonlyArray<CleanupRow>) => SQL,
    ) {
      const observations = [];

      for (let offset = 0; offset < rows.length; offset += 16) {
        const group = rows.slice(offset, offset + 16);

        observations.push(yield* owner.observe(table, identity(group), group));
      }

      return observations;
    });

    const selected = yield* owner.read(flow.table, flowDue(mapping, purposes), {
      limit: input.limit,
      takeOnly: true,
      observe: false,
      columns: mappedColumns(flow),
      clock: mapping.clock,
      orderBy: sql`${col(flow.table, flow.flowId)}`,
    });

    const transitioned: FlowRead[] = [];
    const deleted: FlowRead[] = [];
    const flowObservations = yield* observeRows(flow.table, selected.rows, flowIdentity);
    let horizon = 0;

    if (selected.rows.length > 0) {
      invariant(selected.nowMillis !== undefined);
      for (const rows of Array.chunksOf(selected.rows, flowChunkSize))
        invariant(
          yield* owner.check(
            sql`not exists (select 1 from ${flow.table} where ${both(
              flowIdentity(rows),
              sql`not (${flowDue(mapping, purposes)})`,
            )})`,
          ),
        );
      for (const row of selected.rows) {
        const read = yield* decodeFlow(mapping, row[flow.flowId], row, selected.nowMillis);

        if (read.state === "Pending" || read.state === "Claimed") {
          if (owner.batch && read.state === "Pending")
            yield* releaseRegistrationCustody(mapping, read.ceremony);
          horizon = Math.max(
            horizon,
            read.state === "Pending"
              ? read.ceremony.expiresAtMillis
              : read.claim!.claimExpiresAtMillis,
          );
          transitioned.push(read);
        } else {
          if (owner.batch) yield* scrubRegistrationIntent(mapping, read.ceremony);
          horizon = Math.max(horizon, read.ceremony.retentionUntilMillis);
          owner.postconditions.push(
            custodyFree(mapping, sql`${read.ceremony.flowId}`),
            sql`not exists (select 1 from ${charge.table} where ${both(
              equal(charge.table, {
                [charge.moduleId]: mapping.moduleId,
                [charge.flowId]: read.ceremony.flowId,
              }),
              sql`(${col(charge.table, charge.retainUntil)} is null or ${mapping.clock.toMillis(sql`${col(charge.table, charge.retainUntil)}`)} > ${mapping.clock.engineNowMillis})`,
            )})`,
          );
          deleted.push(read);
        }
      }
    }

    if (!owner.batch)
      yield* cleanupRegistrationCustody(
        mapping,
        transitioned.filter((read) => read.state === "Pending").map((read) => read.ceremony),
        deleted.map((read) => read.ceremony),
      );

    for (const rows of Array.chunksOf(transitioned, flowChunkSize)) {
      const stateColumn = col(flow.table, flow.state);

      yield* owner.write(
        owner.database
          .update(flow.table)
          .set({
            [flow.state]: sql`case when ${stateColumn} = ${sql.param(flow.states.Pending, stateColumn)} then ${sql.param(flow.states.Rejected, stateColumn)} else ${sql.param(flow.states.Ambiguous, stateColumn)} end`,
            [flow.version]: owner.marker,
          })
          .where(flowIdentity(rows.map((read) => read.row))),
      );
    }
    for (const rows of Array.chunksOf(deleted, flowChunkSize))
      yield* owner.write(
        owner.database.delete(flow.table).where(flowIdentity(rows.map((read) => read.row))),
      );

    const expected = new Map(
      transitioned.map((read) => [
        read.ceremony.flowId,
        {
          ...read.row,
          [flow.state]: read.state === "Pending" ? flow.states.Rejected : flow.states.Ambiguous,
          [flow.version]: owner.marker,
        },
      ]),
    );

    for (const observation of flowObservations)
      observation.rows = observation.rows.flatMap((row) => {
        const next = expected.get(row[flow.flowId]);

        return next === undefined ? [] : [next];
      });

    let removedCharges: ReadonlyArray<CleanupRow> = [];
    const remaining = input.limit - selected.rows.length;

    if (remaining > 0) {
      const charges = (yield* owner.read(charge.table, chargeDue(mapping, purposes), {
        limit: remaining,
        takeOnly: true,
        observe: false,
        orderBy: sql`${col(charge.table, charge.flowId)}, ${col(charge.table, charge.kind)}`,
      })).rows;

      const observations = yield* observeRows(charge.table, charges, chargeIdentity);

      for (const row of charges) {
        const until = mapping.clock.decodeInstant(row[charge.retainUntil]);

        invariant(Number.isSafeInteger(until));
        horizon = Math.max(horizon, until);
        owner.postconditions.push(custodyFree(mapping, sql`${row[charge.flowId]}`));
      }
      for (const rows of Array.chunksOf(charges, chargeChunkSize))
        yield* owner.write(owner.database.delete(charge.table).where(chargeIdentity(rows)));
      for (const observation of observations) observation.rows = [];
      removedCharges = charges;
    }
    if (selected.rows.length > 0 || removedCharges.length > 0)
      owner.postconditions.push(sql`${mapping.clock.engineNowMillis} >= ${horizon}`);

    const actual = sql`exists (select 1 from ${flow.table} where ${flowDue(mapping, purposes)}) or exists (select 1 from ${charge.table} where ${chargeDue(mapping, purposes)})`;
    let hasMore: boolean;

    if (!owner.batch) {
      hasMore = yield* owner.check(actual);
    } else {
      const excludeCharges = sql`not (${chargeIdentity(removedCharges)})`;
      const predicted = sql`exists (select 1 from ${flow.table} where ${both(flowDue(mapping, purposes), sql`not (${flowIdentity(selected.rows)})`)}) or exists (select 1 from ${charge.table} where ${both(chargeDue(mapping, purposes), excludeCharges)})`;

      hasMore = yield* owner.check(predicted);
      if (!hasMore && transitioned.length > 0 && mapping.intent === undefined) {
        // These rows will be terminal, but this batch must not also delete them.
        // Include indefinite charges just as flowDue does for retained terminals.
        const transitionedDue = sql`exists (select 1 from ${flow.table} where ${both(
          flowIdentity(transitioned.map((read) => read.row)),
          sql`${mapping.clock.toMillis(sql`${col(flow.table, flow.retentionUntil)}`)} <= ${mapping.clock.engineNowMillis}`,
          sql`not exists (select 1 from ${charge.table} where ${both(
            equal(charge.table, { [charge.moduleId]: mapping.moduleId }),
            sql`${col(charge.table, charge.flowId)} = ${col(flow.table, flow.flowId)}`,
            sql`(${col(charge.table, charge.retainUntil)} is null or ${mapping.clock.toMillis(sql`${col(charge.table, charge.retainUntil)}`)} > ${mapping.clock.engineNowMillis})`,
            excludeCharges,
          )})`,
        )})`;

        hasMore = yield* owner.check(transitionedDue);
      } else if (!hasMore && mapping.intent !== undefined) {
        // Registration custody is mapping-owned; retain its per-flow prediction.
        for (const read of transitioned) {
          if (read.ceremony.retentionUntilMillis > read.nowMillis) continue;

          const liveCharges = sql`exists (select 1 from ${charge.table} where ${both(
            equal(charge.table, {
              [charge.moduleId]: mapping.moduleId,
              [charge.flowId]: read.ceremony.flowId,
            }),
            sql`(${col(charge.table, charge.retainUntil)} is null or ${mapping.clock.toMillis(sql`${col(charge.table, charge.retainUntil)}`)} > ${mapping.clock.engineNowMillis})`,
            excludeCharges,
          )})`;

          if (
            !(yield* owner.check(liveCharges)) &&
            (yield* owner.check(custodyFree(mapping, sql`${read.ceremony.flowId}`)))
          )
            hasMore = true;
        }
      }
    }
    owner.postconditions.push(hasMore ? actual : sql`not (${actual})`);

    return {
      terminalized: transitioned.length,
      removed: deleted.length + removedCharges.length,
      hasMore,
    };
  });

  return {
    assertionPurposes,
    contextPurpose,
    knownSubject,
    compatiblePolicy,
    liveCondition,
    matchesAccess,
    readFlow,
    terminalFlow,
    issueFlow,
    issueAssertion,
    contextAssertion,
    claimAssertion,
    exactClaim,
    settleAssertion,
    cleanupCeremonies,
  };
};
