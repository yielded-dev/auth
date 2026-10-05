/* oxlint-disable no-explicit-any -- existing mapped-row bridge; public adapters preserve table, ID, and Effect types. */

import {
  type PasskeyCeremony,
  PasskeyCeremony as Ceremony,
  type PasskeyManagementPersistence,
} from "@yielded/auth/Passkey";
import { Effect } from "effect";

import type { QueryOperations } from "../query-operations";
import type { makeTransactionKernel, Observation, TransactionRead } from "../transaction-kernel";
import type { makePasskeyAdmissionKernel } from "./admission";
import type { makePasskeyCredentialsKernel } from "./credentials";
import type { makePasskeyFlowKernel } from "./flow";
import { CurrentPasskeyTransaction } from "./state";
import type { makePasskeyStateKernel } from "./state";
import type { WriteSubject, makePasskeyWriteStateKernel } from "./write-state";

type Issue = Parameters<PasskeyManagementPersistence["Service"]["issueEnrollment"]>[0];

type Complete = Parameters<PasskeyManagementPersistence["Service"]["completeEnrollment"]>[0];

export const makePasskeyEnrollmentKernel = (
  operations: QueryOperations,
  admission: Pick<
    ReturnType<typeof makePasskeyAdmissionKernel>,
    "lockAdmission" | "readCharges" | "guardChargeSet" | "admissionRead" | "chargeRead"
  >,
  credentials: Pick<
    ReturnType<typeof makePasskeyCredentialsKernel>,
    "readModule" | "readPolicyGuards" | "moduleRead" | "policyReads"
  >,
  flow: Pick<
    ReturnType<typeof makePasskeyFlowKernel>,
    | "compatiblePolicy"
    | "exactClaim"
    | "issueFlow"
    | "liveCondition"
    | "readFlow"
    | "terminalFlow"
    | "flowRead"
    | "issueRead"
    | "issueCondition"
  >,
  state: Pick<
    ReturnType<typeof makePasskeyStateKernel>,
    "equal" | "handleKey" | "invariant" | "sameRevision" | "credentialKey"
  >,
  writeState: Pick<
    ReturnType<typeof makePasskeyWriteStateKernel>,
    | "authorizeAction"
    | "credentialRead"
    | "currentSubject"
    | "currentSubjectReads"
    | "enrollmentDigest"
    | "digest"
    | "insertCredential"
    | "managementPolicy"
    | "validRegistration"
  >,
  transactions: Pick<ReturnType<typeof makeTransactionKernel>, "both">,
) => {
  const { or, sql } = operations;
  const { lockAdmission, readCharges, guardChargeSet, admissionRead, chargeRead } = admission;
  const { readModule, readPolicyGuards, moduleRead, policyReads } = credentials;

  const {
    compatiblePolicy,
    exactClaim,
    issueFlow,
    liveCondition,
    readFlow,
    terminalFlow,
    flowRead,
    issueRead,
    issueCondition,
  } = flow;

  const { equal, handleKey, sameRevision, credentialKey: credentialKeyFor } = state;
  const invariant: (value: unknown) => asserts value = state.invariant;

  const {
    authorizeAction,
    credentialRead,
    currentSubject,
    currentSubjectReads,
    enrollmentDigest,
    digest,
    insertCredential,
    managementPolicy,
    validRegistration,
  } = writeState;

  const { both } = transactions;

  const handleRead = (
    mapping: any,
    nativeId: unknown,
    ceremony: PasskeyCeremony,
    hashed: string,
  ): TransactionRead => {
    const table = mapping.read.handleOwnership;

    return {
      table: table.table,
      where: or(
        equal(table.table, { [table.rpId]: ceremony.profile.rpId, [table.subjectId]: nativeId }),
        equal(table.table, { [table.handleKey]: hashed }),
      )!,
      options: { limit: 2 },
    };
  };

  const enrollmentHandle = Effect.fn("passkey.enrollmentHandle")(function* (
    mapping: any,
    subject: WriteSubject,
    ceremony: PasskeyCeremony,
    create: boolean,
    captured?: Observation,
  ) {
    const owner = yield* CurrentPasskeyTransaction;

    invariant(ceremony.context._tag === "Enrollment");
    const table = mapping.read.handleOwnership;

    const hashed = yield* handleKey(ceremony.profile.rpId, ceremony.context.userHandle);
    const request = handleRead(mapping, subject.nativeId, ceremony, hashed);
    const found = captured ?? (yield* owner.read(request.table, request.where, request.options));
    const row = found.rows[0];

    if (row !== undefined)
      return (
        found.rows.length === 1 &&
        row[table.rpId] === ceremony.profile.rpId &&
        table.isOwnedState(row[table.state]) &&
        row[table.handleKey] === hashed &&
        row[table.userHandle] === ceremony.context.userHandle &&
        mapping.read.subjectIds.equals(table.decodeSubjectId(row), subject.nativeId)
      );
    if (!create) return false;

    const inserted = yield* owner.insert(
      table.table,
      {
        ...mapping.write.handleOwnership.encodeInsert({
          subjectId: subject.nativeId,
          rpId: ceremony.profile.rpId,
          userHandle: ceremony.context.userHandle,
          marker: owner.marker,
        }),
        [table.handleKey]: hashed,
        [table.rpId]: ceremony.profile.rpId,
        [table.userHandle]: ceremony.context.userHandle,
        [table.subjectId]: subject.nativeId,
        [table.state]: mapping.write.handleOwnership.ownedState,
        [table.version]: owner.marker,
        [table.reservationId]: null,
      },
      { [table.handleKey]: hashed },
    );

    found.rows = inserted.rows;

    return true;
  });

  const capCondition = (mapping: any, subject: WriteSubject, maximum: number, addition: number) => {
    const table = mapping.read.credential;

    return sql`(select count(*) from ${table.table} where ${both(equal(table.table, { [table.subjectId]: subject.nativeId }), table.activeCondition)}) + ${addition} <= ${maximum}`;
  };

  const issueEnrollment = Effect.fn("passkey.issueEnrollment")(function* (
    mapping: any,
    input: Issue,
  ) {
    const owner = yield* CurrentPasskeyTransaction;
    const ceremony = input.ceremony;

    if (
      ceremony.context._tag !== "Enrollment" ||
      ceremony.purpose !== "enrollment" ||
      ceremony.moduleId !== mapping.moduleId
    )
      return { _tag: "Rejected" } as const;
    const subjectId = ceremony.context.revision.subjectId;
    const nativeId = mapping.read.subjectIds.toNative(subjectId);

    const [module, admitted, subjectRows, factors, credentialRows, identity, handle, ...guards] =
      yield* owner.readMany([
        moduleRead(mapping, {
          admitted: yield* issueCondition(mapping, ceremony, input.policy, subjectId),
        }),
        admissionRead(mapping),
        ...currentSubjectReads(
          mapping,
          subjectId,
          mapping.write.policy.action(nativeId, input.authorization),
        ),
        credentialRead(mapping, nativeId),
        issueRead(mapping, ceremony),
        handleRead(
          mapping,
          nativeId,
          ceremony,
          yield* handleKey(ceremony.profile.rpId, ceremony.context.userHandle),
        ),
        ...policyReads(mapping),
      ]);

    const current = yield* readModule(mapping, module!);

    if (current === undefined || !compatiblePolicy(ceremony, input.policy, current))
      return { _tag: "Rejected" } as const;
    yield* lockAdmission(mapping, admitted!);
    const subject = yield* currentSubject(mapping, subjectId, [subjectRows!, factors!]);

    if (subject === undefined || !sameRevision(subject.revision, ceremony.context.revision))
      return { _tag: "Rejected" } as const;
    yield* readPolicyGuards(mapping, guards);
    const policy = managementPolicy(mapping, subject);
    const maximum = Math.min(policy.maximumCredentials, input.management.maximumCredentials);

    const rows = credentialRows!.rows.filter(
      (row) => row[mapping.read.credential.rpId] === ceremony.profile.rpId,
    );

    const ids = rows.map((row) => row[mapping.read.credential.protocolCredentialId]);

    if (
      ids.length !== ceremony.allowedCredentials.length ||
      !ids.every((id) => ceremony.allowedCredentials.some((item) => item.id === id)) ||
      credentialRows!.rows.length + 1 > maximum
    )
      return { _tag: "Rejected" } as const;
    if (
      !(yield* authorizeAction(
        mapping,
        subject,
        input.authorization,
        {
          action: "enroll-begin",
          commandId: ceremony.commandId,
          flowId: ceremony.flowId,
          bindingDigest: yield* enrollmentDigest(ceremony),
          revision: ceremony.context.revision,
        },
        {
          ...policy,
          maximumEvidenceAgeMillis: Math.min(
            policy.maximumEvidenceAgeMillis,
            input.management.maximumEvidenceAgeMillis,
          ),
        },
        undefined,
        true,
      ))
    )
      return { _tag: "Rejected" } as const;
    invariant(
      (yield* digest(Ceremony.fields.context, ceremony.context)) ===
        (yield* digest(Ceremony.fields.context, {
          ...ceremony.context,
          authorization: input.authorization,
        })),
    );

    const issued = yield* issueFlow(mapping, ceremony, input.policy, current, subject.subjectId, {
      identity: identity!,
      admitted: module!.checks!.admitted!,
    });

    if (issued._tag !== "Issued") return issued;
    invariant(yield* enrollmentHandle(mapping, subject, ceremony, true, handle!));
    owner.postconditions.push(capCondition(mapping, subject, maximum, 1));

    return issued;
  });

  const completeEnrollment = Effect.fn("passkey.completeEnrollment")(function* (
    mapping: any,
    input: Complete,
  ) {
    const owner = yield* CurrentPasskeyTransaction;
    const ceremony = input.claim.ceremony;

    if (
      ceremony.context._tag !== "Enrollment" ||
      ceremony.purpose !== "enrollment" ||
      ceremony.moduleId !== mapping.moduleId
    )
      return { _tag: "Rejected" } as const;
    const subjectId = ceremony.context.revision.subjectId;
    const nativeId = mapping.read.subjectIds.toNative(subjectId);
    const tuple = mapping.read.credentialOwnership;
    const key = yield* credentialKeyFor(ceremony.profile.rpId, input.verified.protocolCredentialId);

    const [
      module,
      admitted,
      subjectRows,
      factors,
      capturedFlow,
      handle,
      absent,
      charges,
      credentialRows,
      ...guards
    ] = yield* owner.readMany([
      moduleRead(mapping),
      admissionRead(mapping),
      ...currentSubjectReads(
        mapping,
        subjectId,
        mapping.write.policy.action(nativeId, input.authorization),
      ),
      flowRead(mapping, ceremony.flowId, liveCondition(mapping, ceremony, input.claim)),
      handleRead(
        mapping,
        nativeId,
        ceremony,
        yield* handleKey(ceremony.profile.rpId, ceremony.context.userHandle),
      ),
      {
        table: tuple.table,
        where: equal(tuple.table, { [tuple.credentialKey]: key }),
        options: { limit: 1 },
      },
      chargeRead(mapping, ceremony),
      credentialRead(mapping, nativeId),
      ...policyReads(mapping),
    ]);

    const current = yield* readModule(mapping, module!);

    if (current === undefined) return { _tag: "Rejected" } as const;
    yield* lockAdmission(mapping, admitted!);
    const subject = yield* currentSubject(mapping, subjectId, [subjectRows!, factors!]);

    yield* readPolicyGuards(mapping, guards);

    const read = yield* readFlow(
      mapping,
      ceremony.flowId,
      liveCondition(mapping, ceremony, input.claim),
      capturedFlow!,
    );

    if (read === undefined || !exactClaim(read, input.claim)) return { _tag: "Rejected" } as const;

    const reject = Effect.gen(function* () {
      yield* terminalFlow(mapping, read, "Rejected");

      return { _tag: "Rejected" } as const;
    });

    if (
      subject === undefined ||
      !sameRevision(subject.revision, ceremony.context.revision) ||
      !compatiblePolicy(ceremony, read.policy, current) ||
      !validRegistration(ceremony, input.verified) ||
      !read.conditionHolds
    )
      return yield* reject;
    const policy = managementPolicy(mapping, subject);
    const maximum = Math.min(policy.maximumCredentials, input.management.maximumCredentials);

    if (
      credentialRows!.rows.length + 1 > maximum ||
      !(yield* enrollmentHandle(mapping, subject, ceremony, false, handle!))
    )
      return yield* reject;
    if (
      !(yield* authorizeAction(
        mapping,
        subject,
        input.authorization,
        {
          action: "enroll-complete",
          commandId: ceremony.commandId,
          flowId: ceremony.flowId,
          bindingDigest: yield* digest(Ceremony, ceremony),
          revision: ceremony.context.revision,
        },
        {
          ...policy,
          maximumEvidenceAgeMillis: Math.min(
            policy.maximumEvidenceAgeMillis,
            input.management.maximumEvidenceAgeMillis,
          ),
        },
        ceremony.context.authorization.requirement,
        true,
      ))
    )
      return yield* reject;
    if (absent!.rows.length !== 0) return yield* reject;
    yield* readCharges(mapping, ceremony, read.policy, subject.subjectId, charges!);
    yield* guardChargeSet(mapping, ceremony, subject.subjectId);

    const safe = yield* insertCredential(
      mapping,
      subject,
      ceremony,
      input.verified,
      read.nowMillis,
      absent!,
    );

    yield* terminalFlow(mapping, read, "Verified");
    owner.postconditions.push(
      liveCondition(mapping, ceremony, input.claim),
      capCondition(mapping, subject, maximum, 0),
    );

    return { _tag: "Enrolled", credential: safe } as const;
  });

  return { enrollmentHandle, issueEnrollment, completeEnrollment };
};
