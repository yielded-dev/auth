/* oxlint-disable no-explicit-any -- existing mapped-row bridge; public adapters preserve table, ID, and Effect types. */

import {
  PasskeyConfigurationError,
  PasskeyUnavailable,
  PasskeyCeremony,
  PasskeyCredential,
  PasskeyModuleId,
  PasskeyProfile,
  PasskeyRevision,
  PasskeyMethodPolicy,
  snapshotPasskeySync,
} from "@yielded/auth/Passkey";
import { Context, Crypto, Effect, Schema } from "effect";

import { randomId } from "../crypto";
import {
  requiredPasskeyCredentialConstraints,
  requiredPasskeyPersistenceConstraints,
} from "../models/passkey-model";
import { requiredPasskeyRegistrationCeremonyConstraints } from "../models/passkey-registration-ceremony-model";
import type { SqlExpression as SQL, QueryOperations } from "../query-operations";
import type { TransactionOwner, makeTransactionKernel } from "../transaction-kernel";

export type PasskeyOwner = TransactionOwner<PasskeyUnavailable>;

export class CurrentPasskeyTransaction extends Context.Service<
  CurrentPasskeyTransaction,
  PasskeyOwner
>()("effect-auth/drizzle/CurrentPasskeyTransaction") {}

export const makePasskeyStateKernel = (
  operations: QueryOperations,
  transactions: Pick<ReturnType<typeof makeTransactionKernel>, "both" | "makeTransactionRows">,
) => {
  const { getTableColumns, sql } = operations;
  const { both, makeTransactionRows } = transactions;

  const unavailable = () => PasskeyUnavailable.make({});

  const invariant: (value: unknown) => asserts value = (value) => {
    if (!value) throw unavailable();
  };

  const { col, equal, copiedRow, matchesNativeRow } = makeTransactionRows(unavailable);

  const nonce = randomId;

  const encoder = new TextEncoder();

  const decoder = new TextDecoder("utf-8", { fatal: true });

  /** RP tuples and admission scopes have no collation-dependent string identity. */
  const key = Effect.fnUntraced(function* (kind: string, fields: ReadonlyArray<string>) {
    const values = ["effect-auth/passkey/" + kind + "/v1", ...fields].map((field) => {
      const bytes = encoder.encode(field);

      invariant(decoder.decode(bytes) === field);

      return bytes;
    });

    const packed = new Uint8Array(values.reduce((size, bytes) => size + 4 + bytes.length, 0));
    const view = new DataView(packed.buffer);
    let offset = 0;

    for (const bytes of values) {
      view.setUint32(offset, bytes.length, false);
      packed.set(bytes, offset + 4);
      offset += 4 + bytes.length;
    }

    const crypto = yield* Crypto.Crypto;
    const hashed = yield* crypto.digest("SHA-256", packed);

    return "v1:" + Array.from(hashed, (value) => value.toString(16).padStart(2, "0")).join("");
  });

  const credentialKey = (rpId: string, id: string) => key("credential", [rpId, id]);

  const handleKey = (rpId: string, handle: string) => key("handle", [rpId, handle]);

  const subjectScope = (subjectId: string) => key("subject", [subjectId]);

  const targetScope = (ceremony: PasskeyCeremony) => {
    const context = ceremony.context;

    if (!("target" in context)) return Effect.succeed(null);
    const target = context.target;

    return key("target", [
      target.moduleId,
      target.kind,
      target.flowId,
      target.commandId,
      target.bindingDigest,
      target.revision.subjectId,
    ]);
  };

  /** Private storage is decoded Type data, never a consumer wire transform. */
  const storage = <S extends Schema.Codec<unknown, unknown, never, never>>(
    schema: S,
    maximumBytes: number,
  ) => {
    const codec = Schema.fromJsonString(Schema.toCodecJson(Schema.toType(schema)));

    const encode = (value: S["Type"]) => {
      const text = "v1:" + Schema.encodeSync(codec)(snapshotPasskeySync(schema, value));

      invariant(encoder.encode(text).length <= maximumBytes);

      return text;
    };

    return {
      encode,
      decode: (text: unknown): S["Type"] => {
        invariant(typeof text === "string" && text.startsWith("v1:"));
        invariant(encoder.encode(text).length <= maximumBytes);
        const value = snapshotPasskeySync(schema, Schema.decodeSync(codec)(text.slice(3)));

        invariant(encode(value) === text);

        return value;
      },
    };
  };

  // Legal 32 x 16 x 2048 origins require more than one MiB before JSON escaping.
  const policyStorage = storage(PasskeyMethodPolicy, 8 * 1024 * 1024);

  const ceremonyStorage = storage(PasskeyCeremony, 512 * 1024);

  const credentialStorage = storage(PasskeyCredential, 512 * 1024);

  const profileStorage = storage(PasskeyProfile, 256 * 1024);

  const revisionStorage = storage(PasskeyRevision, 256 * 1024);

  const sameCredential = (left: PasskeyCredential, right: PasskeyCredential) => {
    const semantic = (value: PasskeyCredential) => ({
      ...value,
      counter: 0,
      maximumCounter: 0,
      backupState: false,
      revision: { ...value.revision, credentials: [] },
    });

    return credentialStorage.encode(semantic(left)) === credentialStorage.encode(semantic(right));
  };

  const sameRevision = (left: typeof PasskeyRevision.Type, right: typeof PasskeyRevision.Type) => {
    const pairs = new Map(left.credentials.map((item) => [item.credentialId, item.revision]));

    return (
      left.subjectId === right.subjectId &&
      left.securityRevision === right.securityRevision &&
      pairs.size === left.credentials.length &&
      new Set(right.credentials.map((item) => item.credentialId)).size ===
        right.credentials.length &&
      pairs.size === right.credentials.length &&
      right.credentials.every((item) => pairs.get(item.credentialId) === item.revision)
    );
  };

  const semanticCredentialColumns = (mapping: any): string[] =>
    [
      "credentialId",
      "subjectId",
      "rpId",
      "protocolCredentialId",
      "credentialKey",
      "handleKey",
      "userHandle",
      "publicKey",
      "algorithm",
      "profile",
      "credentialRevision",
      "status",
      "primarySignIn",
      "enrollmentUserVerified",
      "backupEligible",
    ].map((name) => mapping[name]);

  const credentialSnapshot = (
    mapping: any,
    row: any,
    tuple: any,
    decoded: Omit<PasskeyCredential, "revision" | "active">,
    revision: typeof PasskeyRevision.Type,
    rpId: string,
    protocolCredentialId: string,
  ) => {
    const descriptor = mapping.credential;
    const ownership = mapping.credentialOwnership;

    const credential = snapshotPasskeySync(PasskeyCredential, {
      ...decoded,
      revision,
      active: true,
    });

    invariant(credential.rpId === rpId && credential.protocolCredentialId === protocolCredentialId);
    invariant(
      credential.credentialId === row[descriptor.credentialId] &&
        credential.credentialId === tuple[ownership.credentialId],
    );
    invariant(
      credential.profile.rpId === rpId &&
        credential.profile.algorithms.includes(credential.algorithm),
    );
    invariant(
      credential.counter === Number(row[descriptor.counter]) &&
        credential.maximumCounter === Number(row[descriptor.maximumCounter]),
    );
    invariant(
      credential.maximumCounter >= credential.counter &&
        (!credential.backupState || credential.backupEligible),
    );
    if (
      !revision.credentials.some(
        (item) =>
          item.credentialId === credential.credentialId &&
          item.revision === row[descriptor.credentialRevision],
      )
    )
      return undefined;

    return credential;
  };

  const mappedColumns = (mapping: any): string[] =>
    Object.entries(mapping)
      .filter(
        ([name, value]) =>
          !["table", "reservedState", "pendingState", "acceptedState", "rejectedState"].includes(
            name,
          ) && typeof value === "string",
      )
      .map(([, value]) => value as string);

  const observeSemantic = (mapping: any, where: SQL, row: any) =>
    Effect.map(CurrentPasskeyTransaction, (owner) => {
      owner.observations.push({
        table: mapping.table,
        where,
        rows: [
          Object.fromEntries(
            semanticCredentialColumns(mapping).map((column) => [column, row[column]]),
          ),
        ],
      });
    });

  /** Capture descriptor graphs, preserving native SQL expressions and table objects. */
  const captureMapping = <A>(input: A): A => {
    const seen = new Map<object, unknown>();

    const copy = (value: unknown): unknown => {
      if (value === null || typeof value !== "object" || Effect.isEffect(value)) return value;
      if (!Array.isArray(value) && Object.getPrototypeOf(value) !== Object.prototype) return value;
      const prior = seen.get(value);

      if (prior !== undefined) return prior;
      const result: any = Array.isArray(value) ? [] : {};

      seen.set(value, result);
      for (const [name, child] of Object.entries(value)) result[name] = copy(child);

      return Object.freeze(result);
    };

    return copy(input) as A;
  };

  const constraints = (actual: any, expected: any) => {
    for (const [name, columns] of Object.entries(expected))
      // oxlint-disable-next-line no-restricted-properties -- exact configured constraint descriptor fingerprint.
      invariant(JSON.stringify(actual?.[name]) === JSON.stringify(columns));
  };

  const descriptor = (value: any) => {
    const columns = getTableColumns(value.table);

    for (const name of mappedColumns(value)) invariant(columns[name] !== undefined);
  };

  const validateMapping = (
    mapping: any,
    kind: "read" | "context" | "assertion" | "registration",
  ) => {
    try {
      const read = kind === "read" ? mapping : kind !== "registration" ? mapping.read : undefined;

      if (read !== undefined) {
        for (const name of [
          "subject",
          "credential",
          "authority",
          "credentialOwnership",
          "handleOwnership",
        ])
          descriptor(read[name]);
        constraints(read.constraints, requiredPasskeyCredentialConstraints);
      }
      if (kind === "read") return;
      // oxlint-disable-next-line no-restricted-properties -- validate the untyped captured configuration boundary.
      Schema.decodeUnknownSync(PasskeyModuleId)(mapping.moduleId);
      descriptor(mapping.module);
      invariant(mapping.module.policyColumns.length > 0);
      for (const name of mapping.module.policyColumns) col(mapping.module.table, name);
      const scopes = new Set<string>();

      for (const guard of mapping.module.guards ?? []) {
        invariant(
          typeof guard.scope === "string" && guard.scope.length > 0 && guard.scope.length <= 256,
        );
        invariant(!scopes.has(guard.scope) && guard.columns.length > 0);
        scopes.add(guard.scope);
        for (const name of guard.columns) col(guard.table, name);
      }
      invariant(scopes.size <= 32);
      if (kind === "context") return;
      invariant(
        typeof mapping.authorityScope === "string" &&
          mapping.authorityScope.length > 0 &&
          mapping.authorityScope.length <= 256,
      );
      for (const name of ["flow", "admission", "charge"]) descriptor(mapping[name]);
      if (kind === "registration") {
        descriptor(mapping.intent);
        descriptor(mapping.handle);
      } else col(mapping.read.credential.table, mapping.telemetry.lastUsedAt);
      constraints(
        mapping.constraints,
        kind === "registration"
          ? requiredPasskeyRegistrationCeremonyConstraints
          : requiredPasskeyPersistenceConstraints,
      );
      const states = Object.values(mapping.flow.states);

      // oxlint-disable-next-line no-restricted-properties -- configured native state identity fingerprints.
      invariant(
        // oxlint-disable-next-line no-restricted-properties -- configured native state identity fingerprints.
        states.length === 7 && new Set(states.map((value) => JSON.stringify(value))).size === 7,
      );
      for (const value of [0, 1, 123456789, 8640000000000])
        invariant(mapping.clock.decodeInstant(mapping.clock.encodeInstant(value)) === value);
    } catch {
      throw PasskeyConfigurationError.make({});
    }
  };

  const assertNow = (condition: SQL) =>
    Effect.flatMap(CurrentPasskeyTransaction, (owner) =>
      Effect.gen(function* () {
        invariant(yield* owner.check(condition));
        owner.postconditions.push(condition);
      }),
    );

  const existsExact = (table: any, values: any, condition?: SQL) =>
    Effect.map(
      CurrentPasskeyTransaction,
      (owner) =>
        sql`exists(select 1 from ${table} where ${both(owner.exact(table, values), condition)})`,
    );

  return {
    unavailable,
    invariant,
    col,
    equal,
    copiedRow,
    matchesNativeRow,
    nonce,
    key,
    credentialKey,
    handleKey,
    subjectScope,
    targetScope,
    policyStorage,
    ceremonyStorage,
    credentialStorage,
    profileStorage,
    revisionStorage,
    sameCredential,
    sameRevision,
    semanticCredentialColumns,
    credentialSnapshot,
    mappedColumns,
    observeSemantic,
    captureMapping,
    validateMapping,
    assertNow,
    existsExact,
  };
};
