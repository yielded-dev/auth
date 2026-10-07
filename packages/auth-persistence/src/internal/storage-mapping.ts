import { EmailCredentialSnapshot } from "@yielded/auth/Email";
import { LoginIdentifier } from "@yielded/auth/Identity";
import {
  PasswordCredentialSnapshot,
  EncodedPasswordHash,
  type PasswordReplacement,
} from "@yielded/auth/Password";
import { TokenDigest } from "@yielded/auth/Schema";
import {
  SecurityRevision,
  SessionId,
  SessionMetadata,
  SessionAuthenticationProvenance,
  SessionCredentialVersion,
  type StatefulSessionRecord,
} from "@yielded/auth/Sessions";
import { Crypto, DateTime, Effect, Redacted, Schema } from "effect";

import type { MappingInput } from "./configuration";
import { randomId } from "./crypto";
import { PersistenceMappingError } from "./mapping-error";
import { requiredEmailAddressConstraints, type AnyEmailAddressMapping } from "./models/email-model";
import {
  requiredPasswordConstraints,
  type AnyPasswordPersistenceMapping,
} from "./models/password-model";
import { requiredProofConstraints, type AnyProofPersistenceMapping } from "./models/proof-model";
import type { StatefulSessionMapping } from "./models/session-model";
import { makeStorageClock } from "./storage-clock";
import { storageTables, type StorageRole } from "./storage-tables";
import type { TableModel, SqlExpression } from "./table-model";

const failure = (cause: unknown) => PersistenceMappingError.make({ operation: "decode", cause });

const decode = <S extends Schema.Codec<unknown, unknown>>(schema: S, value: unknown) =>
  Schema.decodeUnknownEffect(schema)(value).pipe(Effect.mapError(failure));

const string = (value: unknown) => Schema.decodeUnknownSync(Schema.String)(value);

/** Derive shared row mappings from a managed or custom storage layout.
 * Acquire Effect Crypto once; the returned allocators retain that implementation.
 * Each factory requires its role tables to exist. Adapter authors supply typed
 * table handles and dialect-specific clocks/commit predicates, and may refine
 * authority policy for explicit services. This does not alter composed defaults.
 */
export const makeMappings = Effect.fnUntraced(function* (input: MappingInput) {
  const crypto = yield* Crypto.Crypto;

  const allocate = randomId.pipe(
    Effect.provideService(Crypto.Crypto, crypto),
    Effect.mapError(failure),
  );

  const table = (role: StorageRole) => {
    const found = input.tables[role];

    if (found === undefined) throw failure(`Missing ${role} mapping`);

    return found;
  };

  const mapped = (role: StorageRole) => ({
    table: table(role),
    ...Object.fromEntries(Object.keys(storageTables[role].columns).map((key) => [key, key])),
  });

  const { subjects: s, encodeInstant: instant, decodeInstant: readInstant } = input;
  const subjectId = { toNative: s.toNative, toSubject: s.toSubject, equals: Object.is };

  const subject = {
    table: s.table,
    id: s.id,
    status: s.status,
    securityRevision: s.securityRevision,
    isActiveStatus: (value: unknown) => Object.is(value, s.activeValue),
    d1ActiveStatusValue: s.activeValue,
    decodeRequirement: s.requirements,
    decodeActionRequirement: s.actionRequirements,
    nextSecurityRevision: () => allocate.pipe(Effect.map(SecurityRevision.make)),
  };

  const authorityCredential = () => ({
    ...mapped("credentials"),
    subjectId: "subjectId",
    credentialId: "credentialId",
    revision: "revision",
    status: "active",
    isActiveStatus: (value: unknown) => value === true,
    encodeInsert: (row: object) => ({ ...row, active: true }),
    encodeRevision: (revision: SecurityRevision) => ({ revision }),
  });

  const authority = () => ({ subjectId, subject, credential: authorityCredential() });

  const clock = yield* makeStorageClock(input);

  const proofs = (): AnyProofPersistenceMapping<SqlExpression> => ({
    constraints: requiredProofConstraints,
    subjectId,
    subject: { table: s.table, id: s.id },
    clock,
    proof: {
      ...mapped("proofs"),
      moduleId: "moduleId",
      purpose: "purpose",
      seriesKey: "seriesKey",
      proofId: "proofId",
      binding: "binding",
      verifierKeyId: "verifierKeyId",
      verifierDigest: "verifierDigest",
      issuedAt: "issuedAt",
      expiresAt: "expiresAt",
      failedAttempts: "failedAttempts",
      sendCount: "sendCount",
      encodeInsert: () => ({}),
    },
  });

  const passwords = (): AnyPasswordPersistenceMapping<SqlExpression> => {
    const verifier = (replacement: PasswordReplacement) => ({
      verifier: Redacted.value(replacement.verifier),
      normalization: replacement.normalization,
    });

    return {
      subjectId,
      subject,
      authorityCredential: authorityCredential(),
      constraints: requiredPasswordConstraints,
      encodeInstant: instant,
      decodeInstant: readInstant,
      allocateCredentialId: allocate,
      allocateRevision: allocate.pipe(Effect.map(SecurityRevision.make)),
      sessionInvalidation: "same-authority-immediate",
      identifier: {
        table: table("identifiers"),
        namespace: "namespace",
        value: "value",
        subjectId: "subjectId",
        verifiedAt: "verifiedAt",
        bindingRevision: "revision",
        isCurrent: (row) => row.active === true,
        encodeInitialInsert: (identifier, subjectId, revision) => ({
          ...identifier,
          subjectId,
          revision,
          verifiedAt: null,
          active: true,
        }),
      },
      credential: {
        ...mapped("passwords"),
        moduleId: "moduleId",
        subjectId: "subjectId",
        credentialId: "credentialId",
        credentialRevision: "credentialRevision",
        verifierVersion: "verifierVersion",
        verifier: "verifier",
        normalization: "normalization",
        encodeInsert: ({ replacement, ...row }) => ({ ...row, ...verifier(replacement) }),
        encodeVerifier: (hash, verifierVersion) => ({
          verifier: Redacted.value(hash),
          verifierVersion,
        }),
        encodeReplacement: ({ replacement, ...row }) => ({ ...row, ...verifier(replacement) }),
        decode: ({ moduleId, subject: row, identifier, credential }) =>
          Effect.gen(function* () {
            const id = yield* s.toSubject(row[s.id]);
            const hash = yield* decode(EncodedPasswordHash, credential.verifier);

            return yield* decode(PasswordCredentialSnapshot, {
              moduleId,
              revision: {
                subjectId: id,
                securityRevision: row[s.securityRevision],
                credentials: [
                  {
                    credentialId: credential.credentialId,
                    revision: credential.credentialRevision,
                  },
                ],
              },
              credentialId: credential.credentialId,
              credentialRevision: credential.credentialRevision,
              verifierVersion: credential.verifierVersion,
              verifier: hash,
              normalization: credential.normalization,
              identifier: yield* decode(LoginIdentifier, {
                namespace: identifier.namespace,
                value: identifier.value,
              }),
              identifierBindingRevision: identifier.revision,
              ...(identifier.verifiedAt === null
                ? {}
                : { identifierVerifiedAtMillis: yield* readInstant(identifier.verifiedAt) }),
            });
          }),
      },
      clock,
    };
  };

  const emails = (): AnyEmailAddressMapping<SqlExpression> => ({
    subjectId,
    subject: { ...subject, activeStatusValue: s.activeValue },
    constraints: requiredEmailAddressConstraints,
    addressCardinality: "single",
    changeDisposition: "retire-source",
    clock,
    encodeInstant: instant,
    decodeInstant: readInstant,
    allocateCredentialId: allocate,
    allocateRevision: allocate.pipe(Effect.map(SecurityRevision.make)),
    sessionInvalidation: "same-authority-immediate",
    isIdentifierConflict: () => false,
    isCredentialConflict: () => false,
    authorityCredential: {
      activeStatusValue: true,
      ...authorityCredential(),
      encodeActivation: (revision) => ({ revision, active: true }),
      encodeRetirement: (revision) => ({ revision, active: false }),
    },
    identifier: {
      table: table("identifiers"),
      namespace: "namespace",
      value: "value",
      subjectId: "subjectId",
      verifiedAt: "verifiedAt",
      bindingRevision: "revision",
      isCurrent: (row) => row.active === true && row.verifiedAt !== null,
      isMutableTarget: (row) => row.active === true && row.verifiedAt === null,
      encodeVerifiedInsert: ({ identifier, subjectId, verifiedAtMillis, bindingRevision }) => ({
        ...identifier,
        subjectId,
        verifiedAt: instant(verifiedAtMillis),
        revision: bindingRevision,
        active: true,
      }),
      encodeVerification: ({ verifiedAtMillis, bindingRevision }) => ({
        verifiedAt: instant(verifiedAtMillis),
        revision: bindingRevision,
        active: true,
      }),
      encodeRetirement: ({ bindingRevision }) => ({ revision: bindingRevision, active: false }),
    },
    credential: {
      activeStatusValue: true,
      table: table("emailCredentials"),
      moduleId: "moduleId",
      subjectId: "subjectId",
      credentialId: "credentialId",
      identifierNamespace: "identifierNamespace",
      identifierValue: "identifierValue",
      credentialRevision: "credentialRevision",
      status: "active",
      isActiveStatus: (value) => value === true,
      encodeVerifiedInsert: ({ identifier, ...row }) => ({
        ...row,
        identifierNamespace: identifier.namespace,
        identifierValue: identifier.value,
        active: true,
      }),
      encodeActivation: ({ identifier, credentialRevision }) => ({
        identifierNamespace: identifier.namespace,
        identifierValue: identifier.value,
        credentialRevision,
        active: true,
      }),
      encodeRetirement: ({ credentialRevision }) => ({ credentialRevision, active: false }),
      decode: ({ moduleId, subject: row, identifier, credential }) =>
        Effect.gen(function* () {
          return yield* decode(EmailCredentialSnapshot, {
            moduleId,
            identifier: { namespace: identifier.namespace, value: identifier.value },
            identifierRevision: identifier.revision,
            verifiedAtMillis: yield* readInstant(identifier.verifiedAt),
            credentialId: credential.credentialId,
            credentialRevision: credential.credentialRevision,
            revision: {
              subjectId: yield* s.toSubject(row[s.id]),
              securityRevision: row[s.securityRevision],
              credentials: [
                { credentialId: credential.credentialId, revision: credential.credentialRevision },
              ],
            },
          });
        }),
    },
  });

  const sessions = <C extends Schema.Codec<unknown, unknown, never, never>>(
    claims: C,
  ): StatefulSessionMapping<
    C["Type"],
    TableModel,
    TableModel,
    TableModel,
    TableModel,
    TableModel,
    unknown,
    string
  > => {
    const record = Schema.fromJsonString(
      Schema.Struct({
        ...SessionMetadata.fields,
        claims: Schema.Unknown,
        digest: TokenDigest,
        version: SecurityRevision,
        provenance: SessionAuthenticationProvenance,
        credentialVersion: SessionCredentialVersion,
      }),
    );

    const encodeRow = (value: StatefulSessionRecord<C["Type"]>) => ({
      digest: value.digest,
      version: value.version,
      securityRevision: value.securityRevision,
      issuedAt: instant(DateTime.toEpochMillis(value.issuedAt)),
      expiresAt: instant(DateTime.toEpochMillis(value.expiresAt)),
      absoluteExpiresAt: instant(DateTime.toEpochMillis(value.absoluteExpiresAt)),
      record: Schema.encodeSync(record)({
        ...value,
        claims: Schema.encodeSync(claims)(value.claims),
      }),
    });

    return {
      ...authority(),
      isConstraintConflict: () => false,
      constraints: { sessionDigest: "unique(session.digest)", flowId: "unique(flow.flowId)" },
      sessionId: {
        toNative: (id) => Effect.succeed(id),
        toSession: (id) => decode(SessionId, id),
        equals: Object.is,
      },
      flow: {
        table: table("sessionFlows"),
        flowId: "flowId",
        subjectId: "subjectId",
        state: "state",
        pendingDigest: "pendingDigest",
        dedupUntil: "dedupUntil",
        pendingStateValue: "pending",
        establishedStateValue: "established",
        encodeInstant: (date) => instant(DateTime.toEpochMillis(date)),
        decodeInstant: (value) => readInstant(value).pipe(Effect.map(DateTime.makeUnsafe)),
        encodePendingInsert: (row) => ({
          flowId: row.evidence.flowId,
          subjectId: row.subjectId,
          state: "pending",
          pendingDigest: row.pendingDigest,
          dedupUntil: instant(DateTime.toEpochMillis(row.dedupUntil)),
        }),
        encodeEstablishedInsert: (row) => ({
          flowId: row.evidence.flowId,
          subjectId: row.subjectId,
          state: "established",
          pendingDigest: null,
          dedupUntil: instant(DateTime.toEpochMillis(row.dedupUntil)),
        }),
      },
      session: {
        table: table("sessions"),
        sessionId: "sessionId",
        subjectId: "subjectId",
        digest: "digest",
        version: "version",
        securityRevision: "securityRevision",
        issuedAt: "issuedAt",
        expiresAt: "expiresAt",
        absoluteExpiresAt: "absoluteExpiresAt",
        encodeInstant: (date) => instant(DateTime.toEpochMillis(date)),
        allocateId: allocate,
        allocateVersion: allocate.pipe(Effect.map(SecurityRevision.make)),
        encodeInsert: (value, ids) => ({ ...encodeRow(value), ...ids }),
        encodeRotation: encodeRow,
        decode: (row) =>
          Effect.gen(function* () {
            const saved = yield* decode(record, row.record);
            const decodedClaims = yield* decode(claims, saved.claims);

            return { ...saved, claims: decodedClaims };
          }),
      },
    };
  };

  return { table, authority, proofs, passwords, emails, sessions, string };
});
