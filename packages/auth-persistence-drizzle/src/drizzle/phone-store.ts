import {
  composedPhoneAdmission,
  type MappingInput,
  type PersistenceOwner,
  type PhoneStore,
  randomId,
} from "@yielded/auth-persistence/Adapter";
import { eq, sql, type Table } from "drizzle-orm";
import { Crypto, Effect } from "effect";

import { column } from "./model";
import { NativeDatabase } from "./native-database";
import type { NativeSqlDatabase } from "./native-database";
import {
  admitPhone,
  cleanupPhoneAdmission,
  CurrentPhoneTransaction,
  lookupPhone,
  unavailable,
} from "./phone-state";
import { makeTransactionScope } from "./transaction-owner";

export const makePhoneOwner = Effect.fnUntraced(function* (
  storage: MappingInput,
  options: { readonly dialect: "pg" | "sqlite"; readonly maxParameters?: number },
  nativeDatabase: object,
) {
  const database = nativeDatabase as NativeSqlDatabase;
  const native = yield* NativeDatabase;
  const crypto = yield* Crypto.Crypto;
  const subjects = storage.subjects.table as Table;
  const identifiers = storage.tables.identifiers! as Table;
  const credentials = storage.tables.credentials! as Table;
  const state = storage.tables.phoneState! as Table;

  const mapping = (moduleId: string) => ({
    moduleId,
    subject: {
      table: subjects,
      id: storage.subjects.id,
      securityRevision: storage.subjects.securityRevision,
      activeCondition: eq(column(subjects, storage.subjects.status), storage.subjects.activeValue),
    },
    subjectIds: {
      toNative: storage.subjects.toNativeSync,
      toSubject: storage.subjects.toSubjectSync,
    },
    identifier: {
      table: identifiers,
      namespace: "namespace",
      value: "value",
      subjectId: "subjectId",
      revision: "revision",
      verifiedAt: "verifiedAt",
      activeCondition: eq(column(identifiers, "active"), true),
    },
    credential: {
      table: credentials,
      id: "credentialId",
      subjectId: "subjectId",
      revision: "revision",
      activeCondition: eq(column(credentials, "active"), true),
    },
    state: {
      table: state,
      scope: "scope",
      state: "state",
      version: "version",
      encodeInsert: (row: object) => row,
    },
    admission: composedPhoneAdmission,
    engineNowMillis:
      options.dialect === "pg"
        ? sql`cast(extract(epoch from clock_timestamp()) * 1000 as bigint)`
        : sql`cast(round((julianday('now') - 2440587.5) * 86400000) as integer)`,
    encodeInstant: storage.encodeInstant,
  });

  const store = (current: NativeSqlDatabase): PhoneStore => {
    const run = <A, E>(
      work: Effect.Effect<A, E, CurrentPhoneTransaction | Crypto.Crypto>,
      readonlySnapshot = false,
    ) =>
      Effect.gen(function* () {
        const scope = makeTransactionScope(current, yield* randomId, unavailable, {
          ...options,
          client: native.$client,
          batch: false,
          mysql: false,
          locking: options.dialect === "pg",
          readonlySnapshot,
        });

        const result = yield* work.pipe(Effect.provideService(CurrentPhoneTransaction, scope));

        yield* scope.finish();

        return result;
      }).pipe(Effect.provideService(Crypto.Crypto, crypto));

    return {
      admit: (input) => run(admitPhone(mapping(input.moduleId), input)),
      cleanup: (input) => run(cleanupPhoneAdmission(mapping(input.moduleId), input)),
      lookup: (input) => run(lookupPhone(mapping(input.moduleId), input), true),
    };
  };

  const owner: Pick<PersistenceOwner<PhoneStore>, "transaction"> = {
    transaction: (body) => database.transaction((current) => body(store(current))),
  };

  return owner;
});
