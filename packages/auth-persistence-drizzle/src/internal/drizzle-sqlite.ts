import {
  PersistenceConfigurationError,
  createPersistence,
} from "@yielded/auth-persistence/Adapter";
import type { StorageTable } from "@yielded/auth-persistence/Adapter";
import { getTableColumns } from "drizzle-orm";
import {
  getTableConfig,
  integer,
  sqliteTable,
  text,
  uniqueIndex,
  type SQLiteTable,
} from "drizzle-orm/sqlite-core";
import { Effect } from "effect";
import type { SqlClient } from "effect/sql/SqlClient";

import { makeBackendEmailOwner } from "../drizzle/email-store";
import {
  NativeDatabase,
  nativeDatabase,
  type NativeDatabaseHandle,
} from "../drizzle/native-database";
import { makeDrizzleSqlTables } from "../drizzle/native-sql-table";
import { makeComposedPasskeys } from "../drizzle/passkeys";
import { makeBackendPasswordOwner } from "../drizzle/password-store";
import { makePhoneOwner } from "../drizzle/phone-store";
import { makeBackendProofOwner } from "../drizzle/proof-store";
import { makeRegistrationOwner } from "../drizzle/registration-store";
import { makeStatefulSessionOwner } from "../drizzle/session-store";

const makeTable = (definition: StorageTable) =>
  sqliteTable(
    definition.name,
    Object.fromEntries(
      Object.entries(definition.columns).map(([key, column]) => {
        const builder =
          column.type === "text"
            ? text(column.name)
            : column.type === "boolean"
              ? integer(column.name, { mode: "boolean" })
              : integer(column.name);

        return [key, column.nullable ? builder : builder.notNull()];
      }),
    ),
    (columns) =>
      definition.unique.map((keys, i) => {
        const [first, ...rest] = keys;

        if (first === undefined)
          throw PersistenceConfigurationError.make({ reason: "An empty unique key is invalid" });

        return uniqueIndex(`${definition.name}_key_${i}`).on(
          columns[first],
          ...rest.map((key) => columns[key]),
        );
      }),
  );

const describe = (table: SQLiteTable): StorageTable => {
  const config = getTableConfig(table);

  return {
    name: config.name,
    columns: Object.fromEntries(
      Object.entries(getTableColumns(table)).map(([key, column]) => [
        key,
        {
          name: column.name,
          type:
            column.dataType === "boolean"
              ? "boolean"
              : column.dataType === "number"
                ? "integer"
                : "text",
          nullable: !column.notNull,
        },
      ]),
    ),
    unique: [],
  };
};

export const sqlitePersistence = <R>(acquire: Effect.Effect<object, never, R | SqlClient>) =>
  createPersistence<SQLiteTable, R, NativeDatabaseHandle>({
    nativeTables: (database) => makeDrizzleSqlTables(database.$client, database),
    makeTable,
    describe,
    sessionOwner: (mapping, database) =>
      makeStatefulSessionOwner(mapping, database).pipe(
        Effect.provideService(NativeDatabase, database),
      ),
    proofOwner: (mapping, options, database) =>
      makeBackendProofOwner(mapping, options, database).pipe(
        Effect.provideService(NativeDatabase, database),
      ),
    passwordOwner: (mapping, options, database, proofMapping) =>
      makeBackendPasswordOwner(mapping, options, database, proofMapping).pipe(
        Effect.provideService(NativeDatabase, database),
      ),
    emailOwner: (mapping, options, database, proofMapping) =>
      makeBackendEmailOwner(mapping, options, database, proofMapping).pipe(
        Effect.provideService(NativeDatabase, database),
      ),
    registrationOwner: (mapping, receipts, database) =>
      makeRegistrationOwner(mapping, receipts, database).pipe(
        Effect.provideService(NativeDatabase, database),
      ),
    phoneOwner: (mapping, options, database) =>
      makePhoneOwner(mapping, options, database).pipe(
        Effect.provideService(NativeDatabase, database),
      ),
    acquire: nativeDatabase(acquire),
    maxParameters: (database) => database.maxParameters,
    passkeys: makeComposedPasskeys,
  });
