import {
  makePasswordWorkflow,
  type AnyPasswordPersistenceMapping,
} from "@yielded/auth-persistence/Adapter";
import { Effect } from "effect";
import { SqlClient } from "effect/sql";

import { NativeDatabase } from "./native-database";
import { makeDrizzleSqlTables } from "./native-sql-table";
import { CurrentPasswordSql, type PasswordSqlConfiguration } from "./password-database";
import { unavailable, validConstraints } from "./password-native";
import { makePasswordOwner } from "./password-store";
import { validateDrizzleStorage } from "./storage-validation";

export { CurrentPasswordSql } from "./password-database";

export type { PasswordSqlConfiguration } from "./password-database";

export const makeSqlPasswordPersistence = Effect.fnUntraced(function* (
  mapping: AnyPasswordPersistenceMapping,
  initialConfiguration: PasswordSqlConfiguration,
) {
  const database = yield* CurrentPasswordSql;
  const native = yield* NativeDatabase;

  const configuration: PasswordSqlConfiguration = {
    ...initialConfiguration,
    ...(initialConfiguration.proof === undefined
      ? {}
      : {
          proof: {
            ...initialConfiguration.proof,
            configuration: {
              ...initialConfiguration.proof.configuration,
              pgOrderedLocks: native.$client.onDialectOrElse({
                pg: () => initialConfiguration.proof!.configuration.locking,
                orElse: () => false,
              }),
            },
          },
        }),
  };

  if (!validConstraints(mapping)) return yield* unavailable();
  if (!configuration.coordinated)
    yield* validateDrizzleStorage({ ...mapping, proof: configuration.proof?.mapping }).pipe(
      Effect.mapError(unavailable),
    );
  const owner = yield* makePasswordOwner(mapping, configuration, database);
  const { proof, ...options } = configuration;

  return yield* makePasswordWorkflow(
    mapping,
    { ...options, ...(proof === undefined ? {} : { proof: proof.mapping }) },
    owner,
    makeDrizzleSqlTables(native.$client, native),
  ).pipe(Effect.provideService(SqlClient.SqlClient, native.$client));
});
