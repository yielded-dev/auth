import { makeManagedPasskeys } from "@yielded/auth-persistence/Adapter";
import type { Backend } from "@yielded/auth-persistence/Adapter";
import { Effect } from "effect";
import { SqlClient } from "effect/sql";

import type { NativeDatabaseHandle } from "./native-database";
import { makeDrizzleSqlTables } from "./native-sql-table";

export const makeComposedPasskeys: Backend<object, never, NativeDatabaseHandle>["passkeys"] = (
  input,
  database,
) =>
  makeManagedPasskeys(input, makeDrizzleSqlTables(database.$client, database)).pipe(
    Effect.provideService(SqlClient.SqlClient, database.$client),
  );
