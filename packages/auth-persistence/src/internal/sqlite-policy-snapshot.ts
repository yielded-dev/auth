import { Array } from "effect";
import type { SqlClient } from "effect/sql/SqlClient";

import type { SqlTable } from "./native-sql-table";

/** Capture physical values beside the policy read, then bind one snapshot at
 * commit. Type tags distinguish NULL, text and blobs; hex preserves embedded
 * NULs and collation differences. Real values retain adjacent-double precision.
 * Chunk arrays to respect D1's function-argument and expression-depth limits. */
export const sqlitePolicySnapshot = (
  sql: SqlClient,
  table: SqlTable,
  columns: ReadonlyArray<string>,
) => {
  const chunks = Array.chunksOf(columns, 32).map(
    (keys) =>
      sql`json_array(${sql.join(
        ", ",
        false,
      )(
        keys.map((key) => {
          const column = table.column(key);

          return sql`json_array(typeof(${column}), case typeof(${column}) when 'real' then printf('%!.26g', ${column}) else hex(${column}) end)`;
        }),
      )})`,
  );

  return sql`json_array(${sql.join(", ", false)(chunks)})`;
};
