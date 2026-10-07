import { Effect } from "effect";

import { PersistenceMappingError } from "./mapping-error";

/** Keep one bound JSON value below SQLite DO's 2 MB binding limit. */
export const jsonBatches = Effect.fnUntraced(function* <Row>(rows: ReadonlyArray<Row>) {
  const batches: Array<{ readonly rows: ReadonlyArray<Row>; readonly payload: string }> = [];
  const encoder = new TextEncoder();
  let start = 0;
  let bytes = 2;
  let values: string[] = [];

  for (const [index, row] of rows.entries()) {
    const value = JSON.stringify(row);
    const size = encoder.encode(value).length + 1;

    if (size + 2 > 1_500_000)
      return yield* PersistenceMappingError.make({
        operation: "encode",
        cause: "Stored row exceeds native JSON binding limit",
      });
    if (bytes + size > 1_500_000) {
      batches.push({ rows: rows.slice(start, index), payload: `[${values.join(",")}]` });
      start = index;
      bytes = 2;
      values = [];
    }
    values.push(value);
    bytes += size;
  }
  if (values.length > 0)
    batches.push({ rows: rows.slice(start), payload: `[${values.join(",")}]` });

  return batches;
});
