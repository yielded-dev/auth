import type * as Drizzle from "drizzle-orm";

import type { balancedD1And, compactD1GeneratedStatement } from "../drizzle/d1-generated-statement";
import type { column, updateValues } from "../drizzle/model";

/** Compiler operations shared by the SQL state machines; no driver is acquired here. */
export type QueryOperations = Pick<
  typeof Drizzle,
  | "and"
  | "asc"
  | "or"
  | "eq"
  | "gt"
  | "gte"
  | "lte"
  | "inArray"
  | "isNull"
  | "notExists"
  | "sql"
  | "getTableColumns"
> & {
  readonly column: typeof column;
  readonly updateValues: typeof updateValues;
  readonly balancedD1And: typeof balancedD1And;
  readonly compactD1GeneratedStatement: typeof compactD1GeneratedStatement;
};
