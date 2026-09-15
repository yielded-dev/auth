import {
  and,
  asc,
  or,
  eq,
  gt,
  gte,
  lte,
  inArray,
  isNull,
  notExists,
  sql,
  getTableColumns,
} from "drizzle-orm";

import type { QueryOperations } from "../internal/query-operations";
import { balancedD1And, compactD1GeneratedStatement } from "./d1-generated-statement";
import { column, updateValues } from "./model";

export const drizzleQueryOperations: QueryOperations = {
  and,
  asc,
  or,
  eq,
  gt,
  gte,
  lte,
  inArray,
  isNull,
  notExists,
  sql,
  getTableColumns,
  column,
  updateValues,
  balancedD1And,
  compactD1GeneratedStatement,
};
