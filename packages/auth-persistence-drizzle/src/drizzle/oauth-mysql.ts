import { OAuthUnavailable } from "@yielded/auth/OAuth";
/* oxlint-disable no-explicit-any -- private native transaction adapter. */
import type { Effect } from "effect";

import { mysqlTransaction } from "./transaction-mysql";

export const mysqlOAuthTransaction = <A, E, R>(
  database: any,
  body: (transaction: any) => Effect.Effect<A, E, R>,
) => mysqlTransaction(() => OAuthUnavailable.make({}), database, body);
