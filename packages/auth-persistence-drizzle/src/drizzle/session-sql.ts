import {
  makeStatefulSessionWorkflow,
  makeAuthenticationAuthorityWorkflow,
  type SessionSqlOptions,
} from "@yielded/auth-persistence/Adapter";
import { SessionUnavailable } from "@yielded/auth/Sessions";
import { Effect } from "effect";

import { makeStatefulSessionOwner, makeSessionAuthorityOwner } from "./session-store";
import { validateDrizzleStorage } from "./storage-validation";
export type { SessionSqlOptions } from "@yielded/auth-persistence/Adapter";

import { CurrentSessionSql } from "./session-database";
export { CurrentSessionSql } from "./session-database";

export {
  makeSqlPendingAuthentication,
  makeSqlSignedValidity,
  makeSqlSessionStepUp,
} from "./session-native";

export const makeSqlStatefulSessions = Effect.fnUntraced(function* <Claims>(
  mapping: Parameters<typeof makeStatefulSessionOwner<Claims>>[0],
  options: SessionSqlOptions,
) {
  if (!options.coordinated)
    yield* validateDrizzleStorage(mapping).pipe(Effect.mapError(() => SessionUnavailable.make({})));
  const owner = yield* makeStatefulSessionOwner<Claims>(mapping, yield* CurrentSessionSql);

  return yield* makeStatefulSessionWorkflow(mapping, options, owner);
});

export const makeSqlAuthenticationAuthority = Effect.fnUntraced(function* <Claims>(
  mapping: Parameters<typeof makeSessionAuthorityOwner<Claims>>[0],
  options: SessionSqlOptions,
) {
  if (!options.coordinated)
    yield* validateDrizzleStorage(mapping).pipe(Effect.mapError(() => SessionUnavailable.make({})));
  const owner = yield* makeSessionAuthorityOwner<Claims>(mapping);

  return yield* makeAuthenticationAuthorityWorkflow<Claims>(mapping, options, owner);
});
