import type { PreparedCommit } from "@yielded/auth/Hooks";
import type { PasswordUnavailable } from "@yielded/auth/Password";
import type { ProofUnavailable } from "@yielded/auth/Proofs";
import { Context, type Effect } from "effect";

import type { NativeSqlDatabase } from "./native-database";

/** Final reads resolve the current physical owner, never a released savepoint. */
export class CurrentMutationTransaction extends Context.Service<
  CurrentMutationTransaction,
  NativeSqlDatabase
>()("effect-auth/drizzle/CurrentMutationTransaction") {}

export type MutationPostcondition = Effect.Effect<
  void,
  PasswordUnavailable | ProofUnavailable,
  CurrentMutationTransaction
>;

/** Registration ends when the application owner returns, before final validation. */
export class MutationPostconditions extends Context.Service<
  MutationPostconditions,
  { readonly register: (check: MutationPostcondition) => boolean }
>()("effect-auth/drizzle/MutationPostconditions") {}

/** Journal registration closes with the mutation owner callback. */
export class MutationJournalGuards extends Context.Service<
  MutationJournalGuards,
  { readonly register: (guard: PreparedCommit<void>) => boolean }
>()("effect-auth/drizzle/MutationJournalGuards") {}
