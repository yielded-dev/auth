import { requireStandalone as standalone } from "@yielded/auth-persistence/Adapter";
import { PasswordUnavailable } from "@yielded/auth/Password";
import { ProofUnavailable } from "@yielded/auth/Proofs";
import type { AnyRelations } from "drizzle-orm";
import type { EffectLibsqlDatabase } from "drizzle-orm/effect-libsql";

import { Database } from "./libsql-database";
import { makeSqlitePasswordTarget, sqlitePasswordConfiguration } from "./sqlite-passwords";

const requireStandaloneProof = standalone(() => ProofUnavailable.make({}));
const requireStandalonePassword = standalone(() => PasswordUnavailable.make({}));

export const {
  coordinatePasswordPersistence,
  coordinatePasswordRegistration,
  makePasswordPersistenceServices,
  makePasswordRegistrationServices,
} = makeSqlitePasswordTarget<Database, EffectLibsqlDatabase<AnyRelations>>(
  Database,
  sqlitePasswordConfiguration("interactive", requireStandalonePassword, requireStandaloneProof),
);
