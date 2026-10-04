import { requireStandalone as standalone } from "@yielded/auth-persistence/Adapter";
import { EmailUnavailable } from "@yielded/auth/Email";
import { ProofUnavailable } from "@yielded/auth/Proofs";
import type { AnyRelations } from "drizzle-orm";
import type { EffectLibsqlDatabase } from "drizzle-orm/effect-libsql";

import { Database } from "./libsql-database";
import { makeSqliteEmailTarget, sqliteEmailConfiguration } from "./sqlite-emails";

const requireStandaloneProof = standalone(() => ProofUnavailable.make({}));
const requireStandaloneEmail = standalone(() => EmailUnavailable.make({}));

export const {
  coordinateEmailAddress,
  coordinateEmailRegistration,
  makeEmailAddressServices,
  makeEmailRegistrationServices,
  makeEmailSignInServices,
} = makeSqliteEmailTarget<Database, EffectLibsqlDatabase<AnyRelations>>(
  Database,
  sqliteEmailConfiguration("interactive", requireStandaloneEmail, requireStandaloneProof),
);
