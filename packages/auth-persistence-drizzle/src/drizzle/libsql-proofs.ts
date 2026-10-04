import { requireStandalone as standalone } from "@yielded/auth-persistence/Adapter";
import { ProofUnavailable } from "@yielded/auth/Proofs";
import type { AnyRelations } from "drizzle-orm";
import type { EffectLibsqlDatabase } from "drizzle-orm/effect-libsql";

import { Database } from "./libsql-database";
import { makeSqliteProofTarget, sqliteProofConfiguration } from "./sqlite-proofs";

const requireStandaloneProof = standalone(() => ProofUnavailable.make({}));

export const { coordinateProofPersistence, makeProofPersistenceServices } = makeSqliteProofTarget<
  Database,
  EffectLibsqlDatabase<AnyRelations>
>(Database, sqliteProofConfiguration("interactive", requireStandaloneProof));
