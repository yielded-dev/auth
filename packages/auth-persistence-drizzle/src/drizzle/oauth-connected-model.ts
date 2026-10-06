import * as Shared from "@yielded/auth-persistence/Adapter";
import type { SQL, Table } from "drizzle-orm";

import type { DrizzleTableModel } from "./table-model";

export {
  type OAuthConnectedAction,
  type OAuthConnectedOrderCodec,
  type OAuthConnectedPolicyInput,
  requiredOAuthConnectedConstraints,
  requiredOAuthConnectedRevocationConstraints,
} from "@yielded/auth-persistence/Adapter";

export type OAuthConnectedSubjectTable<S extends Table> = Shared.OAuthConnectedSubjectTable<
  DrizzleTableModel<S>,
  SQL
>;

export type OAuthConnectedFlowTable<F extends Table, N> = Shared.OAuthConnectedFlowTable<
  DrizzleTableModel<F>,
  N
>;

export type OAuthConnectedGrantTable<G extends Table, N> = Shared.OAuthConnectedGrantTable<
  DrizzleTableModel<G>,
  N
>;

/** Also stores a permanent provider/issuer scope anchor. clientKey must fit 52
 * ASCII characters. Empty clientRegistrationId is reserved for that anchor;
 * actual profile registrations are nonempty. Scope counter stays zero. */
export type OAuthConnectedClientRegistrationTable<C extends Table> =
  Shared.OAuthConnectedClientRegistrationTable<DrizzleTableModel<C>>;

/** Remote authority: no local-subject column or subject-scoped key. Retain this
 * anchor/cutoff when a legitimately released tuple gains a different local owner. */
export type OAuthConnectedCohortTable<C extends Table> = Shared.OAuthConnectedCohortTable<
  DrizzleTableModel<C>
>;

export type OAuthConnectedAdmissionTable<A extends Table, N> = Shared.OAuthConnectedAdmissionTable<
  DrizzleTableModel<A>,
  N
>;

export type OAuthConnectedCommandTable<C extends Table, N> = Shared.OAuthConnectedCommandTable<
  DrizzleTableModel<C>,
  N
>;

export type OAuthConnectedRevocationJobTable<
  J extends Table,
  N,
> = Shared.OAuthConnectedRevocationJobTable<DrizzleTableModel<J>, N>;

export type OAuthConnectedPolicyGuardTable<
  T extends Table,
  N,
> = Shared.OAuthConnectedPolicyGuardTable<DrizzleTableModel<T>, N, SQL>;

export type OAuthConnectedPolicyGuard<N> = Shared.OAuthConnectedPolicyGuard<N, SQL, Table>;

export const oauthConnectedPolicyGuard = <T extends Table, N>(
  input: OAuthConnectedPolicyGuardTable<T, N>,
): OAuthConnectedPolicyGuard<N> =>
  Shared.oauthConnectedPolicyGuard<DrizzleTableModel<T>, N, SQL>(input);

export type OAuthConnectedSqlPolicy<N> = Shared.OAuthConnectedSqlPolicy<N, SQL, Table>;

/** Existing ownership only; workers never allocate or acquire a tuple. */
export type OAuthConnectedOwnershipRead<
  T extends Table,
  O extends Table,
  N,
> = Shared.OAuthConnectedOwnershipRead<DrizzleTableModel<T>, DrizzleTableModel<O>, N, SQL>;

export type OAuthConnectedAuthorityMapping<
  T extends Table,
  O extends Table,
  F extends Table,
  G extends Table,
  C extends Table,
  H extends Table,
  N,
> = Shared.OAuthConnectedAuthorityMapping<
  DrizzleTableModel<T>,
  DrizzleTableModel<O>,
  DrizzleTableModel<F>,
  DrizzleTableModel<G>,
  DrizzleTableModel<C>,
  DrizzleTableModel<H>,
  N,
  SQL
>;

export type OAuthConnectedMapping<
  S extends Table,
  AC extends Table,
  T extends Table,
  O extends Table,
  F extends Table,
  G extends Table,
  C extends Table,
  H extends Table,
  A extends Table,
  D extends Table,
  N,
  J extends Table = never,
> = Shared.OAuthConnectedMapping<
  DrizzleTableModel<S>,
  DrizzleTableModel<AC>,
  DrizzleTableModel<T>,
  DrizzleTableModel<O>,
  DrizzleTableModel<F>,
  DrizzleTableModel<G>,
  DrizzleTableModel<C>,
  DrizzleTableModel<H>,
  DrizzleTableModel<A>,
  DrizzleTableModel<D>,
  N,
  DrizzleTableModel<J>,
  SQL,
  Table,
  DrizzleTableModel<Table>
>;

export type OAuthConnectedRevocationMapping<
  T extends Table,
  O extends Table,
  F extends Table,
  G extends Table,
  C extends Table,
  H extends Table,
  J extends Table,
  N,
> = Shared.OAuthConnectedRevocationMapping<
  DrizzleTableModel<T>,
  DrizzleTableModel<O>,
  DrizzleTableModel<F>,
  DrizzleTableModel<G>,
  DrizzleTableModel<C>,
  DrizzleTableModel<H>,
  DrizzleTableModel<J>,
  N,
  SQL
>;
