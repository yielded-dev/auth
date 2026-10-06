import * as Shared from "./models/oauth-connected-model";
import type { SqlTableModel } from "./sql-oauth-model";
import type { Fragment as SQL, Table } from "./sql-table";

export {
  type OAuthConnectedAction,
  type OAuthConnectedOrderCodec,
  type OAuthConnectedPolicyInput,
  requiredOAuthConnectedConstraints,
  requiredOAuthConnectedRevocationConstraints,
} from "./models/oauth-connected-model";

export type OAuthConnectedSubjectTable<S extends Table> = Shared.OAuthConnectedSubjectTable<
  SqlTableModel<S>,
  SQL
>;

export type OAuthConnectedFlowTable<F extends Table, N> = Shared.OAuthConnectedFlowTable<
  SqlTableModel<F>,
  N
>;

export type OAuthConnectedGrantTable<G extends Table, N> = Shared.OAuthConnectedGrantTable<
  SqlTableModel<G>,
  N
>;

/** Also stores a permanent provider/issuer scope anchor. clientKey must fit 52
 * ASCII characters. Empty clientRegistrationId is reserved for that anchor;
 * actual profile registrations are nonempty. Scope counter stays zero. */
export type OAuthConnectedClientRegistrationTable<C extends Table> =
  Shared.OAuthConnectedClientRegistrationTable<SqlTableModel<C>>;

/** Remote authority: no local-subject column or subject-scoped key. Retain this
 * anchor/cutoff when a legitimately released tuple gains a different local owner. */
export type OAuthConnectedCohortTable<C extends Table> = Shared.OAuthConnectedCohortTable<
  SqlTableModel<C>
>;

export type OAuthConnectedAdmissionTable<A extends Table, N> = Shared.OAuthConnectedAdmissionTable<
  SqlTableModel<A>,
  N
>;

export type OAuthConnectedCommandTable<C extends Table, N> = Shared.OAuthConnectedCommandTable<
  SqlTableModel<C>,
  N
>;

export type OAuthConnectedRevocationJobTable<
  J extends Table,
  N,
> = Shared.OAuthConnectedRevocationJobTable<SqlTableModel<J>, N>;

export type OAuthConnectedPolicyGuardTable<
  T extends Table,
  N,
> = Shared.OAuthConnectedPolicyGuardTable<SqlTableModel<T>, N, SQL>;

export type OAuthConnectedPolicyGuard<N> = Shared.OAuthConnectedPolicyGuard<N, SQL, Table>;

export const oauthConnectedPolicyGuard = <T extends Table, N>(
  input: OAuthConnectedPolicyGuardTable<T, N>,
): OAuthConnectedPolicyGuard<N> =>
  Shared.oauthConnectedPolicyGuard<SqlTableModel<T>, N, SQL>(input);

export type OAuthConnectedSqlPolicy<N> = Shared.OAuthConnectedSqlPolicy<N, SQL, Table>;

/** Existing ownership only; workers never allocate or acquire a tuple. */
export type OAuthConnectedOwnershipRead<
  T extends Table,
  O extends Table,
  N,
> = Shared.OAuthConnectedOwnershipRead<SqlTableModel<T>, SqlTableModel<O>, N, SQL>;

export type OAuthConnectedAuthorityMapping<
  T extends Table,
  O extends Table,
  F extends Table,
  G extends Table,
  C extends Table,
  H extends Table,
  N,
> = Shared.OAuthConnectedAuthorityMapping<
  SqlTableModel<T>,
  SqlTableModel<O>,
  SqlTableModel<F>,
  SqlTableModel<G>,
  SqlTableModel<C>,
  SqlTableModel<H>,
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
  SqlTableModel<S>,
  SqlTableModel<AC>,
  SqlTableModel<T>,
  SqlTableModel<O>,
  SqlTableModel<F>,
  SqlTableModel<G>,
  SqlTableModel<C>,
  SqlTableModel<H>,
  SqlTableModel<A>,
  SqlTableModel<D>,
  N,
  SqlTableModel<J>,
  SQL,
  Table,
  SqlTableModel<Table>
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
  SqlTableModel<T>,
  SqlTableModel<O>,
  SqlTableModel<F>,
  SqlTableModel<G>,
  SqlTableModel<C>,
  SqlTableModel<H>,
  SqlTableModel<J>,
  N,
  SQL
>;
