import * as Shared from "./models/oauth-model";
import type { TableModel } from "./query-operations";
import type { Fragment as SQL, Table } from "./sql-table";

export interface SqlTableModel<T extends Table = Table> extends TableModel {
  readonly table: T;
}

export {
  type OAuthFlowState,
  type OAuthTupleState,
  type OAuthRegistrationState,
  type OAuthAction,
  type OAuthEligibilityFact,
  type OAuthD1Mapping,
  requiredOAuthSignInConstraints,
  requiredOAuthTupleConstraints,
  requiredOAuthRegistrationConstraints,
  requiredOAuthAccountsConstraints,
  type OAuthRegistrationAuthority,
} from "./models/oauth-model";

/** The engine writes every critical column explicitly after applying the pure
 * consumer encoder. Native instant values must roundtrip without precision loss. */
export type OAuthClock = Shared.OAuthClock<SQL>;

export type OAuthSubjectReadTable<S extends Table> = Shared.OAuthSubjectReadTable<
  SqlTableModel<S>,
  SQL
>;

export type OAuthSubjectTable<S extends Table> = Shared.OAuthSubjectTable<SqlTableModel<S>, SQL>;

export type OAuthOwnershipReadTable<O extends Table, N> = Shared.OAuthOwnershipReadTable<
  SqlTableModel<O>,
  N,
  SQL
>;

export type OAuthOwnershipTable<O extends Table, N> = Shared.OAuthOwnershipTable<
  SqlTableModel<O>,
  N,
  SQL
>;

export type OAuthCredentialReadTable<C extends Table> = Shared.OAuthCredentialReadTable<
  SqlTableModel<C>,
  SQL
>;

export type OAuthCredentialTable<C extends Table, N> = Shared.OAuthCredentialTable<
  SqlTableModel<C>,
  N,
  SQL
>;

export type OAuthAuthorityReadTable<C extends Table> = Shared.OAuthAuthorityReadTable<
  SqlTableModel<C>,
  SQL
>;

export type OAuthAuthorityTable<C extends Table, N> = Shared.OAuthAuthorityTable<
  SqlTableModel<C>,
  N,
  SQL
>;

/** Both purposes may use the same physical table. Shared tables share module/flow
 * and module/command uniqueness. The snapshot has the exact purpose-specific core
 * codec; terminal writes erase it, while identity, claim and retention columns remain. */
export type OAuthFlowTable<F extends Table> = Shared.OAuthFlowTable<SqlTableModel<F>>;

export type OAuthTupleAuthorityTable<T extends Table, N> = Shared.OAuthTupleAuthorityTable<
  SqlTableModel<T>,
  N
>;

export type OAuthRegistrationIntentTable<I extends Table> = Shared.OAuthRegistrationIntentTable<
  SqlTableModel<I>
>;

export type OAuthRegistrationCommandTable<
  R extends Table,
  Registration,
> = Shared.OAuthRegistrationCommandTable<SqlTableModel<R>, Registration>;

export type OAuthUnlinkCommandTable<U extends Table> = Shared.OAuthUnlinkCommandTable<
  SqlTableModel<U>
>;

/** Each descriptor reads only its own subject-scoped method rows. The native row
 * projector and SQL condition must express the same installed method eligibility.
 * All source/identifier/policy mutations advance subject securityRevision. D1 also
 * guards exact selected IDs/versions and absence/count assumptions, never just a
 * stale boolean. An over-limit graph fails closed rather than truncating. */
export type OAuthEligibilityTable<T extends Table, N> = Shared.OAuthEligibilityTable<
  SqlTableModel<T>,
  N,
  SQL
>;

/** Authenticated command replay uses current subject status and this additional
 * nonconsuming SQL policy. It never consumes a fresh action factor. */
export type OAuthMetadataPolicy<N> = Shared.OAuthMetadataPolicy<N, SQL>;

export type OAuthCleanupTable<T extends Table, N> = Shared.OAuthCleanupTable<
  SqlTableModel<T>,
  N,
  SQL
>;

export type OAuthRegistrationEligibility<N> = Shared.OAuthRegistrationEligibility<N, SQL>;

export type OAuthSignInMapping<
  S extends Table,
  O extends Table,
  C extends Table,
  AC extends Table,
  F extends Table,
  N,
> = Shared.OAuthSignInMapping<
  SqlTableModel<S>,
  SqlTableModel<O>,
  SqlTableModel<C>,
  SqlTableModel<AC>,
  SqlTableModel<F>,
  N,
  SQL
>;

export type OAuthOwnershipMutation<
  T extends Table,
  O extends Table,
  N,
> = Shared.OAuthOwnershipMutation<SqlTableModel<T>, SqlTableModel<O>, N, SQL>;

export type OAuthRegistrationIntentMapping<
  S extends Table,
  O extends Table,
  C extends Table,
  AC extends Table,
  F extends Table,
  T extends Table,
  I extends Table,
  N,
> = Shared.OAuthRegistrationIntentMapping<
  SqlTableModel<S>,
  SqlTableModel<O>,
  SqlTableModel<C>,
  SqlTableModel<AC>,
  SqlTableModel<F>,
  SqlTableModel<T>,
  SqlTableModel<I>,
  N,
  SQL
>;

export type OAuthRegistrationBase<
  Registration,
  T extends Table,
  O extends Table,
  I extends Table,
  R extends Table,
  N,
> = Shared.OAuthRegistrationBase<
  Registration,
  SqlTableModel<T>,
  SqlTableModel<O>,
  SqlTableModel<I>,
  SqlTableModel<R>,
  N,
  SQL,
  Table
>;

export type OAuthRegistrationGuardTable<
  T extends Table,
  Registration,
  N,
> = Shared.OAuthRegistrationGuardTable<SqlTableModel<T>, Registration, N, SQL>;

export type OAuthRegistrationGuardDescriptor<Registration, N> =
  Shared.OAuthRegistrationGuardDescriptor<Registration, N, SQL, Table>;

export const oauthRegistrationGuardTable = <T extends Table, Registration, N>(
  input: OAuthRegistrationGuardTable<T, Registration, N>,
): OAuthRegistrationGuardDescriptor<Registration, N> =>
  Shared.oauthRegistrationGuardTable<SqlTableModel<T>, Registration, N, SQL>(input);

export type OAuthRegistrationMapping<
  Registration,
  S extends Table,
  O extends Table,
  C extends Table,
  AC extends Table,
  T extends Table,
  I extends Table,
  R extends Table,
  N,
> = Shared.OAuthRegistrationMapping<
  Registration,
  SqlTableModel<S>,
  SqlTableModel<O>,
  SqlTableModel<C>,
  SqlTableModel<AC>,
  SqlTableModel<T>,
  SqlTableModel<I>,
  SqlTableModel<R>,
  N,
  SQL,
  Table
>;

/** Heterogeneous descriptors are made by typed factories and projected privately. */
export type OAuthEligibilityDescriptor<N> = Shared.OAuthEligibilityDescriptor<N, SQL, Table>;

export const oauthEligibilityTable = <T extends Table, N>(
  input: OAuthEligibilityTable<T, N>,
): OAuthEligibilityDescriptor<N> => Shared.oauthEligibilityTable<SqlTableModel<T>, N, SQL>(input);

export type OAuthCleanupDescriptor<N> = Shared.OAuthCleanupDescriptor<N, SQL, Table>;

export const oauthCleanupTable = <T extends Table, N>(
  input: OAuthCleanupTable<T, N>,
): OAuthCleanupDescriptor<N> => Shared.oauthCleanupTable<SqlTableModel<T>, N, SQL>(input);

/** A stable application/reference lock acquired before an ownership target.
 * Missing rows retain ownership. Conditions use detached native IDs; every
 * writer of the guarded reference follows the same order. */
export type OAuthReferenceGuardTable<T extends Table, N> = Shared.OAuthReferenceGuardTable<
  SqlTableModel<T>,
  N,
  SQL
>;

export type OAuthReferenceGuardDescriptor<N> = Shared.OAuthReferenceGuardDescriptor<N, SQL, Table>;

export const oauthReferenceGuardTable = <T extends Table, N>(
  input: OAuthReferenceGuardTable<T, N>,
): OAuthReferenceGuardDescriptor<N> =>
  Shared.oauthReferenceGuardTable<SqlTableModel<T>, N, SQL>(input);

export type OAuthAccountsMapping<
  S extends Table,
  O extends Table,
  C extends Table,
  AC extends Table,
  F extends Table,
  T extends Table,
  U extends Table,
  N,
> = Shared.OAuthAccountsMapping<
  SqlTableModel<S>,
  SqlTableModel<O>,
  SqlTableModel<C>,
  SqlTableModel<AC>,
  SqlTableModel<F>,
  SqlTableModel<T>,
  SqlTableModel<U>,
  N,
  SQL,
  Table
>;
