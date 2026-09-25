import * as Shared from "@yielded/auth-persistence/Adapter";
import type { SQL, Table } from "drizzle-orm";

import type { DrizzleTableModel } from "./table-model";

export type PasskeyColumn<T extends Table> = Shared.PasskeyColumn<DrizzleTableModel<T>>;

export type PasskeyMappingSource<M, RSetup = never> = Shared.PasskeyMappingSource<M, RSetup>;

export type PasskeyCredentialServices = Shared.PasskeyCredentialServices;

export type PasskeyPersistenceServices = Shared.PasskeyPersistenceServices;

export type PasskeyEnrollmentContextServices = Shared.PasskeyEnrollmentContextServices;

export const passkeyCredentialsLayer = Shared.passkeyCredentialsLayer;

export const passkeyPersistenceLayer = Shared.passkeyPersistenceLayer;

export const passkeyEnrollmentContextLayer = Shared.passkeyEnrollmentContextLayer;

/** Native IDs roundtrip exactly; protocol IDs and authentication references are
 * different identities. These callbacks never suspend inside an owner. */
export type PasskeySubjectIdCodec<N> = Shared.PasskeySubjectIdCodec<N>;

export type PasskeyClock = Shared.PasskeyClock<SQL>;

export type PasskeySubjectReadTable<T extends Table, N> = Shared.PasskeySubjectReadTable<
  DrizzleTableModel<T>,
  N,
  SQL
>;

export type PasskeyFactorReadTable<T extends Table> = Shared.PasskeyFactorReadTable<
  DrizzleTableModel<T>,
  SQL
>;

/** decode uses only these declared columns. Counter columns are native integral
 * numbers; BS may use a consumer enum. Name/creation metadata is not required. */
export type PasskeyCredentialReadTable<T extends Table, N> = Shared.PasskeyCredentialReadTable<
  DrizzleTableModel<T>,
  N,
  SQL
>;

export type PasskeyCredentialOwnershipTable<
  T extends Table,
  N,
> = Shared.PasskeyCredentialOwnershipTable<DrizzleTableModel<T>, N, SQL>;

/** Reservations do not manufacture a subject; bound handles are RP-global. */
export type PasskeyHandleReadTable<T extends Table> = Shared.PasskeyHandleReadTable<
  DrizzleTableModel<T>
>;

export type PasskeyHandleReservationTable<T extends Table> = Shared.PasskeyHandleReservationTable<
  DrizzleTableModel<T>,
  SQL
>;

export type PasskeyHandleOwnershipTable<T extends Table, N> = Shared.PasskeyHandleOwnershipTable<
  DrizzleTableModel<T>,
  N,
  SQL
>;

export const requiredPasskeyCredentialConstraints = Shared.requiredPasskeyCredentialConstraints;

export type PasskeyCredentialMapping<
  S extends Table,
  C extends Table,
  F extends Table,
  Ownership extends Table,
  Handle extends Table,
  N,
> = Shared.PasskeyCredentialMapping<
  DrizzleTableModel<S>,
  DrizzleTableModel<C>,
  DrizzleTableModel<F>,
  DrizzleTableModel<Ownership>,
  DrizzleTableModel<Handle>,
  N,
  SQL
>;

export type PasskeyPolicyGuard = Shared.PasskeyPolicyGuard<SQL>;

export const passkeyPolicyGuard = <T extends Table>(input: {
  readonly scope: string;
  readonly table: T;
  readonly columns: ReadonlyArray<PasskeyColumn<T>>;
  readonly where: (moduleId: string) => SQL;
  readonly condition: (moduleId: string) => SQL;
}): PasskeyPolicyGuard => Shared.passkeyPolicyGuard<DrizzleTableModel<T>, SQL>(input);

export type PasskeyModuleTable<T extends Table> = Shared.PasskeyModuleTable<
  DrizzleTableModel<T>,
  SQL
>;

export type PasskeyFlowState = Shared.PasskeyFlowState;

export type PasskeyFlowInsert = Shared.PasskeyFlowInsert;

export type PasskeyFlowTable<T extends Table> = Shared.PasskeyFlowTable<DrizzleTableModel<T>>;

export type PasskeyAdmissionTable<T extends Table> = Shared.PasskeyAdmissionTable<
  DrizzleTableModel<T>
>;

export type PasskeyChargeKind = Shared.PasskeyChargeKind;

export type PasskeyChargeInsert = Shared.PasskeyChargeInsert;

/** Charge scope is canonical core identity text; this subject-free descriptor
 * can count all purposes without decoding any unrelated native subject. */
export type PasskeyChargeTable<T extends Table> = Shared.PasskeyChargeTable<DrizzleTableModel<T>>;

export const requiredPasskeyPersistenceConstraints = Shared.requiredPasskeyPersistenceConstraints;

export type PasskeyCeremonyMapping<
  Module extends Table,
  Flow extends Table,
  Admission extends Table,
  Charge extends Table,
> = Shared.PasskeyCeremonyMapping<
  DrizzleTableModel<Module>,
  DrizzleTableModel<Flow>,
  DrizzleTableModel<Admission>,
  DrizzleTableModel<Charge>,
  SQL
>;

type CredentialTable<Read> = Read extends {
  readonly credential: {
    readonly table: infer T extends Table;
  };
}
  ? T
  : never;

export type PasskeyPersistenceMapping<
  Read,
  Module extends Table,
  Flow extends Table,
  Admission extends Table,
  Charge extends Table,
  N,
> = Shared.PasskeyPersistenceMapping<
  Read,
  DrizzleTableModel<Module>,
  DrizzleTableModel<Flow>,
  DrizzleTableModel<Admission>,
  DrizzleTableModel<Charge>,
  N,
  SQL,
  DrizzleTableModel<CredentialTable<Read>>
>;

export type PasskeyEnrollmentContextMapping<
  Read,
  Module extends Table,
  N,
> = Shared.PasskeyEnrollmentContextMapping<Read, DrizzleTableModel<Module>, N, SQL>;

export type D1PasskeyMapping = Shared.D1PasskeyMapping;
