import * as Shared from "@yielded/auth-persistence/Adapter";
import type { InferInsertModel, SQL, Table } from "drizzle-orm";

import type { DrizzleTableModel } from "./table-model";

export type PasskeyCredentialInsert<N> = Shared.PasskeyCredentialInsert<N>;

export type PasskeyWriteTables<
  S extends Table,
  C extends Table,
  F extends Table,
  O extends Table,
  H extends Table,
  N,
> = Shared.PasskeyWriteTables<
  DrizzleTableModel<S>,
  DrizzleTableModel<C>,
  DrizzleTableModel<F>,
  DrizzleTableModel<O>,
  DrizzleTableModel<H>,
  N,
  SQL
>;

export type PasskeyInvalidationInput<N> = Shared.PasskeyInvalidationInput<N>;

export type PasskeyInvalidationMutation<N> = Shared.PasskeyInvalidationMutation<N, SQL>;

/** Same-owner updates for consumer session/pending tables. No external effects or callbacks after commit. */
export const passkeyInvalidationMutation = <T extends Table, N>(input: {
  readonly table: T;
  readonly where: (input: PasskeyInvalidationInput<N>) => SQL;
  readonly values: (input: PasskeyInvalidationInput<N>) => Partial<InferInsertModel<T>>;
  readonly postcondition: (input: PasskeyInvalidationInput<N>) => SQL;
}): PasskeyInvalidationMutation<N> =>
  Shared.passkeyInvalidationMutation<DrizzleTableModel<T>, N, SQL>(input);

export type PasskeyCommandTable<T extends Table, N> = Shared.PasskeyCommandTable<
  DrizzleTableModel<T>,
  N
>;

export type PasskeyManagementMapping<
  S extends Table,
  C extends Table,
  F extends Table,
  O extends Table,
  H extends Table,
  M extends Table,
  Flow extends Table,
  A extends Table,
  Charge extends Table,
  Command extends Table,
  N,
> = Shared.PasskeyManagementMapping<
  DrizzleTableModel<S>,
  DrizzleTableModel<C>,
  DrizzleTableModel<F>,
  DrizzleTableModel<O>,
  DrizzleTableModel<H>,
  DrizzleTableModel<M>,
  DrizzleTableModel<Flow>,
  DrizzleTableModel<A>,
  DrizzleTableModel<Charge>,
  DrizzleTableModel<Command>,
  N,
  SQL
>;

export const requiredPasskeyManagementConstraints = Shared.requiredPasskeyManagementConstraints;

export type PasskeyManagementServices = Shared.PasskeyManagementServices;

export type PasskeyRegistrationWriter<R> = Shared.PasskeyRegistrationWriter<R>;

export type PasskeyRegistrationServices<R> = Shared.PasskeyRegistrationServices<R>;

export type PasskeyRegistrationMapping<
  S extends Table,
  C extends Table,
  F extends Table,
  O extends Table,
  H extends Table,
  M extends Table,
  Flow extends Table,
  A extends Table,
  Charge extends Table,
  Intent extends Table,
  N,
  R,
> = Shared.PasskeyRegistrationMapping<
  DrizzleTableModel<S>,
  DrizzleTableModel<C>,
  DrizzleTableModel<F>,
  DrizzleTableModel<O>,
  DrizzleTableModel<H>,
  DrizzleTableModel<M>,
  DrizzleTableModel<Flow>,
  DrizzleTableModel<A>,
  DrizzleTableModel<Charge>,
  DrizzleTableModel<Intent>,
  N,
  R,
  SQL
>;

export const requiredPasskeyRegistrationWriteConstraints =
  Shared.requiredPasskeyRegistrationWriteConstraints;
