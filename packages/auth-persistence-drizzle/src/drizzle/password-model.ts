import * as Shared from "@yielded/auth-persistence/Adapter";
import type { SQL, Table } from "drizzle-orm";

import type { DrizzleTableModel } from "./table-model";

export type PasswordAttemptAction = Shared.PasswordAttemptAction;

export type PasswordAttemptState = Shared.PasswordAttemptState;

export type PasswordRateScopeKind = Shared.PasswordRateScopeKind;

export type PasswordScopeKeys = Shared.PasswordScopeKeys;

export type PasswordSubjectTable<
  Subject extends Table,
  _NativeSubjectId,
> = Shared.PasswordSubjectTable<DrizzleTableModel<Subject>, _NativeSubjectId>;

export type PasswordIdentifierTable<
  Identifier extends Table,
  NativeSubjectId,
> = Shared.PasswordIdentifierTable<DrizzleTableModel<Identifier>, NativeSubjectId, SQL>;

export type PasswordAuthorityCredentialTable<
  Credential extends Table,
  NativeSubjectId,
> = Shared.PasswordAuthorityCredentialTable<DrizzleTableModel<Credential>, NativeSubjectId>;

export type PasswordCredentialTable<
  Subject extends Table,
  Identifier extends Table,
  Credential extends Table,
  NativeSubjectId,
> = Shared.PasswordCredentialTable<
  DrizzleTableModel<Subject>,
  DrizzleTableModel<Identifier>,
  DrizzleTableModel<Credential>,
  NativeSubjectId
>;

export type PasswordAttemptRecord = Shared.PasswordAttemptRecord;

export type PasswordAttemptTable<
  Attempt extends Table,
  NativeSubjectId,
> = Shared.PasswordAttemptTable<DrizzleTableModel<Attempt>, NativeSubjectId>;

export type PasswordRateScopeTable<RateScope extends Table> = Shared.PasswordRateScopeTable<
  DrizzleTableModel<RateScope>
>;

export type PasswordChargeTable<Charge extends Table> = Shared.PasswordChargeTable<
  DrizzleTableModel<Charge>
>;

export type PasswordCommandTable<Command extends Table> = Shared.PasswordCommandTable<
  DrizzleTableModel<Command>
>;

export type RequiredPasswordConstraints = Shared.RequiredPasswordConstraints;

export const requiredPasswordConstraints = Shared.requiredPasswordConstraints;

export type PasswordConstraintClassifier = Shared.PasswordConstraintClassifier;

export type PasswordD1Clock = Shared.PasswordD1Clock<SQL>;

export type PasswordPersistenceMapping<
  Subject extends Table,
  Identifier extends Table,
  Credential extends Table,
  AuthorityCredential extends Table,
  Attempt extends Table,
  RateScope extends Table,
  Charge extends Table,
  Command extends Table,
  NativeSubjectId,
> = Shared.PasswordPersistenceMapping<
  DrizzleTableModel<Subject>,
  DrizzleTableModel<Identifier>,
  DrizzleTableModel<Credential>,
  DrizzleTableModel<AuthorityCredential>,
  DrizzleTableModel<Attempt>,
  DrizzleTableModel<RateScope>,
  DrizzleTableModel<Charge>,
  DrizzleTableModel<Command>,
  NativeSubjectId,
  SQL
>;

export type D1PasswordPersistenceMapping<
  Subject extends Table,
  Identifier extends Table,
  Credential extends Table,
  AuthorityCredential extends Table,
  Attempt extends Table,
  RateScope extends Table,
  Charge extends Table,
  Command extends Table,
  NativeSubjectId,
> = Shared.D1PasswordPersistenceMapping<
  DrizzleTableModel<Subject>,
  DrizzleTableModel<Identifier>,
  DrizzleTableModel<Credential>,
  DrizzleTableModel<AuthorityCredential>,
  DrizzleTableModel<Attempt>,
  DrizzleTableModel<RateScope>,
  DrizzleTableModel<Charge>,
  DrizzleTableModel<Command>,
  NativeSubjectId,
  SQL
>;

export type PasswordRegistrationState = Shared.PasswordRegistrationState;

export type PasswordRegistrationIntent<Registration> =
  Shared.PasswordRegistrationIntent<Registration>;

export type PasswordRegistrationTable<
  Registration,
  Request extends Table,
  NativeSubjectId,
> = Shared.PasswordRegistrationTable<Registration, DrizzleTableModel<Request>, NativeSubjectId>;

export type PasswordRegistrationProvisioning<
  Registration,
  Subject extends Table,
  NativeSubjectId,
> = Shared.PasswordRegistrationProvisioning<
  Registration,
  DrizzleTableModel<Subject>,
  NativeSubjectId
>;

export type RequiredPasswordRegistrationConstraints =
  Shared.RequiredPasswordRegistrationConstraints;

export const requiredPasswordRegistrationConstraints =
  Shared.requiredPasswordRegistrationConstraints;

export type PasswordRegistrationConstraintClassifier =
  Shared.PasswordRegistrationConstraintClassifier;

export type PasswordRegistrationMapping<
  Registration,
  Subject extends Table,
  Identifier extends Table,
  Credential extends Table,
  AuthorityCredential extends Table,
  Request extends Table,
  NativeSubjectId,
> = Shared.PasswordRegistrationMapping<
  Registration,
  DrizzleTableModel<Subject>,
  DrizzleTableModel<Identifier>,
  DrizzleTableModel<Credential>,
  DrizzleTableModel<AuthorityCredential>,
  DrizzleTableModel<Request>,
  NativeSubjectId,
  SQL
>;

export type AnyPasswordPersistenceMapping = PasswordPersistenceMapping<
  Table,
  Table,
  Table,
  Table,
  Table,
  Table,
  Table,
  Table,
  unknown
>;

export type AnyPasswordRegistrationMapping<Registration = unknown> = PasswordRegistrationMapping<
  Registration,
  Table,
  Table,
  Table,
  Table,
  Table,
  unknown
>;
