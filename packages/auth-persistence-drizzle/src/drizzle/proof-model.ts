import * as Shared from "@yielded/auth-persistence/Adapter";
import type { SQL, Table } from "drizzle-orm";

import type { DrizzleTableModel } from "./table-model";

export type ProofAction = Shared.ProofAction;

export type ProofScopeKind = Shared.ProofScopeKind;

export type ProofGenerationState = Shared.ProofGenerationState;

export type ProofDeliveryState = Shared.ProofDeliveryState;

export type ProofCommandKind = Shared.ProofCommandKind;

export type ProofCommandDecision = Shared.ProofCommandDecision;

export type ProofScopeKeys = Shared.ProofScopeKeys;

export type ProofAuthorityInput<NativeSubjectId> = Shared.ProofAuthorityInput<NativeSubjectId>;

export type ProofAuthorityTables<
  Subject extends Table,
  Identifier extends Table,
  Credential extends Table,
  NativeSubjectId,
> = Shared.ProofAuthorityTables<
  DrizzleTableModel<Subject>,
  DrizzleTableModel<Identifier>,
  DrizzleTableModel<Credential>,
  NativeSubjectId,
  SQL
>;

export type ProofRequestTable<Request extends Table> = Shared.ProofRequestTable<
  DrizzleTableModel<Request>
>;

export type ProofSeriesTable<Series extends Table> = Shared.ProofSeriesTable<
  DrizzleTableModel<Series>
>;

export type ProofGenerationTable<Generation extends Table> = Shared.ProofGenerationTable<
  DrizzleTableModel<Generation>
>;

export type ProofContinuationRecord = Shared.ProofContinuationRecord;

export type ProofContinuationTable<Continuation extends Table> = Shared.ProofContinuationTable<
  DrizzleTableModel<Continuation>
>;

export type ProofRateScopeTable<RateScope extends Table> = Shared.ProofRateScopeTable<
  DrizzleTableModel<RateScope>
>;

export type ProofAbuseEventTable<AbuseEvent extends Table> = Shared.ProofAbuseEventTable<
  DrizzleTableModel<AbuseEvent>
>;

export type ProofFailureEventTable<FailureEvent extends Table> = Shared.ProofFailureEventTable<
  DrizzleTableModel<FailureEvent>
>;

export type ProofCommandTable<Command extends Table> = Shared.ProofCommandTable<
  DrizzleTableModel<Command>
>;

export type RequiredProofConstraints = Shared.RequiredProofConstraints;

export const requiredProofConstraints = Shared.requiredProofConstraints;

export type ProofConstraintClassifier = Shared.ProofConstraintClassifier;

export type ProofD1Clock = Shared.ProofD1Clock<SQL>;

export type ProofPersistenceMapping<
  Request extends Table,
  Series extends Table,
  Generation extends Table,
  Continuation extends Table,
  RateScope extends Table,
  AbuseEvent extends Table,
  FailureEvent extends Table,
  Command extends Table,
  Subject extends Table,
  Identifier extends Table,
  Credential extends Table,
  NativeSubjectId,
> = Shared.ProofPersistenceMapping<
  DrizzleTableModel<Request>,
  DrizzleTableModel<Series>,
  DrizzleTableModel<Generation>,
  DrizzleTableModel<Continuation>,
  DrizzleTableModel<RateScope>,
  DrizzleTableModel<AbuseEvent>,
  DrizzleTableModel<FailureEvent>,
  DrizzleTableModel<Command>,
  DrizzleTableModel<Subject>,
  DrizzleTableModel<Identifier>,
  DrizzleTableModel<Credential>,
  NativeSubjectId,
  SQL
>;

export type D1ProofPersistenceMapping<
  Request extends Table,
  Series extends Table,
  Generation extends Table,
  Continuation extends Table,
  RateScope extends Table,
  AbuseEvent extends Table,
  FailureEvent extends Table,
  Command extends Table,
  Subject extends Table,
  Identifier extends Table,
  Credential extends Table,
  NativeSubjectId,
> = Shared.D1ProofPersistenceMapping<
  DrizzleTableModel<Request>,
  DrizzleTableModel<Series>,
  DrizzleTableModel<Generation>,
  DrizzleTableModel<Continuation>,
  DrizzleTableModel<RateScope>,
  DrizzleTableModel<AbuseEvent>,
  DrizzleTableModel<FailureEvent>,
  DrizzleTableModel<Command>,
  DrizzleTableModel<Subject>,
  DrizzleTableModel<Identifier>,
  DrizzleTableModel<Credential>,
  NativeSubjectId,
  SQL
>;

export type AnyProofPersistenceMapping = ProofPersistenceMapping<
  Table,
  Table,
  Table,
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
