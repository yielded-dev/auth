import { Schema } from "effect";

const name = Schema.NonEmptyString.check(Schema.isMaxLength(4096));
const instant = Schema.Int.check(Schema.isGreaterThanOrEqualTo(0));
const limit = Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: 500 }));

/** Keys and partitions are application-private; only internal functions accept these commands. */
export const Selection = Schema.Union([
  Schema.TaggedStruct("Point", { partition: name, key: name }),
  Schema.TaggedStruct("Range", {
    partition: name,
    after: Schema.NullOr(Schema.String),
    limit,
  }),
]);

export type Selection = typeof Selection.Type;

export const Document = Schema.Struct({
  id: Schema.String,
  key: name,
  revision: Schema.Natural,
  payload: Schema.String,
});

export type Document = typeof Document.Type;

export const Read = Schema.Struct({
  namespace: name,
  selection: Selection,
  nonce: Schema.optionalKey(name),
});

export const ReadResult = Schema.Struct({ now: instant, rows: Schema.Array(Document) });
export const Observation = Schema.Struct({ selection: Selection, rows: Schema.Array(Document) });
export type Observation = typeof Observation.Type;

export const Write = Schema.Struct({
  partition: name,
  key: name,
  payload: Schema.NullOr(Schema.String),
});

export type Write = typeof Write.Type;

export const Commit = Schema.Struct({
  namespace: name,
  startedAt: instant,
  before: instant,
  observations: Schema.Array(Observation).check(Schema.isMaxLength(128)),
  writes: Schema.Array(Write).check(Schema.isMaxLength(128)),
});

export const CommitResult = Schema.Literals(["Committed", "Conflict", "Expired"]);

export class PersistenceUnavailable extends Schema.TaggedError<PersistenceUnavailable>()(
  "ConvexPersistenceUnavailable",
  {},
) {}

/** The native owner definitively rejected the conditional commit; no writes applied. */
export class TransactionConflict extends Schema.TaggedError<TransactionConflict>()(
  "ConvexTransactionConflict",
  {},
) {}
