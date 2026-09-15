import { Schema } from "effect";

export class EmailRejected extends Schema.TaggedError<EmailRejected>()("EmailRejected", {}) {}

export class EmailUnavailable extends Schema.TaggedError<EmailUnavailable>()(
  "EmailUnavailable",
  {},
) {}

export class EmailActionRequired extends Schema.TaggedError<EmailActionRequired>()(
  "EmailActionRequired",
  {},
) {}

export class EmailMethodUnsupported extends Schema.TaggedError<EmailMethodUnsupported>()(
  "EmailMethodUnsupported",
  {},
) {}

export class EmailConfigurationError extends Schema.TaggedError<EmailConfigurationError>()(
  "EmailConfigurationError",
  {},
) {}
