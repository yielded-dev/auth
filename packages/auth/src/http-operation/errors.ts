import { Schema } from "effect";

export class OperationHttpConfigurationError extends Schema.TaggedError<OperationHttpConfigurationError>()(
  "OperationHttpConfigurationError",
  {
    reason: Schema.Literals([
      "route",
      "duplicate-route",
      "duplicate-operation",
      "internal-operation",
      "credentials",
      "cookies",
      "origin",
      "callback",
      "redirect",
    ]),
  },
) {}

export class OperationHttpError extends Schema.TaggedError<OperationHttpError>()(
  "OperationHttpError",
  {
    reason: Schema.Literals([
      "request",
      "not-found",
      "method",
      "origin",
      "csrf",
      "credentials",
      "too-large",
      "response",
      "network",
      "stale-response",
      "private-output",
      "unavailable",
    ]),
  },
) {}
