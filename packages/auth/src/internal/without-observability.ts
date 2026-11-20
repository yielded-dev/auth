import * as Console from "effect/Console";
import * as Context from "effect/Context";
import * as References from "effect/References";
import * as Tracer from "effect/Tracer";

/** Captured dependencies win; logging and tracing belong to the invoking fiber. */
export const withoutObservability = <R>(context: Context.Context<R>): Context.Context<R> =>
  Context.omit(
    Tracer.ParentSpan,
    Tracer.Tracer,
    Tracer.CurrentTraceLevel,
    Tracer.MinimumTraceLevel,
    Console.Console,
    References.CurrentLoggers,
    References.CurrentLogLevel,
    References.MinimumLogLevel,
    References.LogToStderr,
    References.CurrentLogAnnotations,
    References.CurrentLogSpans,
    References.CurrentStackFrame,
    References.TracerEnabled,
    References.TracerTimingEnabled,
    References.TracerSpanAnnotations,
    References.TracerSpanLinks,
  )(context) as Context.Context<R>;
