import type { TokenDigest } from "@yielded/auth/Schema";
import { Effect } from "effect";

import type { makeNativeSessionPending, SessionPendingKind } from "./session-native-pending";
import type {
  makeNativeSessionAuthorityState,
  NativeSessionAuthorityMapping,
} from "./session-native-state";
import { exactSqlText } from "./sql-change";

/** Both semantic pending ports use the same kind-bound physical snapshot.
 * Distinct native ID encodings use their own bound reads; joined rows still
 * validate each decoded owner before returning current policy. */
export const readNativeSessionPending = Effect.fnUntraced(function* (
  mapping: NativeSessionAuthorityMapping,
  state: Effect.Success<ReturnType<typeof makeNativeSessionAuthorityState>>,
  pending: Effect.Success<ReturnType<typeof makeNativeSessionPending>>,
  kind: SessionPendingKind,
  digest: TokenDigest,
) {
  const { sql, now } = state,
    { p, table } = pending;

  const compatible =
    table.unencodedTextColumn?.(p.subjectId) !== undefined &&
    state.subject.unencodedTextColumn?.(mapping.subject.id) !== undefined &&
    state.credential.unencodedTextColumn?.(mapping.credential.subjectId) !== undefined;

  if (compatible) {
    const pt = table.as("authentication_pending"),
      st = state.joinedSubject,
      ct = state.joinedCredential,
      s = mapping.subject,
      c = mapping.credential;

    const rows =
      yield* sql`select ${pt.fields("p_")}, ${st.fields("s_")}, ${ct.fields("c_")}, ${now} as engine_now from ${pt.name} join ${st.name} on ${exactSqlText(sql, st.column(s.id), pt.column(p.subjectId))} and ${state.activeSubject(st)} left join ${ct.name} on ${exactSqlText(sql, ct.column(c.subjectId), pt.column(p.subjectId))} and ${state.activeCredential(ct)} where ${pending.predicate(pt, kind, digest)} limit 65`;

    if (rows[0] === undefined) return undefined;
    const record = yield* pending.decode(kind, pt.decode(rows[0], "p_"));
    const owner = yield* mapping.subjectId.toNative(record.subjectId);

    const authority = yield* state.decode(
      record.subjectId,
      owner,
      st.decode(rows[0], "s_"),
      rows.map((row) => ct.decode(row, "c_")),
      rows[0].engine_now,
    );

    return authority === undefined ? undefined : { record, authority };
  }
  const selected = yield* pending.read(kind, digest);

  if (selected === undefined) return undefined;
  const authority = yield* state.read(selected.record.subjectId);

  return authority === undefined || authority.now >= selected.record.expiresAtMillis
    ? undefined
    : { record: selected.record, authority };
});
