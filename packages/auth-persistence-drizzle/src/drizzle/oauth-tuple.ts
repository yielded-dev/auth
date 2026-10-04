import type { OAuthExternalIdentity } from "@yielded/auth/OAuth";
/* oxlint-disable no-explicit-any -- private owner kernel retains the captured native mapping. */
import { sql } from "drizzle-orm";
import { Effect } from "effect";

import { both, equal, matchesNativeRow, CurrentOAuthTransaction } from "./oauth-owner";
import { invariant, oauthIdentityKey } from "./oauth-state";

export const readTuple = (ownership: any, identity: typeof OAuthExternalIdentity.Type) =>
  Effect.flatMap(CurrentOAuthTransaction, (owner) =>
    Effect.gen(function* () {
      const t = ownership.tuple,
        key = oauthIdentityKey(identity);

      const where = { [t.identityKey]: key };
      const observed = yield* owner.read(t.table, equal(t.table, where), { limit: 1 });

      if (observed.rows.length === 0) {
        const values = {
          ...t.encodeInsert({ identityKey: key, identity }),
          ...where,
          [t.provider]: identity.provider,
          [t.issuer]: identity.issuer,
          [t.externalSubject]: identity.subject,
          [t.state]: "Unowned",
          [t.version]: owner.marker,
          [t.subjectId]: null,
          [t.reservation]: null,
        };

        const inserted = yield* owner.insert(t.table, values, where, true);

        observed.rows = inserted.rows;
      }
      const row = observed.rows[0]!;

      invariant(
        row[t.provider] === identity.provider &&
          row[t.issuer] === identity.issuer &&
          row[t.externalSubject] === identity.subject &&
          ["Unowned", "Reserved", "Owned"].includes(row[t.state]),
      );
      invariant(
        row[t.state] === "Owned"
          ? row[t.subjectId] !== null
          : row[t.subjectId] === null &&
              (row[t.state] === "Reserved"
                ? typeof row[t.reservation] === "string"
                : row[t.reservation] === null),
      );
      if (ownership.mode === "separate") {
        const o = ownership.external;

        const external = yield* owner.read(o.table, equal(o.table, { [o.identityKey]: key }), {
          limit: 1,
        });

        if (row[t.state] === "Owned") {
          const linked = external.rows[0];

          invariant(
            linked !== undefined &&
              linked[o.provider] === identity.provider &&
              linked[o.issuer] === identity.issuer &&
              linked[o.externalSubject] === identity.subject &&
              matchesNativeRow(o.table, linked, { [o.subjectId]: row[t.subjectId] }),
          );
          const owned = sql`exists(select 1 from ${o.table} where ${both(equal(o.table, { [o.identityKey]: key }), o.ownedCondition)})`;

          invariant(yield* owner.check(owned));
          owner.postconditions.push(owned);
        } else invariant(external.rows.length === 0);
      }

      return { observed, row, key };
    }),
  );

export const acquireTuple = (
  ownership: any,
  identity: typeof OAuthExternalIdentity.Type,
  key: string,
  subjectId: unknown,
) =>
  Effect.flatMap(CurrentOAuthTransaction, (owner) =>
    Effect.gen(function* () {
      const t = ownership.tuple;

      yield* owner.update(
        t.table,
        { [t.identityKey]: key },
        {
          [t.state]: "Owned",
          [t.subjectId]: subjectId,
          [t.reservation]: null,
          [t.version]: owner.marker,
        },
      );
      if (ownership.mode === "separate") {
        const o = ownership.external;

        const values = {
          ...o.encodeInsert({ identity, identityKey: key, subjectId }),
          [o.identityKey]: key,
          [o.provider]: identity.provider,
          [o.issuer]: identity.issuer,
          [o.externalSubject]: identity.subject,
          [o.subjectId]: subjectId,
        };

        yield* owner.insert(o.table, values, { [o.identityKey]: key });
      }
    }),
  );
