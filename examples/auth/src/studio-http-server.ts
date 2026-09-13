import { Http } from "@yielded/auth";
import * as HttpServer from "@yielded/auth/OperationHttpServer";
import { requireAuthenticated } from "@yielded/auth/Operations";
import { type AnyRelations, eq } from "drizzle-orm";
import type { EffectPgDatabase } from "drizzle-orm/effect-postgres";
import { Effect, Layer } from "effect";

import { StudioAuth } from "./studio-auth";
import { subject } from "./studio-passkey-schema";
import { MemberProfile, transport } from "./studio-transport";

export const memberLayer = (db: EffectPgDatabase<AnyRelations>) =>
  MemberProfile.handlerLayer(
    Effect.fn(function* (_input, invocation) {
      const caller = yield* requireAuthenticated(invocation);

      const [member] = yield* db
        .select()
        .from(subject)
        .where(eq(subject.id, caller.subjectId))
        .pipe(Effect.orDie);

      if (member === undefined) return yield* Effect.die(new Error("Missing current member"));

      return { memberId: caller.subjectId, organization: member.organization, name: member.name };
    }),
  );

/** Localhost uses an explicit insecure cookie override; production uses HTTPS defaults. */
const http = Http.make(StudioAuth, {
  origin: "http://localhost:4179",
  cookie: { prefix: "studio-", secure: false },
  csrf: { header: "x-studio-csrf", value: "operation" },
  maximumBodyBytes: 300000,
});

export const makeStudioHttp = (db: EffectPgDatabase<AnyRelations>) =>
  HttpServer.make(transport).pipe(
    Effect.provide(Layer.mergeAll(http.operationLayer, memberLayer(db))),
  );
