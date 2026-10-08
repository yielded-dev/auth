import { D1Client } from "@effect/sql-d1/D1Client";
import { PersistenceConfigurationError } from "@yielded/auth-persistence/Adapter";
import { sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/d1";
import { formatToMillis, getMigrationsToRun } from "drizzle-orm/migrator.utils";
import { upgradeAsyncIfNeeded } from "drizzle-orm/up-migrations/sqlite";
import { Crypto, DateTime, Effect, Layer, Schema } from "effect";

const MigrationFiles = Schema.Record(Schema.String, Schema.NonEmptyString);
const MigrationName = Schema.String.check(Schema.isPattern(/^\d{14}_.+$/));

const configurationError = () =>
  PersistenceConfigurationError.make({
    reason: "Could not apply D1 migrations; check the bundled SQL and database binding",
  });

const JournalRows = Schema.Array(
  Schema.Struct({
    id: Schema.Int,
    hash: Schema.String,
    created_at: Schema.String,
    name: Schema.NullOr(Schema.String),
  }),
);

/** Drizzle's D1 migration journal and selection, with bundled SQL in place of
 * filesystem loading. Pending statements and journal entries share one D1 batch.
 * Applications own when migrations run; do not run competing migration owners.
 */
export const d1MigrationsLayer = (options: {
  readonly migrations: Readonly<Record<string, string>>;
  readonly migrationsTable?: string;
}) =>
  Layer.effectDiscard(
    Effect.gen(function* () {
      const files = yield* Schema.decodeEffect(MigrationFiles)(options.migrations);
      const client = yield* D1Client;
      const crypto = yield* Crypto.Crypto;
      const appliedAt = DateTime.formatIso(yield* DateTime.now);

      const migrations = yield* Effect.forEach(
        Object.entries(files).sort(([left], [right]) => left.localeCompare(right)),
        Effect.fnUntraced(function* ([name, contents]) {
          yield* Schema.decodeEffect(MigrationName)(name);

          const folderMillis = yield* Schema.decodeEffect(Schema.Int)(
            formatToMillis(name.slice(0, 14)),
          );

          const digest = yield* crypto.digest("SHA-256", new TextEncoder().encode(contents));

          return {
            name,
            folderMillis,
            hash: Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join(""),
            sql: contents.split("--> statement-breakpoint"),
            bps: true,
          };
        }),
      );

      yield* Effect.tryPromise({
        try: async () => {
          const db = drizzle(client.config.db);
          const name = options.migrationsTable ?? "__drizzle_migrations";
          const table = sql.identifier(name);
          const { newDb } = await upgradeAsyncIfNeeded(name, db, migrations);

          if (newDb)
            await db.run(sql`create table if not exists ${table} (
              id integer primary key, hash text not null, created_at numeric,
              name text, applied_at text
            )`);

          const journal = Schema.decodeUnknownSync(JournalRows)(
            await db.all(
              sql`select id, hash, cast(created_at as text) as created_at, name from ${table}`,
            ),
          );

          const statements = getMigrationsToRun({
            localMigrations: migrations,
            dbMigrations: [...journal],
          }).flatMap((migration) => [
            ...migration.sql.map((statement) => db.run(sql.raw(statement))),
            db.run(sql`insert into ${table} (hash, created_at, name, applied_at)
                values (${migration.hash}, ${migration.folderMillis}, ${migration.name}, ${appliedAt})`),
          ]);

          const [first, ...rest] = statements;

          if (first !== undefined) await db.batch([first, ...rest]);
        },
        catch: configurationError,
      });
    }).pipe(Effect.mapError(configurationError)),
  );
