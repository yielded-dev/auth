import { gzip } from "node:zlib";

import { NodeRuntime, NodeServices } from "@effect/platform-node";
import { Console, Effect, FileSystem, Option, Path, Schema, Stream } from "effect";
import { Command, Flag } from "effect/cli";
import { ChildProcess } from "effect/process";
import { version as esbuildVersion } from "esbuild";
import { version as viteVersion } from "vite-plus";

import { bundleFixtures } from "./bundle-fixtures.ts";
import { buildConsumer, initialChunks, type Bundler } from "./consumer-bundles.ts";
import { PublishManifest, withPublishManifests } from "./release-publish.ts";

class BundleSizeError extends Schema.TaggedError<BundleSizeError>()("BundleSizeError", {
  message: Schema.String,
  cause: Schema.optionalKey(Schema.Defect()),
}) {}

const Bytes = Schema.Struct({ raw: Schema.Int, gzip: Schema.Int });

const BundleSize = Schema.Struct({
  initial: Bytes,
  deferred: Bytes,
  total: Bytes,
  chunks: Schema.Array(
    Schema.Struct({ file: Schema.String, initial: Schema.Boolean, ...Bytes.fields }),
  ),
});

const Environment = Schema.Struct({ revision: Schema.String, effect: Schema.String });

const BundleReport = Schema.Struct({
  schemaVersion: Schema.Literal(1),
  bundlers: Schema.Struct({ esbuild: Schema.String, vite: Schema.String }),
  settings: Schema.Struct({
    format: Schema.Literal("esm"),
    target: Schema.Literal("es2022"),
    resolution: Schema.Literal("browser"),
    minify: Schema.Literal(true),
    compression: Schema.Literal("gzip level 9 per chunk"),
    builtins: Schema.Literal("external for server probes"),
  }),
  base: Environment,
  head: Environment,
  fixtures: Schema.Array(
    Schema.Struct({
      name: Schema.String,
      bundler: Schema.Literals(["esbuild", "vite"]),
      base: Schema.NullOr(BundleSize),
      head: BundleSize,
      missingBaseExports: Schema.Array(Schema.String),
    }),
  ),
});

type BundleReport = typeof BundleReport.Type;

// Effect has no compression service. Node's gzip stays at this typed boundary.
const gzipBytes = (bytes: Uint8Array) =>
  Effect.callback<number, BundleSizeError>((resume) => {
    gzip(bytes, { level: 9 }, (cause, compressed) =>
      resume(
        cause
          ? Effect.fail(new BundleSizeError({ message: "Could not gzip bundle chunk", cause }))
          : Effect.succeed(compressed.byteLength),
      ),
    );
  });

const measureBundle = Effect.fn("bundleSize.measure")(function* (
  stage: string,
  name: string,
  bundler: Bundler,
  server: boolean,
  output: string,
) {
  const fs = yield* FileSystem.FileSystem;
  const path = yield* Path.Path;
  const built = yield* buildConsumer(stage, name, bundler, server);

  if (built.chunks.filter((chunk) => chunk.entry).length !== 1)
    return yield* new BundleSizeError({ message: `${bundler}/${name} must emit one entry` });
  const initial = initialChunks(built.chunks);

  yield* fs.makeDirectory(output, { recursive: true });

  const chunks = yield* Effect.forEach(
    built.chunks,
    Effect.fn(function* (chunk) {
      const bytes = new TextEncoder().encode(chunk.code);

      yield* fs.writeFile(path.join(output, chunk.fileName), bytes);

      return {
        file: chunk.fileName,
        initial: initial.has(chunk.fileName),
        raw: bytes.byteLength,
        gzip: yield* gzipBytes(bytes),
      };
    }),
  );

  const sum = (selected: typeof chunks) => ({
    raw: selected.reduce((total, chunk) => total + chunk.raw, 0),
    gzip: selected.reduce((total, chunk) => total + chunk.gzip, 0),
  });

  yield* fs.writeFileString(path.join(output, "meta.json"), built.metadata);
  yield* fs.writeFileString(path.join(output, "modules.txt"), built.analysis);

  return {
    initial: sum(chunks.filter((chunk) => chunk.initial)),
    deferred: sum(chunks.filter((chunk) => !chunk.initial)),
    total: sum(chunks),
    chunks,
  } satisfies typeof BundleSize.Type;
});

const revision = Effect.fn("bundleSize.revision")(function* (root: string) {
  const child = yield* ChildProcess.make("git", ["rev-parse", "HEAD"], {
    cwd: root,
    stdout: "pipe",
    stderr: "ignore",
  });

  const [output, code] = yield* Effect.all([
    Stream.mkString(Stream.decodeText(child.stdout)),
    child.exitCode,
  ]);

  return code === 0 ? output.trim() : "unversioned checkout";
}, Effect.scoped);

const measureCheckout = Effect.fn("bundleSize.checkout")(function* (
  root: string,
  fixtures: string,
  output: string,
  allowMissing: boolean,
) {
  const fs = yield* FileSystem.FileSystem;
  const path = yield* Path.Path;

  const stage = yield* fs
    .makeTempDirectoryScoped({ prefix: "yielded-auth-bundles-" })
    .pipe(Effect.flatMap((directory) => fs.realPath(directory)));

  const available = new Set<string>();
  const decodeManifest = Schema.decodeUnknownEffect(Schema.fromJsonString(PublishManifest));

  yield* fs.copyFile(path.join(root, "package.json"), path.join(stage, "package.json"));
  // Head consumer sources are shared with the baseline, including relative imports.
  yield* fs.copy(fixtures, path.join(stage, "fixtures"));
  for (const fixture of bundleFixtures) {
    if (fixture.source !== undefined)
      yield* fs.writeFileString(path.join(stage, "fixtures", `${fixture.name}.ts`), fixture.source);
  }

  for (const directory of (yield* fs.readDirectory(path.join(root, "packages"))).sort()) {
    if (directory.startsWith(".")) continue;
    const source = path.join(root, "packages", directory);

    const manifest = yield* decodeManifest(
      yield* fs.readFileString(path.join(source, "package.json")),
    );

    if (manifest.private === true) continue;
    const destination = path.join(stage, "packages", directory);

    yield* fs.makeDirectory(destination, { recursive: true });
    yield* fs.copyFile(path.join(source, "package.json"), path.join(destination, "package.json"));
    // No source files in the stage: all library imports must resolve to published output.
    yield* fs.copy(path.join(source, "dist"), path.join(destination, "dist"));
    const link = path.join(stage, "node_modules", manifest.name);

    yield* fs.makeDirectory(path.dirname(link), { recursive: true });
    yield* fs.symlink(destination, link);
    for (const key of Object.keys(manifest.exports ?? {}))
      available.add(key === "." ? manifest.name : manifest.name + key.slice(1));

    for (const dependency of new Set([
      ...Object.keys(manifest.dependencies ?? {}),
      ...Object.keys(manifest.peerDependencies ?? {}),
    ])) {
      if (dependency.startsWith("@yielded/")) continue;
      const target = path.join(stage, "node_modules", dependency);
      const installed = path.join(source, "node_modules", dependency);

      if ((yield* fs.exists(target)) || !(yield* fs.exists(installed))) continue;
      yield* fs.makeDirectory(path.dirname(target), { recursive: true });
      yield* fs.symlink(yield* fs.realPath(installed), target);
    }
  }

  const results = yield* withPublishManifests(stage, () =>
    Effect.forEach(
      bundleFixtures.flatMap((fixture) =>
        (["esbuild", "vite"] as const).map((bundler) => ({ fixture, bundler })),
      ),
      Effect.fn(function* ({ fixture, bundler }) {
        const missing = fixture.requires.filter((required) => !available.has(required));

        if (missing.length > 0) {
          if (allowMissing) return { name: fixture.name, bundler, size: null, missing };

          return yield* new BundleSizeError({
            message: `Missing public exports: ${missing.join(", ")}`,
          });
        }

        const size = yield* measureBundle(
          stage,
          fixture.name,
          bundler,
          fixture.server === true,
          path.join(output, bundler, fixture.name),
        );

        return { name: fixture.name, bundler, size, missing };
      }),
      { concurrency: 2 },
    ),
  );

  const effect = yield* Schema.decodeUnknownEffect(
    Schema.fromJsonString(Schema.Struct({ version: Schema.String })),
  )(yield* fs.readFileString(path.join(root, "node_modules/effect/package.json")));

  return { results, environment: { revision: yield* revision(root), effect: effect.version } };
});

const kb = (bytes: number) => `${(bytes / 1000).toFixed(2)} kB`;

const renderBundleReport = (report: BundleReport) => {
  const lines = [
    "| Fixture | Bundler | Part | Base gzip | PR gzip | Change | PR minified |",
    "| --- | --- | --- | ---: | ---: | ---: | ---: |",
  ];

  for (const fixture of report.fixtures) {
    for (const part of ["initial", "deferred", "total"] as const) {
      if (
        part !== "initial" &&
        fixture.head.deferred.raw === 0 &&
        (fixture.base?.deferred.raw ?? 0) === 0
      )
        continue;
      const before = fixture.base?.[part].gzip;
      const after = fixture.head[part].gzip;
      const delta = before === undefined ? undefined : after - before;
      const sign = delta !== undefined && delta > 0 ? "+" : "";

      const change =
        delta === undefined || before === undefined
          ? "new export"
          : `${sign}${kb(delta)}${before === 0 ? "" : ` / ${sign}${((delta / before) * 100).toFixed(2)}%`}`;

      lines.push(
        `| ${fixture.name} | ${fixture.bundler} | ${part} | ${before === undefined ? "n/a" : kb(before)} | ${kb(after)} | ${change} | ${kb(fixture.head[part].raw)} |`,
      );
    }
  }

  return lines.join("\n") + "\n";
};

export const compareBundles = Effect.fn("bundleSize.compare")(
  function* (options: {
    readonly root: string;
    readonly base: string;
    readonly output: string;
    readonly baseRevision?: string;
  }) {
    const fs = yield* FileSystem.FileSystem;
    const path = yield* Path.Path;

    // Clear only generated report paths so a failure cannot publish stale success data.
    for (const generated of ["base", "head", "report.json", "report.md"])
      yield* fs.remove(path.join(options.output, generated), { recursive: true, force: true });
    const fixtures = path.join(options.root, "packages/auth/test/packaging");

    const base = yield* measureCheckout(
      options.base,
      fixtures,
      path.join(options.output, "base"),
      true,
    );

    const head = yield* measureCheckout(
      options.root,
      fixtures,
      path.join(options.output, "head"),
      false,
    );

    const comparisons: BundleReport["fixtures"][number][] = [];

    for (const current of head.results) {
      const previous = base.results.find(
        (row) => row.name === current.name && row.bundler === current.bundler,
      );

      if (current.size === null || previous === undefined)
        return yield* new BundleSizeError({
          message: `Incomplete measurement for ${current.name}`,
        });
      comparisons.push({
        name: current.name,
        bundler: current.bundler,
        head: current.size,
        base: previous.size,
        missingBaseExports: previous.missing,
      });
    }

    const report: BundleReport = {
      schemaVersion: 1,
      bundlers: { esbuild: esbuildVersion, vite: viteVersion },
      settings: {
        format: "esm",
        target: "es2022",
        resolution: "browser",
        minify: true,
        compression: "gzip level 9 per chunk",
        builtins: "external for server probes",
      },
      base: { ...base.environment, revision: options.baseRevision ?? base.environment.revision },
      head: head.environment,
      fixtures: comparisons,
    };

    yield* fs.writeFileString(
      path.join(options.output, "report.json"),
      yield* Schema.encodeEffect(Schema.fromJsonString(BundleReport))(report),
    );
    yield* fs.writeFileString(path.join(options.output, "report.md"), renderBundleReport(report));

    return report;
  },
  Effect.scoped,
  Effect.mapError((cause) =>
    cause._tag === "BundleSizeError"
      ? cause
      : new BundleSizeError({
          message: `Bundle comparison failed. Install dependencies and build packages in both checkouts. ${cause.message}`,
          cause,
        }),
  ),
);

export const command = Command.make(
  "bundle-size",
  {
    base: Flag.String("base-dir").pipe(
      Flag.withDescription("Base checkout with installed dependencies and built packages."),
    ),
    baseRevision: Flag.String("base-revision").pipe(
      Flag.withDescription("Revision label for a base snapshot without Git metadata."),
      Flag.optional,
    ),
    output: Flag.String("out-dir").pipe(
      Flag.withDefault(".bundle-report"),
      Flag.withDescription("Write comparisons, emitted chunks, and module analysis here."),
    ),
  },
  Effect.fn(function* ({ base, baseRevision, output }) {
    const path = yield* Path.Path;

    const root = path.resolve(
      path.dirname(yield* path.fromFileUrl(new URL(import.meta.url))),
      "..",
    );

    const report = yield* compareBundles({
      root,
      base: path.resolve(base),
      output: path.resolve(output),
      ...(Option.isSome(baseRevision) ? { baseRevision: baseRevision.value } : {}),
    });

    yield* Console.log(renderBundleReport(report));
  }),
).pipe(
  Command.withDescription(
    "Compare published consumer bundles with esbuild and Vite using browser resolution. Includes Effect and other dependencies; server built-ins are external.",
  ),
);

if (import.meta.main)
  NodeRuntime.runMain(
    Command.run(command, { version: "1.0.0" }).pipe(
      Effect.tapErrorTag("BundleSizeError", (error) => Console.error(error.message)),
      Effect.provide(NodeServices.layer),
    ),
    { disableErrorReporting: true },
  );
