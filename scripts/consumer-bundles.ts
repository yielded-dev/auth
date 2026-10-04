import { builtinModules } from "node:module";

import { Effect, Path, Schema } from "effect";
import { analyzeMetafile, build } from "esbuild";
import { build as viteBuild } from "vite-plus";

export class BundleBuildError extends Schema.TaggedError<BundleBuildError>()("BundleBuildError", {
  message: Schema.String,
  cause: Schema.optionalKey(Schema.Defect()),
}) {}

export type Bundler = "esbuild" | "vite";

export interface ConsumerChunk {
  readonly fileName: string;
  readonly code: string;
  readonly imports: ReadonlyArray<string>;
  readonly modules: ReadonlyArray<string>;
  readonly entry: boolean;
}

const builtins = new Set([...builtinModules, ...builtinModules.map((name) => `node:${name}`)]);

/** Both verification and size reports bundle the publisher's files with these settings. */
export const buildConsumer = Effect.fn("packageConsumers.build")(function* (
  stage: string,
  probe: string,
  bundler: Bundler,
  server = false,
) {
  const path = yield* Path.Path;
  const external = server ? [...builtins] : [];
  const chunks: Array<ConsumerChunk> = [];

  if (bundler === "esbuild") {
    const result = yield* Effect.tryPromise({
      try: () =>
        build({
          absWorkingDir: stage,
          entryPoints: [`fixtures/${probe}.ts`],
          outdir: `bundles/esbuild/${probe}`,
          entryNames: "entry",
          outExtension: { ".js": ".mjs" },
          bundle: true,
          splitting: true,
          treeShaking: true,
          minify: true,
          format: "esm",
          platform: "browser",
          target: "es2022",
          define: { "process.env.NODE_ENV": '"production"' },
          legalComments: "none",
          external,
          write: false,
          metafile: true,
          logLevel: "silent",
        }),
      catch: (cause) =>
        new BundleBuildError({ message: `Cannot bundle esbuild consumer ${probe}`, cause }),
    });

    for (const file of result.outputFiles) {
      const output = result.metafile.outputs[path.relative(stage, file.path)];

      if (
        output === undefined ||
        output.imports.some((item) => item.external && !(server && builtins.has(item.path)))
      )
        return yield* new BundleBuildError({
          message: `${probe} has missing metadata or unexpected external imports`,
        });
      chunks.push({
        fileName: path.basename(file.path),
        code: file.text,
        imports: output.imports
          .filter((item) => !item.external && item.kind !== "dynamic-import")
          .map((item) => path.basename(item.path)),
        modules: Object.entries(output.inputs)
          .filter(([, input]) => input.bytesInOutput > 0)
          .map(([file]) => file),
        entry: output.entryPoint === `fixtures/${probe}.ts`,
      });
    }

    const analysis = yield* Effect.tryPromise({
      try: () => analyzeMetafile(result.metafile, { verbose: true }),
      catch: (cause) => new BundleBuildError({ message: `Cannot analyze ${probe}`, cause }),
    });

    return { chunks, metadata: JSON.stringify(result.metafile, null, 2), analysis };
  }

  const result = yield* Effect.tryPromise({
    try: () =>
      viteBuild({
        configFile: false,
        root: stage,
        logLevel: "silent",
        define: { "process.env.NODE_ENV": '"production"' },
        build: {
          target: "es2022",
          minify: true,
          write: false,
          lib: { entry: path.join(stage, `fixtures/${probe}.ts`), formats: ["es"] },
          rolldownOptions: {
            external,
            output: {
              entryFileNames: "entry.mjs",
              chunkFileNames: "[name]-[hash].mjs",
              // Library mode otherwise preserves whitespace and path-dependent
              // region comments. Measure final consumer output, not reusable code.
              minify: true,
              comments: false,
            },
          },
        },
      }),
    catch: (cause) =>
      new BundleBuildError({ message: `Cannot bundle Vite consumer ${probe}`, cause }),
  });

  const modules: Array<{ chunk: string; file: string; renderedBytes: number }> = [];

  for (const bundle of Array.isArray(result) ? result : [result]) {
    if (!("output" in bundle))
      return yield* new BundleBuildError({
        message: `Vite ${probe} unexpectedly started a watcher`,
      });
    for (const file of bundle.output) {
      if (file.type !== "chunk") continue;
      if (
        [...file.imports, ...file.dynamicImports].some(
          (name) =>
            !bundle.output.some((output) => output.fileName === name) &&
            !(server && builtins.has(name)),
        )
      )
        return yield* new BundleBuildError({
          message: `Vite consumer ${probe} retained unexpected external imports`,
        });
      const retained = Object.entries(file.modules).filter(([, value]) => value.renderedLength > 0);

      modules.push(
        ...retained.map(([module, value]) => ({
          chunk: file.fileName,
          file: module,
          renderedBytes: value.renderedLength,
        })),
      );
      chunks.push({
        fileName: file.fileName,
        code: file.code,
        imports: file.imports.filter((name) => !builtins.has(name)),
        modules: retained.map(([module]) => module),
        entry: file.isEntry,
      });
    }
  }

  return {
    chunks,
    metadata: JSON.stringify(modules, null, 2),
    analysis: modules
      .sort((left, right) => right.renderedBytes - left.renderedBytes)
      .map((module) => `${module.renderedBytes}\t${module.chunk}\t${module.file}`)
      .join("\n"),
  };
});

/** Initial bytes include every statically reachable shared chunk. */
export const initialChunks = (chunks: ReadonlyArray<ConsumerChunk>) => {
  const initial = new Set(chunks.filter((chunk) => chunk.entry).map((chunk) => chunk.fileName));

  for (const name of initial) {
    for (const imported of chunks.find((chunk) => chunk.fileName === name)?.imports ?? [])
      initial.add(imported);
  }

  return initial;
};
