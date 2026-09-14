# Learning more about the Effect

This repository uses the Effect Typescript library.

Before writing any Effect code, first read `node_modules/effect/AGENTS.md`
**completely**, and follow the links in the file when required.

If you need to learn more about particular Effect apis and concepts that the
guide doesn't cover, search through the source code in `node_modules/effect/src`.

# Effect Atom client boundary

Effect Atom owns client queries, mutations, shared state, and workflows.
Keep business logic in Effect: compose multi-step client workflows as atoms,
declare cross-query invalidation as reactivity keys on mutations, and keep
promise-mode dispatches at the React boundary logic-free — no `.then` chains
in components or routes.

## Project command policy

Vite+ is the unified toolchain and command authority for this repository. It wraps Vite, Rolldown, Vitest, tsdown, Oxlint, Oxfmt, and Vite Task behind the `vp` CLI; Vite+ is distinct from Vite.

Run `vp help` for available commands and `vp <command> --help` for command-specific options. Documentation is available locally in `node_modules/vite-plus/docs` and online at https://viteplus.dev/guide/.

Use these repository commands:

- Install dependencies: `vp install`.
- Full validation: `vp run check`.
- Static checks: `vp check`.
- Format check: `vp fmt --check`; format fixes: `vp fmt`.
- Lint only: `vp lint`; lint fixes: `vp lint --fix`.
- Tests only: `vp test`.
- Other repository tasks and package scripts: `vp run <task>`.
- Toolchain or runtime troubleshooting: run `vp env doctor` and include its output when asking for help.

Do not use `bun run`, `npm run`, `pnpm run`, or `yarn run` in this repository. Do not invoke underlying tools such as `tsc`, `vitest`, `oxlint`, or `oxfmt` directly; use the Vite+ entry points above.

# Instructions for implementation agents

This repository is designed to be implemented by a large, parallel AI-assisted project. Every
agent must preserve a common domain language, dependency direction, and durability contract.

## Required reading

Before editing code:

1. Read `README.md`.
2. Read `GLOSSARY.md` when changing domain concepts or public terminology.
3. Read `docs/TOOLCHAIN.md`.
4. Read the relevant guide, API comments, and neighboring tests for the modules in scope.
5. Read `node_modules/effect/AGENTS.md` before writing Effect code (the canonical Effect
   guidance; `.agents/skills` carries the focused task skills).
6. Read `.agents/skills/effect-development/references/cli/index.md` before creating or
   changing repository scripts.
7. Inspect neighboring package tests before introducing a new pattern.

Keep user-facing behavior in existing guides, implementation contracts beside the code, and
regression evidence in tests. Explain change rationale in the pull request. Do not create separate
specifications, planning documents, decision registers, ADRs, roadmaps, or evidence logs.

## Non-negotiable architecture rules

1. Public asynchronous operations return `Effect` or `Stream`, not naked `Promise` values.
2. Expected failures remain typed in `E`; dependency requirements remain visible in `R`.
3. Effect `Schema` is the canonical source for persisted and transported values.
4. Every acquired resource belongs to `Scope`. The library must not create daemon fibers.
5. Security decisions fail closed. Credentials, provider claims, and caller payloads are untrusted.
6. Private credential delivery stays outside public operation results and telemetry.
7. No code may claim exactly-once external side-effect execution. Unknown commit outcomes do
   not authorize repeating credential issuance or provider exchange.
8. Concurrency is bounded and uses Effect structured concurrency.
9. Node platform assumptions must not enter core domain modules.

## Designing strategies

Strategy constructors configure behavior; default to `make()` where possible and derive
identities from the Auth definition. Supply storage, delivery, secrets, and provider config
through required services and Layers. Optional rendering uses a defaulted service.
Adapter Layers require their config and platform services; keep every dependency visible in `R`.
Do not add strategies or constructor callbacks merely to forward service dependencies.
Guides show concrete Layer construction and distinguish library defaults from application policy.

## Package dependency direction

```text
identity and operation contracts <- authentication strategies <- persistence/protocol adapters
public @yielded/auth modules <- consumer examples
```

An inward module must not import an outward adapter. Define or deepen an inward port and
implement an outward adapter when necessary. Applications own subject identifiers, account
provisioning, transaction authority, policy, and delivery.

Framework code lives in `packages/*`; do not create an `apps/` workspace. Runnable consumer
examples live in `examples/*`, remain leaf workspaces, and import the package's public modules.
Internal adapter fixtures remain under the owning package's `test/fixtures`. Create a new
framework package only for a new concern agreed with the repository owner.

## Toolchain rules

- Bun `1.4.0` is the package manager. Use `catalog:` for shared dependencies and `workspace:*`
  for repository packages.
- The root catalog is the single source for the exact Effect v4 version. Do not pin Effect
  independently in a package.
- After changing an Effect-family version, run `vp install` and `vp run check`.
- Contributor skills under `.agents/skills` are repo-owned, each tracked by its own
  `.dev-kit-origin.json` receipt. Check for upstream updates with
  `bunx @danieljvdm/dev-kit@latest skills status`, and fast-forward an unmodified skill with
  `bunx @danieljvdm/dev-kit@latest skills update <name>`; a skill with local edits is left for an
  agent merge instead of being overwritten. Add a new skill from the approved catalog with
  `bunx @danieljvdm/dev-kit@latest skills add <name>`.
- Contributor agent skills are repository tooling. They are not runtime Skill definitions and
  must not be imported by `@yielded/auth`.
- Before handoff, run `vp run ready`.

## Change discipline

- Add or update Effect Schema definitions before implementing new wire or persisted values.
- Identify requested observable outcomes and the cheapest sufficient proof before substantial work.
- Preserve existing regression suites. Add a committed test only for a current failure or an
  explicit human request; load the `testing` skill before adding one. A new source file alone
  does not justify a test. Keep one regression per incident at the strongest boundary.
- Put tests under the owning package's `test/`, mirroring source paths. Keep shared helpers,
  fixtures, and mocks there, not in `src/`. Database tests use in-process PGlite or SQLite.
- Reuse passing evidence until relevant inputs change. Distinguish in-scope defects from
  unrelated failures or unavailable environments before rerunning checks.
- Update existing guides or API comments when a change affects their documented behavior.
- Explain rejected alternatives in the pull request when a future agent could reasonably
  re-propose them.
- Do not silently widen errors to `unknown`, `Error`, or `any`.
- Do not use type assertions to cross a schema boundary.
- Yielded Auth is pre-production. Keep one current implementation per workflow; update internal
  contracts in place and remove superseded aliases or migration shims. Prefer resetting affected
  development data and state the reset scope. External contracts require explicit compatibility.
  Preserve authorization, validation, durable identities, and receipts needed for safe retries.
- Write changesets as one or two imperative sentences naming the consumer-visible change. Add only
  a short usage example or an explicit BEHAVIOR CHANGE note when consumers must act; keep IDs,
  root-cause, review and test stories, and implementation mechanics in the pull request.

## Parallel work

Parallel agents must own disjoint packages or documents. Shared domain schemas, error unions,
authentication records, and public exports require one designated integrator. Before merging parallel
branches, run:

1. `vp run ready`;
2. adapter contract suites;
3. generated schema fixture checks;
4. relevant crash/fault tests.

## Completion standard

A feature is not complete merely because the happy path works. It is complete when:

- its interface, invariants, and error modes are documented;
- success, expected failure, defect, timeout, and interruption paths are tested;
- resource finalizers are verified;
- durable commit and retry boundaries are specified when persistence is involved;
- security and telemetry behavior are defined;
- public examples compile;
- no forbidden dependency crosses into core.

## Repository boundaries

`main` requires a pull request and the `ready` check. Use `open-pull-request` when preparing
or publishing PRs. When green and approved for landing, squash and delete the branch without
bypassing checks. Bring main into a branch only to resolve a real conflict.

Keep package READMEs to purpose, ownership, and non-obvious constraints. Code, schemas,
configuration, and command help own implementation details; investigations belong in issues or
pull requests. Do not patch owned dependencies in this consumer; fix and release their owners.
