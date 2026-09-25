# Repository toolchain

Vite+ is the command authority; Bun is the package manager and script runtime.
The root catalog owns shared versions, and the lockfile is committed. Workspace
manifests use `catalog:` and `workspace:*`. CI installs the frozen lockfile and
uses the same checks as local development.

## Development

Run `vp install`, then `vp run patch:tsgo`. The prepare hook installs `.vite-hooks`;
the pre-commit hook runs Vite+ checks on staged TypeScript and JavaScript.
`vp run ready` is the handoff gate: static checks, tests, package builds, and docs.
Use `vp help` and command help for task options. Include `vp env doctor` output
when investigating toolchain failures.

Shared strict compiler settings live in `tsconfig.base.json`. Public packages
use Effect as a peer and the exact catalog pin for development. Upgrade the
Effect family together and rerun installation and the handoff gate. Vite+ 0.3.3
bundles Vitest 4.1.11. Root overrides pin `vitest` and `@effect/vitest` to the catalog,
which keeps Effect's test integration on that Vitest despite its Vitest 5 peer range,
matching Effect Agent; keep the catalog `vitest` pin equal to the bundled version. The `preferTypedSchemaDecoder` diagnostic follows the reference repository's disabled
setting until the upstream TypeScript-Go panic is resolved.

Library code lives in `packages/*`; public consumer examples are leaf workspaces
under `examples/*`. Internal adapter fixtures belong to the package's `test/fixtures`.
Every workspace and repository script is typechecked. Add, retain, and remove
tests according to the repository's testing policy; existing coverage is not a quota.

The Drizzle examples run generation through `scripts/db-generate.ts`. It forwards
Drizzle Kit arguments and compacts JSON snapshots to one line. Snapshots are excluded
from formatting and marked as generated in Git; SQL remains available for review.

## Public modules

Use explicit, flat source exports with matching `vp pack` entries. Root namespaces,
the lowercase `contracts` and `strategies` groups, and direct subpaths identify the
same public modules. Group exports retain distinct contract and strategy names.
Internal imports go directly to their owning implementation, without routing
through self-barrels.

The export check validates casing, namespace targets, build entries, and workspace
dependencies, including relative imports through the package's own public barrels.
Core may depend only on Effect; SDK and cryptography implementations belong in
companion packages. The export check enforces
this boundary for runtime imports and declarations. The purity check rejects
production paths that reach test-only code.
`@yielded/auth/Testing` is an explicit test-only entrypoint. SDK adapters live in
companion packages, and `sideEffects: []` requires import-time code to stay free of I/O.

The package build preserves implementation modules and native root/group namespaces
in both JavaScript and declarations. Every namespace target is also an explicit
pack entry. The resolver leaves sibling imports external to root and group entries
so the bundler does not synthesize namespace objects or expose helper exports.
Do not merge unrelated implementations into shared chunks: consumer bundlers can
retain their initialization even when only one API is used.

`vp run check:package-consumers` requires built packages and runs during `build`.
It loads and type-checks every core export with only Effect installed, then every
default persistence export without Drizzle installed. It stages the publisher's
manifests and built files with the selected adapters' required dependencies,
compares equivalent root/group/direct consumers through esbuild and Vite/Rolldown,
checks their declarations, and runs native ESM and bundled consumers. It protects
narrow identity imports, browser contracts, deferred client loading, and root
namespace identity without optional adapter peers. Reported initial/deferred
bytes include Effect and are diagnostics, not fixed size budgets. Retained-module
checks enforce the boundaries; esbuild's re-exported namespace retention remains
visible in the comparisons. The full contracts group must exclude strategy
implementations and cryptography. Keep direct paths for lazy imports and narrow bundles.

## Contributor skills

Repository-owned skills under `.agents/skills` are linked from `.claude/skills`;
Dev Kit copies have individual `.dev-kit-origin.json` receipts. Use the `dev-kit` skill for catalog
updates. Dev Kit is not a runtime dependency or repository lifecycle manager.

## Releases

Changesets maintains the public package's beta release train. Add a changeset for
consumer-visible changes. Do not leave prerelease mode without an explicit release
decision. `release:publish` builds and temporarily converts source manifests to
npm-ready exports and resolves catalog/workspace ranges, then restores the original
files on success, failure, or interruption.

Before enabling automated releases:

1. Give the release GitHub App contents and pull-request write access to this repo.
2. Configure `EFFECT_AUTH_APP_ID` and `EFFECT_AUTH_APP_PRIVATE_KEY` repository secrets.
3. Configure npm trusted publishing for each published package, including
   `@yielded/auth`, `@yielded/auth-persistence`, `@yielded/auth-persistence-drizzle`,
   `@yielded/auth-simplewebauthn`,
   `@yielded/auth-openid-client`, `@yielded/auth-cloudflare`, and `@yielded/auth-crypto`, repository
   `yielded-dev/auth`, workflow `release.yml`. The first npm publication may
   require a manually authenticated owner before trusted publishing can be set.
   Enable direct `npm publish` for this trusted publisher; the release workflow
   does not use staged publishing.
4. Set the repository variable `RELEASE_ENABLED=true`.

The release workflow maintains a version PR using the App token so updates trigger
ordinary CI. After merge, it validates unpublished versions with the full ready gate
and publishes to npm with provenance. Initialization alone does not enable publication.

For a manual release, run the handoff gate, `vp run changeset:version`, and
`vp run release:publish --dry-run`. Once authorized, run `vp run release:publish`
and push the generated tags. The dry run does not publish or create tags. Manual
publishing requires an npm login with access to the `yielded` organization; the
public prerelease is installed as `@yielded/auth@beta`.

## CI and review

CI runs static checks, tests, and builds in separate jobs with a required `ready`
fan-in on pull requests. Vite Task cache entries are reused only when their inputs
match; Vitest's mutable result cache is disabled.

Effect Agent reviews use `GITHUB_TOKEN` and the repository secret `OPENAI_API_KEY`.
Set `PR_REVIEW_ENABLED=true` after the workflow reaches `main`.
The `pr-review-forks` environment requires maintainer
approval; `pr-review` handles same-repository and authorized `@effect-agent review`
comments. Both execute trusted default-branch code, never PR-head code.

## Documentation

The `docs/` workspace is an Astro Starlight site using the shared yielded.dev theme,
`@yielded/starlight-theme` (`yielded-dev/site`). Public pages live in
`docs/src/content/docs/` and the sidebar in `docs/astro.config.ts`.
Run `vp run docs:dev` to edit locally. `vp run docs:build` checks local links and
anchors and produces the static site; `vp run docs:preview` serves that build. Link
pages with relative Markdown paths such as `./sessions.md`. The home page and quick
start include the root README's shared contract, server, and client examples:
Markdown pages use `<!--@include: @/../README.md#region-->` and the MDX home page
uses `<Snippet>`. Guides show feature setup and usage.
This contributor guide stays at the top of `docs/` and is excluded from the public site.

`alchemy.run.ts` deploys the site to `https://yielded.dev/auth/` through the
`effect-auth-docs` Cloudflare Worker at stage `prod`. It uses the account-wide
Cloudflare state store, matching Effect Agent. The Astro base and Worker asset
base both use `/auth/`. The Worker route covers the `/auth` prefix;
other paths on `yielded.dev` remain available for sibling projects. The stack
owns the proxied apex DNS placeholder until a shared Yielded site provides an origin.
The old `effect-auth.com` domain remains attached for TLS and permanently redirects
paths and query strings to the new docs location.
Set `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` in your environment, then run
`vp run docs:plan --stage prod` to review changes or
`vp run docs:deploy --stage prod --yes` to deploy. Alchemy builds the docs and
uses their content hash to avoid unchanged uploads.

The `Deploy docs` workflow runs on relevant changes to `main` and supports manual
dispatch. Configure repository secrets `CLOUDFLARE_API_TOKEN` and
`CLOUDFLARE_ACCOUNT_ID`; Alchemy resolves the shared state-store credentials from
the account's Secrets Store. The token must also be able to manage the Worker and
its custom domain, zone routes, DNS record, and legacy redirect rule in the selected account.
