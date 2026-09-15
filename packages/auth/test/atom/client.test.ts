import * as AuthAtom from "@yielded/auth/Atom";
import * as AuthContract from "@yielded/auth/AuthContract";
import * as Client from "@yielded/auth/Client";
import { Context, Deferred, Effect, Layer, Schema, SchemaGetter, Stream } from "effect";
import { AsyncResult, Atom, AtomRegistry } from "effect/unstable/reactivity";
import { expect, test } from "vite-plus/test";

test("account replacement invalidates application queries and named mutation callers settle", () =>
  Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const contract = AuthContract.make("test/invalidation", { claims: Schema.Struct({}) });
        const memoMap = yield* Layer.makeMemoMap;
        const factory = Atom.context({ memoMap });
        const runtime = factory(Layer.empty);

        const registry = yield* Effect.acquireRelease(
          Effect.sync(() => AtomRegistry.make()),
          (value) => Effect.sync(() => value.dispose()),
        );

        let reads = 0;

        const projects = runtime
          .atom(Effect.sync(() => ++reads))
          .pipe(factory.withReactivity(["projects"]));

        yield* AtomRegistry.mount(registry, projects);

        const observed = (count: number) =>
          AtomRegistry.toStreamResult(registry, projects).pipe(
            Stream.filter((value) => value === count),
            Stream.take(1),
            Stream.runDrain,
            Effect.timeout("1 second"),
          );

        yield* observed(1);

        const AppClient = Client.make(contract, {
          baseUrl: "https://example.test",
          fetch: async () =>
            Response.json({
              _tag: "Success",
              value: { clearCredential: true, invalidation: "client-only" },
            }),
        });

        const auth = AuthAtom.make(AppClient, {
          runtime: factory,
          reactivityKeys: { signOut: ["projects"] },
        });

        const context = yield* AtomRegistry.getResult(registry, auth.runtime);
        const client = Context.get(context, AppClient);
        const lifetime = Context.get(context, AuthAtom.AuthAtomLifetime);

        yield* client.auth.signOut();
        yield* observed(2);

        const previous = yield* lifetime.get;

        yield* AtomRegistry.mount(registry, auth.signOut);
        registry.set(auth.signOut, undefined);
        expect(yield* AtomRegistry.getResult(registry, auth.signOut)).toEqual({
          clearCredential: true,
          invalidation: "client-only",
        });
        yield* observed(3);
        expect((yield* lifetime.get).registry).not.toBe(previous.registry);
        expect(previous.registry.getNodes().size).toBe(0);

        const mutation = AuthAtom.mutation(contract.actions.signOut.route, {
          runtime: auth.runtime,
          reactivityKeys: ["projects"],
          subject: { fromSuccess: () => null },
        });

        yield* AtomRegistry.mount(registry, mutation);
        registry.set(mutation, undefined);
        yield* observed(4);

        const workflow = AuthAtom.workflow<void>()(
          auth.runtime,
          () =>
            Effect.gen(function* () {
              const flow = yield* AuthAtom.AuthAtomWorkflow;

              return yield* flow.completeAuthentication(
                contract.actions.signOut.route,
                undefined,
                () => null,
              );
            }),
          { reactivityKeys: ["projects"] },
        );

        yield* AtomRegistry.mount(registry, workflow);
        registry.set(workflow, undefined);
        yield* observed(5);
      }),
    ),
  ));

test("a query with an undefined encoded input remains a no-argument atom after decoding", () =>
  Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const contract = AuthContract.make("test/query-input", {
          claims: Schema.Struct({}),
          actions: () => ({
            status: AuthContract.action({
              payload: Schema.Undefined.pipe(
                Schema.decodeTo(Schema.Literal("default"), {
                  decode: SchemaGetter.succeed("default"),
                  encode: SchemaGetter.succeed(undefined),
                }),
              ),
              success: Schema.String,
              error: Schema.Never,
              mode: "query",
            }),
          }),
        });

        let calls = 0;

        const AppClient = Client.make(contract, {
          baseUrl: "https://example.test",
          fetch: async () => {
            calls++;

            return Response.json({ _tag: "Success", value: "available" });
          },
        });

        const auth = AuthAtom.make(AppClient);

        const registry = yield* Effect.acquireRelease(
          Effect.sync(() => AtomRegistry.make()),
          (value) => Effect.sync(() => value.dispose()),
        );

        expect(yield* AtomRegistry.getResult(registry, auth.status)).toBe("available");
        expect(calls).toBe(1);
      }),
    ),
  ));

test("latest named authentication settles after interrupted admission and failures discard previous values", () =>
  Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const authContract = AuthContract.make("test/mutation-race", {
          claims: Schema.Struct({}),
          actions: () => ({
            authenticate: AuthContract.action({
              payload: Schema.String,
              success: Schema.String,
              error: Schema.String,
              mode: "mutation",
              credentials: true,
              subject: { fromSuccess: (value) => (value === "pending" ? undefined : value) },
            }),
          }),
        });

        const first = yield* Deferred.make<Response>();
        const second = yield* Deferred.make<Response>();
        const enteredFirst = yield* Deferred.make<void>();
        const enteredSecond = yield* Deferred.make<void>();
        let calls = 0;

        const AppClient = Client.make(authContract, {
          baseUrl: "https://example.test",
          fetch: () => {
            calls++;
            if (calls === 1)
              return Promise.resolve(Response.json({ _tag: "Success", value: "old-member" }));
            if (calls === 2)
              return Promise.resolve(Response.json({ _tag: "Failure", error: "denied" }));
            const entered = calls === 3 ? enteredFirst : enteredSecond;
            const response = calls === 3 ? first : second;

            return Effect.runPromise(
              Deferred.succeed(entered, undefined).pipe(Effect.andThen(Deferred.await(response))),
            );
          },
        });

        const auth = AuthAtom.make(AppClient);

        const r = yield* Effect.acquireRelease(
          Effect.sync(() => AtomRegistry.make()),
          (registry) => Effect.sync(() => registry.dispose()),
        );

        const result = <A, E>(
          registry: AtomRegistry.AtomRegistry,
          atom: Atom.Atom<AsyncResult.AsyncResult<A, E>>,
        ) =>
          AtomRegistry.getResult(registry, atom, { suspendOnWaiting: true }).pipe(
            Effect.timeout("1 second"),
          );

        yield* AtomRegistry.mount(r, auth.authenticate);
        r.set(auth.authenticate, "old");
        expect(yield* result(r, auth.authenticate)).toBe("old-member");
        r.refresh(auth.authenticate);
        expect(yield* result(r, auth.authenticate)).toBe("old-member");
        expect(calls).toBe(1);
        r.set(auth.authenticate, "denied");
        expect(yield* Effect.flip(result(r, auth.authenticate))).toBe("denied");
        expect(AsyncResult.value(r.get(auth.authenticate))._tag).toBe("None");
        r.set(auth.authenticate, "first");
        yield* Deferred.await(enteredFirst);
        r.set(auth.authenticate, "second");
        yield* Deferred.succeed(first, Response.json({ _tag: "Success", value: "pending" }));
        yield* Deferred.await(enteredSecond);
        yield* Deferred.succeed(second, Response.json({ _tag: "Success", value: "new-member" }));
        expect(yield* result(r, auth.authenticate)).toBe("new-member");
        expect(calls).toBe(4);
      }),
    ),
  ));

test("server session snapshots are inert and live verification retires the display seed", () =>
  Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const contract = AuthContract.make("test/session-seed", {
          claims: Schema.Struct({ name: Schema.String }),
        });

        const seed = {
          sessionId: "session",
          subjectId: "member",
          securityRevision: "1",
          assurance: { method: "password", factors: ["knowledge"], authenticatedAt: 0 },
          issuedAt: 0,
          expiresAt: 9999999999999,
          absoluteExpiresAt: 9999999999999,
          claims: { name: "Ada" },
        };

        let calls = 0;

        const AppClient = Client.make(contract, {
          baseUrl: "https://example.test",
          fetch: async () => {
            calls++;

            return Response.json({ _tag: "Success", value: null });
          },
        });

        const registry = yield* Effect.acquireRelease(
          Effect.sync(() => AtomRegistry.make()),
          (value) => Effect.sync(() => value.dispose()),
        );

        const plain = AuthAtom.make(AppClient);

        expect(Atom.getServerValue(plain.session, registry)._tag).toBe("Initial");
        expect(calls).toBe(0);
        const auth = AuthAtom.make(AppClient, { initialSession: seed });

        yield* AtomRegistry.getResult(registry, auth.runtime);
        expect(Atom.getServerValue(auth.session, registry)).toMatchObject({
          _tag: "Success",
          value: { claims: { name: "Ada" } },
        });
        expect(calls).toBe(0);
        expect(
          yield* AtomRegistry.getResult(registry, auth.session, { suspendOnWaiting: true }),
        ).toBe(null);
        expect(calls).toBe(1);
        expect(Atom.getServerValue(auth.session, registry)._tag).toBe("Initial");
      }),
    ),
  ));

test("synchronous account replacement publishes a fresh query value", () =>
  Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const contract = AuthContract.make("test/synchronous-replacement", {
          claims: Schema.Struct({}),
        });

        const AppClient = Client.make(contract, { baseUrl: "https://example.test" });
        const auth = AuthAtom.make(AppClient);

        const registry = yield* Effect.acquireRelease(
          Effect.sync(() => AtomRegistry.make()),
          (value) => Effect.sync(() => value.dispose()),
        );

        let reads = 0;

        const query = auth.runtime.atom(
          Effect.gen(function* () {
            reads++;
            if (reads === 1) {
              const lifetime = yield* AuthAtom.AuthAtomLifetime;

              yield* lifetime.replaceSubject(null);

              return "retired";
            }

            return "current";
          }),
        );

        expect(
          yield* AtomRegistry.getResult(registry, query).pipe(Effect.timeout("1 second")),
        ).toBe("current");
        expect(reads).toBe(2);
      }),
    ),
  ));
