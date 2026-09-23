import { Context, Effect, Layer, type Schema } from "effect";

import * as Http from "../../http/oauth-app";
import type { Options } from "./models";
import { make as makeWorkflow } from "./workflow";

/** Compose the managed workflow and its HTTP adapter without extra application services. */
export const make = <
  const Id extends string,
  Claims extends Schema.Codec<unknown, unknown, never, never>,
>(
  id: Id,
  input: Parameters<typeof makeWorkflow<Id, Claims>>[1],
) => {
  const app = makeWorkflow(id, input);
  const binding = Http.binding(id);

  const Service = Context.Service<
    { readonly app: Id; readonly kind: "application" },
    (typeof app.Service)["Service"] & {
      readonly handle: (request: Request) => Effect.Effect<Response>;
    }
  >()(`effect-auth/OAuthApp/${id}`);

  const layer = <E, R>(options: Options<E, R>) => {
    const config = { ...options };

    return Layer.effectContext(
      Effect.gen(function* () {
        const workflow = yield* app.Service;
        const sessions = yield* app.Sessions;

        const handle = Http.makeHandler(app, workflow, sessions, {
          ...binding,
          origin: config.origin,
        });

        return Context.make(Service, { ...workflow, handle }).pipe(
          Context.add(app.Sessions, sessions),
        );
      }),
    ).pipe(
      Layer.provide(
        app.layer({ ...config, callbackUrl: `${config.origin}${binding.paths.callback}` }),
      ),
    );
  };

  return {
    Service,
    Sessions: app.Sessions,
    Accounts: app.Accounts,
    Session: app.Session,
    Account: app.Account,
    layer,
    sessionLayer: app.sessionLayer,
    routes: Http.routes(Service, binding.paths),
    paths: binding.paths,
    cookieName: binding.cookieName,
  };
};
