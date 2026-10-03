import {
  ActionContext,
  type FunctionReferences,
  Functions,
  OAuthServerPersistence,
} from "@yielded/auth-persistence-convex";
import * as OAuthServer from "@yielded/auth/OAuthServer";
import { Layer } from "effect";

export const oauth = OAuthServer.make("convex-app", { scopes: ["read"] });

/** Build inside each Convex action or HTTP action. The application still supplies
 * oauth.Identity from its authenticated request and owns OAuth keys/client policy.
 * See the Convex guide for schema and internal function registration.
 */
export const makeOAuthLayer = (
  ctx: ActionContext["Service"],
  functions: FunctionReferences,
  options: OAuthServer.Options,
) =>
  oauth
    .layer(options)
    .pipe(
      Layer.provide(
        OAuthServerPersistence.layer.pipe(
          Layer.provide([Layer.succeed(ActionContext, ctx), Layer.succeed(Functions, functions)]),
        ),
      ),
    );
