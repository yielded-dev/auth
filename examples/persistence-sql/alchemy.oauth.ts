import * as Alchemy from "alchemy";
import * as Cloudflare from "alchemy/Cloudflare";
import { Config, Effect } from "effect";

/** Independent of the documentation stack. Keep the AUTH binding and class stable. */
export default Alchemy.Stack(
  "yielded-auth",
  { providers: Cloudflare.providers(), state: Cloudflare.state() },
  Effect.gen(function* () {
    yield* Cloudflare.Worker("Auth", {
      name: "yielded-auth",
      main: "./src/oauth-settings-worker.ts",
      compatibility: { date: "2026-07-01", flags: ["nodejs_compat"] },
      domain: { name: "auth.yielded.dev", zoneName: "yielded.dev" },
      workersDev: { enabled: false, previewsEnabled: false },
      assets: { directory: "./dist", runWorkerFirst: true },
      env: {
        AUTH: Cloudflare.DurableObject("AuthV1", { className: "HostedAuth" }),
        AUTH_ORIGIN: "https://auth.yielded.dev",
        GITHUB_CLIENT_ID: Config.NonEmptyString("GITHUB_CLIENT_ID"),
        GITHUB_CLIENT_SECRET: Config.Redacted("GITHUB_CLIENT_SECRET"),
        GITHUB_USER_ID: Config.NonEmptyString("GITHUB_USER_ID"),
        YIELDED_DISPLAY_NAME: Config.NonEmptyString("YIELDED_DISPLAY_NAME"),
        YIELDED_AGENT_ORIGIN: "https://agent.yielded.dev",
        YIELDED_AGENT_CLIENT_SECRET: Config.Redacted("YIELDED_AGENT_CLIENT_SECRET"),
        AUTH_SETTINGS_KEYS: Config.Redacted("AUTH_SETTINGS_KEYS"),
        AUTH_IDENTITY_KEYS: Config.Redacted("AUTH_IDENTITY_KEYS"),
      },
      observability: {
        enabled: false,
        logs: { enabled: false, invocationLogs: false },
        traces: { enabled: false },
      },
      logpush: false,
    });

    return { url: "https://auth.yielded.dev" };
  }),
);
