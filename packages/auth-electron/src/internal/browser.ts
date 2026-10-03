import * as BrowserLogin from "@yielded/auth/BrowserLogin";
import { Effect, Layer, Schema } from "effect";
import { app, shell, type Event } from "electron";

const unavailable = () => BrowserLogin.PlatformError.make({ reason: "unavailable" });

const optionsSchema = Schema.Struct({
  hostedUrl: BrowserLogin.HostedUrl,
  returnUrl: BrowserLogin.ReturnUrl.check(Schema.makeFilter((url) => !url.startsWith("https:"))),
});

/** Acquire synchronously in the main process BEFORE app.whenReady(), under the
 * application's Scope. The host must already hold app.requestSingleInstanceLock().
 * No import-time listeners, protocol registration, or external browser launch.
 * macOS requires a packaged Info.plist; Linux requires an installed .desktop
 * handler. Windows also supports the default Electron executable in development.
 */
export const makeBrowser = Effect.fnUntraced(function* (options: typeof optionsSchema.Type) {
  if (process.type !== "browser" || !app.hasSingleInstanceLock()) return yield* unavailable();

  const config = yield* Schema.decodeEffect(optionsSchema)(options).pipe(
    Effect.mapError(unavailable),
  );

  const scheme = new URL(config.returnUrl).protocol.slice(0, -1);

  const callbackSchema = Schema.String.check(
    Schema.isMaxLength(2304),
    Schema.makeFilter((text) => {
      try {
        const url = new URL(text);
        const keys = [...url.searchParams.keys()];

        if (
          url.href !== text ||
          url.username ||
          url.password ||
          url.hash ||
          keys.length !== 2 ||
          !keys.includes("code") ||
          !keys.includes("state") ||
          !Schema.is(BrowserLogin.Random)(url.searchParams.get("code")) ||
          !Schema.is(BrowserLogin.Random)(url.searchParams.get("state"))
        )
          return false;
        url.search = "";

        return url.href === config.returnUrl;
      } catch {
        return false;
      }
    }),
  );

  const openSchema = Schema.Struct({
    returnUrl: Schema.Literal(config.returnUrl),
    ephemeral: Schema.Literal(false),
    url: Schema.String.check(
      Schema.isMaxLength(config.hostedUrl.length + "?attempt=".length + 43),
      Schema.makeFilter((text) => {
        try {
          const url = new URL(text);

          if (
            url.href !== text ||
            url.hash ||
            [...url.searchParams.keys()].join() !== "attempt" ||
            !Schema.is(BrowserLogin.Random)(url.searchParams.get("attempt"))
          )
            return false;
          url.search = "";

          return url.href === config.hostedUrl;
        } catch {
          return false;
        }
      }),
    ),
  });

  const queued: string[] = [];
  let receive: ((url: string) => void) | undefined;
  let close: (() => void) | undefined;
  let disposed = false;

  const capture = (url: string) => {
    if (disposed || !Schema.is(callbackSchema)(url)) return;
    if (receive !== undefined) receive(url);
    else if (!queued.includes(url) && queued.length < 8) queued.push(url);
  };

  const openUrl = (event: Event, url: string) => {
    if (!Schema.is(callbackSchema)(url)) return;
    event.preventDefault();
    capture(url);
  };

  const secondInstance = (_event: Event, argv: string[]) => {
    for (const arg of argv) capture(arg);
  };

  yield* Effect.acquireRelease(
    Effect.sync(() => {
      app.on("open-url", openUrl);
      app.on("second-instance", secondInstance);
      for (const arg of process.argv) capture(arg);
    }),
    () =>
      Effect.sync(() => {
        disposed = true;
        app.removeListener("open-url", openUrl);
        app.removeListener("second-instance", secondInstance);
        queued.length = 0;
        close?.();
      }),
  );

  const registration = Effect.try({
    try: () => {
      if (!app.isReady() || disposed) return false;
      if (process.platform === "linux")
        return app.isPackaged && app.isDefaultProtocolClient(scheme);
      if (process.platform === "darwin")
        return (
          app.isPackaged &&
          app.setAsDefaultProtocolClient(scheme) &&
          app.isDefaultProtocolClient(scheme)
        );
      if (process.platform !== "win32") return false;
      const args = process.defaultApp ? [app.getAppPath()] : [];

      return (
        app.setAsDefaultProtocolClient(scheme, process.execPath, args) &&
        app.isDefaultProtocolClient(scheme, process.execPath, args)
      );
    },
    catch: unavailable,
  }).pipe(Effect.flatMap((registered) => (registered ? Effect.void : Effect.fail(unavailable()))));

  return BrowserLogin.Browser.of({
    open: Effect.fnUntraced(function* (input) {
      const request = yield* Schema.decodeUnknownEffect(openSchema)(input).pipe(
        Effect.mapError(unavailable),
      );

      yield* registration;

      return yield* Effect.callback<string, BrowserLogin.PlatformError>((resume) => {
        if (receive !== undefined) {
          resume(Effect.fail(BrowserLogin.PlatformError.make({ reason: "busy" })));

          return;
        }
        let active = true;

        const finish = (result: Effect.Effect<string, BrowserLogin.PlatformError>) => {
          if (active) {
            active = false;
            resume(result);
          }
        };

        receive = (url) => finish(Effect.succeed(url));
        close = () => finish(Effect.fail(unavailable()));
        const pending = queued.shift();

        if (pending !== undefined) receive(pending);
        else {
          try {
            void shell.openExternal(request.url).catch(() => finish(Effect.fail(unavailable())));
          } catch {
            finish(Effect.fail(unavailable()));
          }
        }

        return Effect.sync(() => {
          active = false;
          receive = undefined;
          close = undefined;
        });
      }).pipe(
        Effect.timeout("10 minutes"),
        Effect.catchTag("TimeoutError", () =>
          Effect.fail(BrowserLogin.PlatformError.make({ reason: "expired" })),
        ),
      );
    }),
  });
});

/** Build before app readiness, or use makeBrowser for synchronous startup capture. */
export const layerBrowser = (options: typeof optionsSchema.Type) =>
  Layer.effect(BrowserLogin.Browser, makeBrowser(options));
