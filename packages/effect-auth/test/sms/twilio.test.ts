import { it } from "@effect/vitest";
import { SmsDelivery } from "@yielded/auth/SmsDelivery";
import * as Twilio from "@yielded/auth/Twilio";
import { Deferred, Effect, Fiber, Layer, Redacted } from "effect";
import { TestClock } from "effect/testing";
import { HttpClient, HttpClientResponse } from "effect/unstable/http";
import { expect, expectTypeOf } from "vite-plus/test";

const configuration = Layer.succeed(Twilio.TwilioConfig, {
  accountSid: `AC${"0".repeat(32)}`,
  authToken: Redacted.make("test-token"),
  from: "+14155550100",
});

const message = { id: "delivery-1", to: "+14155550123", body: Redacted.make("Code: 123456") };
const send = Effect.flatMap(SmsDelivery, (sms) => sms.send(message));

it.effect("requires config and HTTP, sends a private form once, and releases every response", () =>
  Effect.gen(function* () {
    expectTypeOf<Layer.Services<typeof Twilio.layer>>().toEqualTypeOf<
      Twilio.TwilioConfig | HttpClient.HttpClient
    >();
    for (const [status, outcome] of [
      [201, "Accepted"],
      [400, "DefiniteFailure"],
      [503, "Ambiguous"],
    ] as const) {
      let calls = 0;
      let signal: AbortSignal | undefined;

      const client = HttpClient.make((request, url, abort) =>
        Effect.sync(() => {
          calls++;
          signal = abort;
          expect(request.method).toBe("POST");
          expect(url.href).toBe(
            `https://api.twilio.com/2010-04-01/Accounts/AC${"0".repeat(32)}/Messages.json`,
          );
          expect(request.headers["content-type"]).toBe("application/x-www-form-urlencoded");
          expect(request.headers.authorization).toBe(
            `Basic ${btoa(`AC${"0".repeat(32)}:test-token`)}`,
          );
          if (request.body._tag !== "Uint8Array") throw new Error("Expected an encoded form");
          const form = new URLSearchParams(new TextDecoder().decode(request.body.body));

          expect(Object.fromEntries(form)).toEqual({
            To: message.to,
            From: "+14155550100",
            Body: "Code: 123456",
          });

          return HttpClientResponse.fromWeb(
            request,
            new Response("private provider body", { status }),
          );
        }),
      );

      const result = yield* send.pipe(
        Effect.provide(
          Twilio.layer.pipe(
            Layer.provide(configuration),
            Layer.provide(Layer.succeed(HttpClient.HttpClient, client)),
          ),
        ),
      );

      expect(result._tag).toBe(outcome);
      expect(calls).toBe(1);
      expect(signal?.aborted).toBe(true);
    }
  }),
);

it.effect("contains transport defects and times out without repeating a send", () =>
  Effect.gen(function* () {
    let calls = 0;
    let aborted = false;
    const started = yield* Deferred.make<void>();

    const client = HttpClient.make((_request, _url, signal) =>
      Effect.gen(function* () {
        calls++;
        signal.addEventListener(
          "abort",
          () => {
            aborted = true;
          },
          { once: true },
        );
        yield* Deferred.succeed(started, undefined);

        return yield* Effect.never;
      }),
    );

    const live = Twilio.layer.pipe(
      Layer.provide(configuration),
      Layer.provide(Layer.succeed(HttpClient.HttpClient, client)),
    );

    const fiber = yield* send.pipe(Effect.provide(live), Effect.forkChild);

    yield* Deferred.await(started);
    yield* TestClock.adjust("10 seconds");
    expect(yield* Fiber.join(fiber)).toEqual({ _tag: "Ambiguous" });
    expect(calls).toBe(1);
    expect(aborted).toBe(true);

    const defect = HttpClient.make(() => Effect.die("private transport failure"));

    expect(
      yield* send.pipe(
        Effect.provide(
          Twilio.layer.pipe(
            Layer.provide(configuration),
            Layer.provide(Layer.succeed(HttpClient.HttpClient, defect)),
          ),
        ),
      ),
    ).toEqual({ _tag: "Ambiguous" });
  }),
);

it.effect("preserves interruption and releases an in-flight request", () =>
  Effect.gen(function* () {
    let aborted = false;
    let calls = 0;
    const started = yield* Deferred.make<void>();

    const client = HttpClient.make((_request, _url, signal) =>
      Effect.gen(function* () {
        calls++;
        signal.addEventListener(
          "abort",
          () => {
            aborted = true;
          },
          { once: true },
        );
        yield* Deferred.succeed(started, undefined);

        return yield* Effect.never;
      }),
    );

    const fiber = yield* send.pipe(
      Effect.provide(
        Twilio.layer.pipe(
          Layer.provide(configuration),
          Layer.provide(Layer.succeed(HttpClient.HttpClient, client)),
        ),
      ),
      Effect.forkChild,
    );

    yield* Deferred.await(started);
    yield* Fiber.interrupt(fiber);
    expect(aborted).toBe(true);
    expect(calls).toBe(1);
  }),
);
