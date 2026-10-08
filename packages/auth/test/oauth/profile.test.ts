import { it } from "@effect/vitest";
import { Effect } from "effect";
import { describe, expect } from "vite-plus/test";

import { decodeOidcProfile, OidcUserProfile } from "../../src/oauth/providers/profile";

describe("OIDC profile claims", () => {
  it.effect("keeps Google's hosted domain from the verified ID token", () =>
    Effect.gen(function* () {
      const profile = yield* decodeOidcProfile(
        {
          email: "ada@example.com",
          email_verified: true,
          hd: "example.com",
        },
        OidcUserProfile,
      );

      expect(profile?.providerData).toMatchObject({ hd: "example.com" });
    }),
  );

  it.effect("leaves hd absent for an account outside a Workspace", () =>
    Effect.gen(function* () {
      const profile = yield* decodeOidcProfile(
        { email: "ada@gmail.com", email_verified: true },
        OidcUserProfile,
      );

      expect(profile?.providerData).not.toHaveProperty("hd");
    }),
  );
});
