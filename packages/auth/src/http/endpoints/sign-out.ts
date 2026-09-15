import { HttpApiEndpoint, HttpApiSchema } from "effect/unstable/httpapi";

export const SignOutEndpoint = HttpApiEndpoint.post("signOut", "/auth/sign-out", {
  success: HttpApiSchema.NoContent,
});
