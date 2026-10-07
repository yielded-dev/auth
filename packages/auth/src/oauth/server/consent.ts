import { Context, Effect, Layer } from "effect";

import type { SubjectId } from "../../Schema";
import type { Unavailable } from "./models";

export interface Consent {
  readonly clientName: string;
  readonly clientId: string;
  readonly registered: boolean;
  readonly subjectId: SubjectId;
  readonly resource: string;
  readonly scopes: ReadonlyArray<string>;
  readonly redirectUri: string;
  readonly action: string;
  readonly loginPath: string;
  readonly csrf: string;
}

export const escapeHtml = (value: string) =>
  value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");

/** Render trusted consent metadata. Escape all displayed values and preserve the
 * POST action, csrf field and approve/deny decisions. Scripts are forbidden;
 * styles, fonts and images may load from the authorization server's own origin.
 */
export class ConsentRenderer extends Context.Service<
  ConsentRenderer,
  {
    readonly render: (consent: Consent) => Effect.Effect<string, Unavailable>;
  }
>()("effect-auth/OAuthServer/ConsentRenderer") {
  static readonly default = ConsentRenderer.of({
    render: (consent) =>
      Effect.succeed(
        `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Authorize access</title><main><h1>Allow ${escapeHtml(consent.clientName)}?</h1>${consent.registered ? "" : `<p>Client: ${escapeHtml(new URL(consent.clientId).hostname)}</p>`}<p>Access to ${escapeHtml(consent.resource)} as ${escapeHtml(consent.subjectId)}.</p><ul>${consent.scopes.map((scope) => `<li>${escapeHtml(scope)}</li>`).join("")}</ul><p>Return to ${escapeHtml(new URL(consent.redirectUri).host)}.</p>${new URL(consent.redirectUri).protocol === "http:" ? "<p>A local application will receive this authorization. Only continue if you started this connection.</p>" : ""}<form method="post" action="${escapeHtml(consent.action)}"><input type="hidden" name="csrf" value="${escapeHtml(consent.csrf)}"><button name="decision" value="approve">Allow</button><button name="decision" value="deny">Deny</button></form><a href="${escapeHtml(consent.loginPath)}">Use another account</a></main></html>`,
      ),
  });

  /** Plain HTML consent; it does not remember consent or sign users in. */
  static readonly defaultLayer = Layer.succeed(ConsentRenderer, ConsentRenderer.default);
}
