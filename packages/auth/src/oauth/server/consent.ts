import * as Effect from "effect/Effect";

import type { Authentication, Unavailable } from "./models";

export interface OpenIdConsentService<Subject extends string = string> {
  readonly approved: (input: {
    readonly clientId: string;
    readonly redirectUri: string;
    readonly scopes: ReadonlyArray<string>;
    readonly authentication: Authentication<Subject>;
  }) => Effect.Effect<boolean, Unavailable>;
}

export interface Consent<Subject extends string = string> {
  readonly clientName: string;
  readonly clientId: string;
  /** False only for metadata-document clients, whose clientId is their HTTPS URL.
   * Not a vetting signal: stored client names may be self-asserted.
   */
  readonly registered: boolean;
  readonly subjectId: Subject;
  readonly resource: string;
  readonly scopes: ReadonlyArray<string>;
  readonly redirectUri: string;
  readonly action: string;
  readonly loginPath: string;
  readonly csrf: string;
}

export interface ConsentRendererService<Subject extends string = string> {
  readonly render: (consent: Consent<Subject>) => Effect.Effect<string, Unavailable>;
}

export const escapeHtml = (value: string) =>
  value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");

export const defaultOpenIdConsent = <Subject extends string>(): OpenIdConsentService<Subject> => ({
  approved: () => Effect.succeed(false),
});

export const defaultConsentRenderer = <
  Subject extends string,
>(): ConsentRendererService<Subject> => ({
  render: (consent) =>
    Effect.succeed(
      `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Authorize access</title><main><h1>Allow ${escapeHtml(consent.clientName)}?</h1>${consent.registered ? "" : `<p>Client: ${escapeHtml(new URL(consent.clientId).hostname)}</p>`}<p>Access to ${escapeHtml(consent.resource)} as ${escapeHtml(consent.subjectId)}.</p><ul>${consent.scopes.map((scope) => `<li>${escapeHtml(scope)}</li>`).join("")}</ul><p>Return to ${escapeHtml(new URL(consent.redirectUri).host)}.</p>${new URL(consent.redirectUri).protocol === "http:" ? "<p>A local application will receive this authorization. Only continue if you started this connection.</p>" : ""}<form method="post" action="${escapeHtml(consent.action)}"><input type="hidden" name="csrf" value="${escapeHtml(consent.csrf)}"><button name="decision" value="approve">Allow</button><button name="decision" value="deny">Deny</button></form><a href="${escapeHtml(consent.loginPath)}">Use another account</a></main></html>`,
    ),
});
