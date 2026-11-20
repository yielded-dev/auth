import * as Schema from "effect/Schema";

const tenantPlaceholder = "{tenantid}";

export const entraTenantId = Schema.String.check(
  Schema.isPattern(
    /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/u,
  ),
);

/** Commercial personal-account tenant; `consumers` is this GUID's nickname. */
export const personalMicrosoftAccountTenant = "9188040d-6c67-4c5b-b112-36a304b66dad";

const multiTenantAlias = (segment: string) => segment === "common" || segment === "organizations";

const issuerOriginAndPath = (value: string) => {
  const match = /^(https:\/\/[^/?#]+)(\/[^?#]*)?$/u.exec(value);

  if (match === null) return undefined;

  const origin = match[1];

  return origin === undefined ? undefined : { origin, path: match[2] ?? "" };
};

/** True when `issuer` has exactly one `{tenantid}` path segment. The URL parser
 * percent-encodes braces, so matching stays on the raw identifier. */
export const isTenantIssuerTemplate = (issuer: string): boolean => {
  const parts = issuerOriginAndPath(issuer);

  return (
    parts !== undefined &&
    parts.path.split("/").filter((segment) => segment === tenantPlaceholder).length === 1
  );
};

/** Replace one `consumers` segment on the commercial host with its tenant GUID. */
const personalAccountIssuer = (configured: string): string | undefined => {
  const parts = issuerOriginAndPath(configured);

  if (parts === undefined || parts.origin !== "https://login.microsoftonline.com") return undefined;

  const segments = parts.path.split("/");
  const index = segments.indexOf("consumers");

  if (index < 0 || segments.filter((segment) => segment === "consumers").length !== 1)
    return undefined;

  segments[index] = personalMicrosoftAccountTenant;

  return `${parts.origin}${segments.join("/")}`;
};

/** Tenant segment when `discovered` is a `{tenantid}` template of `configured`. */
const templateTenantSegment = (configured: string, discovered: string): string | undefined => {
  if (configured === discovered || !isTenantIssuerTemplate(discovered)) return undefined;

  const configuredParts = issuerOriginAndPath(configured);
  const discoveredParts = issuerOriginAndPath(discovered);

  if (configuredParts === undefined || discoveredParts === undefined) return undefined;
  if (configuredParts.origin !== discoveredParts.origin) return undefined;

  const configuredSegments = configuredParts.path.split("/");
  const discoveredSegments = discoveredParts.path.split("/");

  if (configuredSegments.length !== discoveredSegments.length) return undefined;

  const index = discoveredSegments.indexOf(tenantPlaceholder);
  const tenant = configuredSegments[index];

  if (tenant === undefined || tenant === "" || tenant === tenantPlaceholder) return undefined;

  const filled = discoveredSegments.map((segment) =>
    segment === tenantPlaceholder ? tenant : segment,
  );

  return filled.every((segment, segmentIndex) => segment === configuredSegments[segmentIndex]) &&
    `${discoveredParts.origin}${filled.join("/")}` === configured
    ? tenant
    : undefined;
};

/** Match an exact issuer, commercial `consumers` personal-account alias, or an
 * Entra `{tenantid}` template whose remaining origin and path match the
 * configured authority. Single-tenant GUIDs and commercial `consumers` pin the
 * template to their concrete issuer and report `pinned: true` so verification
 * keeps requiring signing-key issuer authority. `common` and `organizations`
 * stay on the template. Other segments, including tenant domains, are rejected. */
export const matchEntraDiscoveryIssuer = (
  configured: string,
  discovered: string,
): { readonly issuer: string; readonly pinned: boolean } | undefined => {
  if (configured === discovered) {
    return { issuer: discovered, pinned: false };
  }

  const personal = personalAccountIssuer(configured);

  if (personal !== undefined && personal === discovered) {
    return { issuer: discovered, pinned: false };
  }

  const tenant = templateTenantSegment(configured, discovered);

  if (tenant === undefined) return undefined;
  if (multiTenantAlias(tenant)) {
    return { issuer: discovered, pinned: false };
  }
  if (Schema.is(entraTenantId)(tenant)) {
    return { issuer: configured, pinned: true };
  }
  if (tenant === "consumers" && personal !== undefined) {
    return { issuer: personal, pinned: true };
  }

  return undefined;
};

/** True when `discovered` matches `configured` directly or under Entra
 * `{tenantid}` / commercial `consumers` authority rules. */
export const discoveredIssuerMatches = (configured: string, discovered: string): boolean =>
  matchEntraDiscoveryIssuer(configured, discovered) !== undefined;
