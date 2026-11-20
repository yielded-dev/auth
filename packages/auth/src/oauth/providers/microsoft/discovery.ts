import * as Schema from "effect/Schema";

const tenantPlaceholder = "{tenantid}";

export const entraTenantId = Schema.String.check(
  Schema.isPattern(
    /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/u,
  ),
);

/** Commercial personal-account tenant; `consumers` is this GUID's nickname. */
export const personalMicrosoftAccountTenant = "9188040d-6c67-4c5b-b112-36a304b66dad";

const entraV2TenantHosts: ReadonlySet<string> = new Set([
  "login.microsoftonline.com",
  "login.microsoftonline.us",
  "login.partner.microsoftonline.cn",
  "login.chinacloudapi.cn",
]);

const isEntraV2TenantHost = (origin: string): boolean => {
  let url: URL;

  try {
    url = new URL(origin);
  } catch {
    return false;
  }

  if (url.protocol !== "https:" || url.port !== "") return false;
  const host = url.hostname.toLowerCase();

  return (
    entraV2TenantHosts.has(host) ||
    (host.endsWith(".ciamlogin.com") && host.length > ".ciamlogin.com".length)
  );
};

const issuerOriginAndPath = (value: string) => {
  const match = /^(https:\/\/[^/?#]+)(\/[^?#]*)?$/u.exec(value);

  if (match === null) return undefined;

  const origin = match[1];

  return origin === undefined ? undefined : { origin, path: match[2] ?? "" };
};

/** True when `issuer` belongs to a known Microsoft Entra / CIAM / v1 host or
 * the Microsoft provider preset. Case-insensitive tenant GUID matching and
 * lowercase subject canonicalization apply only to these authorities. */
export const isKnownEntraAuthority = (issuer: string, isMicrosoftProfile = false): boolean => {
  if (isMicrosoftProfile) return true;

  const parts = issuerOriginAndPath(issuer);

  if (parts === undefined) return false;

  return (
    isEntraV2TenantHost(parts.origin) || parts.origin.toLowerCase() === "https://sts.windows.net"
  );
};

/** Extract the concrete tenant GUID and signing-key issuer policy from an Entra
 * / CIAM single-tenant authority. v2 authorities (`/<tenantId>/v2.0` on known
 * Entra hosts, `*.ciamlogin.com`, or Microsoft-profile registrations) require
 * per-key `issuer` metadata; v1 authorities (`https://sts.windows.net/<tenantId>/`)
 * bind `tid` without requiring per-key `issuer` because Microsoft's v1 JWKS
 * omits it. */
export const concreteEntraAuthority = (
  issuer: string,
  isMicrosoftProfile = false,
): { readonly tenantId: string; readonly signingKeyIssuerRequired: boolean } | undefined => {
  const parts = issuerOriginAndPath(issuer);

  if (parts === undefined) return undefined;

  const segments = parts.path.split("/");

  if (
    segments.length !== 3 ||
    segments[0] !== "" ||
    segments[1] === undefined ||
    !Schema.is(entraTenantId)(segments[1])
  ) {
    return undefined;
  }

  if (segments[2] === "v2.0" && (isMicrosoftProfile || isEntraV2TenantHost(parts.origin))) {
    return { tenantId: segments[1], signingKeyIssuerRequired: true };
  }

  if (segments[2] === "" && parts.origin.toLowerCase() === "https://sts.windows.net") {
    return { tenantId: segments[1], signingKeyIssuerRequired: false };
  }

  return undefined;
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

/** Substitutes a validated tenant GUID into a single-placeholder `{tenantid}` template. */
export const substituteTenantIssuer = (template: string, tenantId: string): string | undefined => {
  if (!Schema.is(entraTenantId)(tenantId)) return undefined;

  const parts = issuerOriginAndPath(template);

  if (parts === undefined) return undefined;

  const segments = parts.path.split("/");
  const index = segments.indexOf(tenantPlaceholder);

  if (index < 0 || segments.filter((segment) => segment === tenantPlaceholder).length !== 1)
    return undefined;

  segments[index] = tenantId;

  return `${parts.origin}${segments.join("/")}`;
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
 * configured authority. Concrete Entra / CIAM tenant authorities, template
 * matches for single-tenant GUIDs, and both forms of `consumers` discovery pin
 * the issuer, report `pinned: true` so verification keeps requiring signing-key
 * issuer authority, and carry `expectedTenantId` so signed `tid` must match the
 * pinned tenant GUID. `common` and `organizations` stay on the template, with
 * the personal-account tenant excluded for `organizations`. Other segments,
 * including tenant domains, are rejected. */
export const matchEntraDiscoveryIssuer = (
  configured: string,
  discovered: string,
  isMicrosoftProfile = false,
):
  | {
      readonly issuer: string;
      readonly pinned: boolean;
      readonly expectedTenantId?: string;
      readonly excludedTenantId?: string;
    }
  | undefined => {
  if (configured === discovered) {
    const concrete = concreteEntraAuthority(discovered, isMicrosoftProfile);

    return concrete === undefined
      ? { issuer: discovered, pinned: false }
      : {
          issuer: discovered,
          pinned: concrete.signingKeyIssuerRequired,
          expectedTenantId: concrete.tenantId,
        };
  }

  const personal = personalAccountIssuer(configured);

  if (personal !== undefined && personal === discovered) {
    return {
      issuer: discovered,
      pinned: true,
      expectedTenantId: personalMicrosoftAccountTenant,
    };
  }

  const tenant = templateTenantSegment(configured, discovered);

  if (tenant === undefined) return undefined;
  if (tenant === "common") {
    return { issuer: discovered, pinned: false };
  }
  if (tenant === "organizations") {
    return {
      issuer: discovered,
      pinned: false,
      excludedTenantId: personalMicrosoftAccountTenant,
    };
  }
  if (Schema.is(entraTenantId)(tenant)) {
    return { issuer: configured, pinned: true, expectedTenantId: tenant };
  }
  if (tenant === "consumers" && personal !== undefined) {
    return {
      issuer: personal,
      pinned: true,
      expectedTenantId: personalMicrosoftAccountTenant,
    };
  }

  return undefined;
};

/** True when `discovered` matches `configured` directly or under Entra
 * `{tenantid}` / commercial `consumers` authority rules. */
export const discoveredIssuerMatches = (configured: string, discovered: string): boolean =>
  matchEntraDiscoveryIssuer(configured, discovered) !== undefined;
