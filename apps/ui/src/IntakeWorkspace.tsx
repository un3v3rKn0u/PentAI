import { FormEvent, useEffect, useState } from "react";

type Json = Record<string, any>;
export type SourceMode = "pasted_text" | "file" | "url";
export type IntakeState = "empty" | "ready" | "loading" | "denied" | "degraded" | "error";
export type SourceImport =
  | { mode: "pasted_text"; authority: string; effectiveAt: string | null; sourceVersion: string | null; content: string }
  | { mode: "file"; authority: string; effectiveAt: string | null; sourceVersion: string | null; filename: string; mediaType: string; contentBase64: string }
  | { mode: "url"; authority: string; effectiveAt: string | null; sourceVersion: string | null; url: string };

const maxSourceBytes = 2 * 1024 * 1024;
const authorityPrecedence: Record<string, number> = {
  contract: 0,
  program_staff: 1,
  program_page: 2,
  platform_rule: 3,
  internal_note: 4
};

export function reviewedSource(sources: Json[], sourceId: string) {
  const matches = sources.filter((source) => source.id === sourceId);
  const source = matches[0];
  if (matches.length !== 1 || !source || typeof source.content_hash !== "string" || !source.content_hash.match(/^[a-f0-9]{64}$/) || typeof source.authority !== "string" || typeof source.retrieved_at !== "string" || !Number.isFinite(Date.parse(source.retrieved_at))) throw new Error("SOURCE_REVIEW_INVALID");
  return source;
}

export type SourceBundleReview = {
  sources: Json[];
  primary: Json;
  conflicts: string[];
  normalizationWarnings: string[];
};

export type AssetType = "domain" | "wildcard_domain" | "url" | "ipv4" | "ipv6" | "cidr";
export type DenyBoundary = { assetType: AssetType; target: string; includeApex?: boolean };
export type AssetRuleReview = {
  effect: "allow" | "deny";
  assetType: AssetType;
  target: string;
  sourceReference: string;
  includeApex?: boolean;
  allowedPaths?: string[];
  deniedPaths?: string[];
  allowedPorts?: number[];
};
export type ScopeBoundaryReview = {
  thirdPartyServices: "deny" | "allow_if_explicit";
  sharedHostingAndCdn: "deny" | "allow_if_explicit";
  scopeExpansionProcess: string;
};
export type TechniqueReview = {
  allowedCapabilities: string[];
  deniedCapabilities: string[];
  conditionalCapabilities: Array<{ capability: string; approvalType: string; conditions: string[] }>;
  allowedHttpMethods: Array<"GET" | "HEAD" | "OPTIONS">;
};
export type OperationalLimitReview = {
  requestsPerSecond: number;
  perHostRequestsPerSecond: number;
  burstLimit: number;
  concurrentConnections: number;
  maximumRuntimeMinutes: number;
  maximumTotalRequests: number;
  maximumRequestBodyBytes: number;
  maximumResponseBytes: number;
  stopConditions: string[];
  allowedTestingWindows?: TestingWindowReview[];
  blackoutPeriods?: BlackoutPeriodReview[];
};
export type TestingWindowReview = { days: string[]; startTime: string; endTime: string; timezone: string };
export type BlackoutPeriodReview = { startsAt: string; endsAt: string; reason: string };
export type DataHandlingReview = {
  realUserData: "avoid_and_stop" | "minimal_if_explicit";
  maximumRecordsToView?: number;
  retentionDays: number;
  approvedStorage: "local_encrypted";
  remoteAiMaxClassification: "none" | "public" | "internal" | "confidential";
  redactionRules: string[];
};
export type ReportingReview = { submissionChannel: string; requiredFields: string[]; evidenceRules: string[]; disclosureTimeline: string };
type AssetRuleDraft = Record<"effect" | "assetType" | "target" | "sourceReference" | "includeApex" | "allowedPaths" | "deniedPaths" | "allowedPorts", string>;

export type NormalizationReview = {
  assetType: AssetType;
  target: string;
  includeApex?: boolean;
  denyBoundary?: DenyBoundary;
  assetRules?: AssetRuleReview[];
  scopeBoundaries?: ScopeBoundaryReview;
  techniques?: TechniqueReview;
  operationalLimits?: OperationalLimitReview;
  dataHandling?: DataHandlingReview;
  reporting?: ReportingReview;
  allowedPaths: string[];
  deniedPaths: string[];
  allowedPorts: number[];
  allowedCapabilities: string[];
  requestsPerSecond: number;
  maximumTotalRequests: number;
  maximumResponseBytes: number;
  rationale: string;
};

function normalizedAssetValue(assetType: NormalizationReview["assetType"], value: string): string {
  const target = value.trim();
  const domain = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  const normalizeDomain = (candidate: string) => {
    const normalized = candidate.toLowerCase().replace(/\.$/, "");
    if (!domain.test(normalized)) throw new Error("NORMALIZATION_REVIEW_INVALID");
    return normalized;
  };
  const normalizeIpv4 = (candidate: string) => {
    const octets = candidate.split(".");
    if (octets.length !== 4 || octets.some((octet) => !octet.match(/^(?:0|[1-9][0-9]{0,2})$/) || Number(octet) > 255)) throw new Error("NORMALIZATION_REVIEW_INVALID");
    return octets.join(".");
  };
  if (assetType === "domain") return normalizeDomain(target);
  if (assetType === "wildcard_domain") return `*.${normalizeDomain(target.startsWith("*.") ? target.slice(2) : target)}`;
  if (assetType === "ipv4") return normalizeIpv4(target);
  if (assetType === "ipv6") {
    try {
      const parsed = new URL(`http://[${target}]/`);
      if (!parsed.hostname.startsWith("[") || !target.includes(":")) throw new Error();
      return parsed.hostname.slice(1, -1).toLowerCase();
    } catch { throw new Error("NORMALIZATION_REVIEW_INVALID"); }
  }
  if (assetType === "cidr") {
    const [address, prefix, ...rest] = target.split("/");
    const maximum = address.includes(":") ? 128 : 32;
    if (rest.length > 0 || !prefix?.match(/^(?:0|[1-9][0-9]{0,2})$/) || Number(prefix) > maximum) throw new Error("NORMALIZATION_REVIEW_INVALID");
    const normalizedAddress: string = address.includes(":")
      ? normalizedAssetValue("ipv6", address)
      : normalizeIpv4(address);
    return `${normalizedAddress}/${Number(prefix)}`;
  }
  try {
    const parsed = new URL(target);
    if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password || parsed.hash) throw new Error();
    return parsed.toString();
  } catch { throw new Error("NORMALIZATION_REVIEW_INVALID"); }
}

export function reviewedAssetRules(
  rows: Array<Record<string, string>>,
  reviewedSourceIds: string[]
): AssetRuleReview[] {
  const assetTypes = ["domain", "wildcard_domain", "url", "ipv4", "ipv6", "cidr"] as const;
  const sourceIds = new Set(reviewedSourceIds);
  if (rows.length === 0 || rows.length > 50 || sourceIds.size !== reviewedSourceIds.length) throw new Error("ASSET_RULES_INVALID");
  const rules = rows.map((row) => {
    const effect: AssetRuleReview["effect"] | null = row.effect === "allow" || row.effect === "deny" ? row.effect : null;
    const assetType = assetTypes.find((item) => item === row.assetType);
    if (!effect || !assetType || !sourceIds.has(row.sourceReference)) throw new Error("ASSET_RULE_INVALID");
    const target = normalizedAssetValue(assetType, row.target);
    const paths = (value: string) => [...new Set((value ?? "").split(",").map((item) => item.trim()).filter(Boolean))];
    const allowedPaths = paths(row.allowedPaths);
    const deniedPaths = paths(row.deniedPaths);
    const allowedPorts = paths(row.allowedPorts).map(Number);
    if (effect === "allow" && (
      allowedPaths.length === 0
      || [...allowedPaths, ...deniedPaths].some((path) => !path.startsWith("/"))
      || allowedPorts.length === 0
      || allowedPorts.some((port) => !Number.isInteger(port) || port < 1 || port > 65535)
    )) throw new Error("ASSET_RULE_INVALID");
    if (effect === "deny" && (allowedPaths.length > 0 || deniedPaths.length > 0 || allowedPorts.length > 0)) throw new Error("DENY_RULE_AUTHORITY_INVALID");
    return {
      effect,
      assetType,
      target,
      sourceReference: row.sourceReference,
      ...(assetType === "wildcard_domain" ? { includeApex: row.includeApex === "true" } : {}),
      ...(effect === "allow" ? { allowedPaths, deniedPaths, allowedPorts } : {})
    };
  });
  const identities = rules.map((rule) => `${rule.assetType}:${rule.target}`);
  if (new Set(identities).size !== identities.length) throw new Error("ASSET_RULE_CONFLICT");
  if (!rules.some((rule) => rule.effect === "allow")) throw new Error("ALLOW_RULE_REQUIRED");
  return rules;
}

export function reviewedScopeBoundaries(input: Record<string, string>): ScopeBoundaryReview {
  const thirdPartyServices = input.thirdPartyServices === "deny" || input.thirdPartyServices === "allow_if_explicit" ? input.thirdPartyServices : null;
  const sharedHostingAndCdn = input.sharedHostingAndCdn === "deny" || input.sharedHostingAndCdn === "allow_if_explicit" ? input.sharedHostingAndCdn : null;
  const scopeExpansionProcess = input.scopeExpansionProcess?.trim() ?? "";
  if (!thirdPartyServices || !sharedHostingAndCdn || !scopeExpansionProcess || scopeExpansionProcess.length > 500) throw new Error("SCOPE_BOUNDARY_REVIEW_INVALID");
  return { thirdPartyServices, sharedHostingAndCdn, scopeExpansionProcess };
}

export function reviewedTechniques(input: Record<string, string>): TechniqueReview {
  const list = (value: string) => [...new Set((value ?? "").split(",").map((item) => item.trim()).filter(Boolean))];
  const capabilityPattern = /^[a-z][a-z0-9_.-]+$/;
  const allowedCapabilities = list(input.allowedCapabilities);
  const deniedCapabilities = list(input.deniedCapabilities);
  const conditionalCapability = input.conditionalCapability?.trim() ?? "";
  const conditionalApprovalType = input.conditionalApprovalType?.trim() ?? "";
  const conditionalConditions = list(input.conditionalConditions);
  const conditionalParts = [conditionalCapability, conditionalApprovalType, ...conditionalConditions];
  const hasConditional = conditionalParts.some(Boolean);
  if (allowedCapabilities.length === 0 || [...allowedCapabilities, ...deniedCapabilities].some((item) => !capabilityPattern.test(item))) throw new Error("TECHNIQUE_REVIEW_INVALID");
  if (hasConditional && (!conditionalCapability || !capabilityPattern.test(conditionalCapability) || !conditionalApprovalType || conditionalApprovalType.length > 128 || conditionalConditions.length === 0 || conditionalConditions.some((item) => item.length > 200))) throw new Error("CONDITIONAL_CAPABILITY_INVALID");
  const classified = [...allowedCapabilities, ...deniedCapabilities, ...(conditionalCapability ? [conditionalCapability] : [])];
  if (new Set(classified).size !== classified.length) throw new Error("TECHNIQUE_CLASSIFICATION_CONFLICT");
  const allowedHttpMethods = (["GET", "HEAD", "OPTIONS"] as const).filter((method) => input[`method${method}`] === "true");
  const requiredMethod: Record<string, typeof allowedHttpMethods[number]> = { "network.http.get": "GET", "network.http.head": "HEAD", "network.http.options": "OPTIONS" };
  if (allowedHttpMethods.length === 0 || allowedCapabilities.some((capability) => requiredMethod[capability] && !allowedHttpMethods.includes(requiredMethod[capability]))) throw new Error("TECHNIQUE_METHOD_CONFLICT");
  return {
    allowedCapabilities,
    deniedCapabilities,
    conditionalCapabilities: conditionalCapability ? [{ capability: conditionalCapability, approvalType: conditionalApprovalType, conditions: conditionalConditions }] : [],
    allowedHttpMethods
  };
}

export function reviewedOperationalLimits(input: Record<string, string>): OperationalLimitReview {
  const numericFields = ["requestsPerSecond", "perHostRequestsPerSecond", "burstLimit", "concurrentConnections", "maximumRuntimeMinutes", "maximumTotalRequests", "maximumRequestBodyBytes", "maximumResponseBytes"];
  const requestsPerSecond = Number(input.requestsPerSecond);
  const perHostRequestsPerSecond = Number(input.perHostRequestsPerSecond);
  const burstLimit = Number(input.burstLimit);
  const concurrentConnections = Number(input.concurrentConnections);
  const maximumRuntimeMinutes = Number(input.maximumRuntimeMinutes);
  const maximumTotalRequests = Number(input.maximumTotalRequests);
  const maximumRequestBodyBytes = Number(input.maximumRequestBodyBytes);
  const maximumResponseBytes = Number(input.maximumResponseBytes);
  const stopConditions = [...new Set((input.stopConditions ?? "").split(",").map((item) => item.trim()).filter(Boolean))];
  if (
    numericFields.some((field) => !(input[field] ?? "").trim())
    || !Number.isFinite(requestsPerSecond) || requestsPerSecond <= 0
    || !Number.isFinite(perHostRequestsPerSecond) || perHostRequestsPerSecond <= 0 || perHostRequestsPerSecond > requestsPerSecond
    || !Number.isInteger(burstLimit) || burstLimit < 1
    || !Number.isInteger(concurrentConnections) || concurrentConnections < 1
    || !Number.isInteger(maximumRuntimeMinutes) || maximumRuntimeMinutes < 1
    || !Number.isInteger(maximumTotalRequests) || maximumTotalRequests < 1
    || !Number.isInteger(maximumRequestBodyBytes) || maximumRequestBodyBytes < 0
    || !Number.isInteger(maximumResponseBytes) || maximumResponseBytes < 1
    || stopConditions.length === 0 || stopConditions.some((item) => item.length > 200)
  ) throw new Error("OPERATIONAL_LIMIT_REVIEW_INVALID");
  return { requestsPerSecond, perHostRequestsPerSecond, burstLimit, concurrentConnections, maximumRuntimeMinutes, maximumTotalRequests, maximumRequestBodyBytes, maximumResponseBytes, stopConditions };
}

export function reviewedTestingSchedule(input: Record<string, string>): Pick<OperationalLimitReview, "allowedTestingWindows" | "blackoutPeriods"> {
  const validDays = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"];
  const days = [...new Set((input.testingDays ?? "").split(",").map((item) => item.trim().toLowerCase()).filter(Boolean))];
  const timePattern = /^(?:[01][0-9]|2[0-3]):[0-5][0-9]$/;
  const startTime = input.testingStartTime?.trim() ?? "";
  const endTime = input.testingEndTime?.trim() ?? "";
  const timezone = input.testingTimezone?.trim() ?? "";
  let validTimezone = true;
  try { new Intl.DateTimeFormat("en", { timeZone: timezone }).format(); } catch { validTimezone = false; }
  if (days.length === 0 || days.some((day) => !validDays.includes(day)) || !timePattern.test(startTime) || !timePattern.test(endTime) || startTime >= endTime || !timezone || timezone.length > 64 || !validTimezone) throw new Error("TESTING_WINDOW_REVIEW_INVALID");
  const blackoutStarts = input.blackoutStartsAt?.trim() ?? "";
  const blackoutEnds = input.blackoutEndsAt?.trim() ?? "";
  const blackoutReason = input.blackoutReason?.trim() ?? "";
  const hasBlackout = [blackoutStarts, blackoutEnds, blackoutReason].some(Boolean);
  let blackoutPeriods: BlackoutPeriodReview[] = [];
  if (hasBlackout) {
    const timezoneAware = /(?:Z|[+-][0-9]{2}:[0-9]{2})$/;
    const startsAt = new Date(blackoutStarts);
    const endsAt = new Date(blackoutEnds);
    if (!timezoneAware.test(blackoutStarts) || !timezoneAware.test(blackoutEnds) || !blackoutReason || blackoutReason.length > 200 || !Number.isFinite(startsAt.getTime()) || !Number.isFinite(endsAt.getTime()) || startsAt >= endsAt) throw new Error("BLACKOUT_PERIOD_REVIEW_INVALID");
    blackoutPeriods = [{ startsAt: startsAt.toISOString(), endsAt: endsAt.toISOString(), reason: blackoutReason }];
  }
  return { allowedTestingWindows: [{ days, startTime, endTime, timezone }], blackoutPeriods };
}

export function reviewedDataHandling(input: Record<string, string>): DataHandlingReview {
  const realUserData = input.realUserData === "avoid_and_stop" || input.realUserData === "minimal_if_explicit" ? input.realUserData : null;
  const remoteAiMaxClassification = ["none", "public", "internal", "confidential"].find((item) => item === input.remoteAiMaxClassification) as DataHandlingReview["remoteAiMaxClassification"] | undefined;
  const retentionText = input.retentionDays?.trim() ?? "";
  const retentionDays = Number(retentionText);
  const recordsText = input.maximumRecordsToView?.trim() ?? "";
  const maximumRecordsToView = Number(recordsText);
  const redactionRules = [...new Set((input.redactionRules ?? "").split(",").map((item) => item.trim()).filter(Boolean))];
  if (!realUserData || !remoteAiMaxClassification || !retentionText || !Number.isInteger(retentionDays) || retentionDays < 1 || redactionRules.some((item) => item.length > 200)) throw new Error("DATA_HANDLING_REVIEW_INVALID");
  if (realUserData === "minimal_if_explicit" && (!recordsText || !Number.isInteger(maximumRecordsToView) || maximumRecordsToView < 1)) throw new Error("REAL_USER_DATA_LIMIT_REQUIRED");
  if (realUserData === "avoid_and_stop" && recordsText) throw new Error("REAL_USER_DATA_LIMIT_CONFLICT");
  return { realUserData, ...(realUserData === "minimal_if_explicit" ? { maximumRecordsToView } : {}), retentionDays, approvedStorage: "local_encrypted", remoteAiMaxClassification, redactionRules };
}

export function reviewedReporting(input: Record<string, string>): ReportingReview {
  const list = (value: string) => [...new Set((value ?? "").split(",").map((item) => item.trim()).filter(Boolean))];
  const submissionChannel = input.submissionChannel?.trim() ?? "";
  const requiredFields = list(input.requiredFields);
  const evidenceRules = list(input.evidenceRules);
  const disclosureTimeline = input.disclosureTimeline?.trim() ?? "";
  if (!submissionChannel || submissionChannel.length > 200 || requiredFields.length === 0 || evidenceRules.length === 0 || !disclosureTimeline || disclosureTimeline.length > 500 || [...requiredFields, ...evidenceRules].some((item) => item.length > 200)) throw new Error("REPORTING_REVIEW_INVALID");
  return { submissionChannel, requiredFields, evidenceRules, disclosureTimeline };
}

export function reviewedNormalization(input: Record<string, string>): NormalizationReview {
  const assetTypes = ["domain", "wildcard_domain", "url", "ipv4", "ipv6", "cidr"] as const;
  const assetType = assetTypes.find((item) => item === input.assetType);
  if (!assetType) throw new Error("NORMALIZATION_REVIEW_INVALID");
  const target = normalizedAssetValue(assetType, input.target);
  const denyAssetType = assetTypes.find((item) => item === input.denyAssetType);
  const denyTarget = input.denyTarget?.trim() ?? "";
  if ((denyAssetType && !denyTarget) || (!denyAssetType && denyTarget)) throw new Error("DENY_BOUNDARY_INVALID");
  const denyBoundary = denyAssetType && denyTarget
    ? {
        assetType: denyAssetType,
        target: normalizedAssetValue(denyAssetType, denyTarget),
        ...(denyAssetType === "wildcard_domain" ? { includeApex: input.denyIncludeApex === "true" } : {})
      }
    : undefined;
  if (denyBoundary?.assetType === assetType && denyBoundary.target === target) throw new Error("DENY_BOUNDARY_CONFLICT");
  const paths = (value: string) => [...new Set(value.split(",").map((item) => item.trim()).filter(Boolean))];
  const allowedPaths = paths(input.allowedPaths);
  const deniedPaths = paths(input.deniedPaths);
  const allowedPorts = paths(input.allowedPorts).map(Number);
  const allowedCapabilities = paths(input.allowedCapabilities);
  const requestsPerSecond = Number(input.requestsPerSecond);
  const maximumTotalRequests = Number(input.maximumTotalRequests);
  const maximumResponseBytes = Number(input.maximumResponseBytes);
  const rationale = input.rationale.trim();
  if (
    allowedPaths.length === 0
    || [...allowedPaths, ...deniedPaths].some((path) => !path.startsWith("/"))
    || allowedPorts.length === 0
    || allowedPorts.some((port) => !Number.isInteger(port) || port < 1 || port > 65535)
    || allowedCapabilities.length === 0
    || allowedCapabilities.some((capability) => !capability.match(/^[a-z][a-z0-9_.-]+$/))
    || !Number.isFinite(requestsPerSecond) || requestsPerSecond <= 0
    || !Number.isInteger(maximumTotalRequests) || maximumTotalRequests < 1
    || !Number.isInteger(maximumResponseBytes) || maximumResponseBytes < 1
    || !rationale || rationale.length > 500
  ) throw new Error("NORMALIZATION_REVIEW_INVALID");
  return { assetType, target, ...(assetType === "wildcard_domain" ? { includeApex: input.includeApex === "true" } : {}), ...(denyBoundary ? { denyBoundary } : {}), allowedPaths, deniedPaths, allowedPorts, allowedCapabilities, requestsPerSecond, maximumTotalRequests, maximumResponseBytes, rationale };
}

export function reviewedSourceBundle(
  sources: Json[],
  sourceIds: string[],
  conflictNote: string
): SourceBundleReview {
  if (sourceIds.length === 0 || new Set(sourceIds).size !== sourceIds.length) {
    throw new Error("SOURCE_BUNDLE_INVALID");
  }
  const reviewed = sourceIds.map((sourceId) => reviewedSource(sources, sourceId));
  if (reviewed.some((source) =>
    !(source.authority in authorityPrecedence)
    || typeof source.reference !== "string"
    || !source.reference.trim()
    || (source.effective_at != null && !Number.isFinite(Date.parse(source.effective_at)))
  )) throw new Error("SOURCE_BUNDLE_INVALID");
  const ordered = [...reviewed].sort((left, right) => {
    const authority = (authorityPrecedence[left.authority] ?? 99) - (authorityPrecedence[right.authority] ?? 99);
    return authority || Date.parse(right.effective_at ?? right.retrieved_at) - Date.parse(left.effective_at ?? left.retrieved_at) || left.id.localeCompare(right.id);
  });
  const references = new Map<string, Set<string>>();
  for (const source of ordered) {
    const hashes = references.get(source.reference) ?? new Set<string>();
    hashes.add(source.content_hash);
    references.set(source.reference, hashes);
  }
  const conflicts = [...references.entries()]
    .filter(([, hashes]) => hashes.size > 1)
    .map(([reference]) => reference)
    .sort();
  const note = conflictNote.trim();
  if (conflicts.length > 0 && (!note || note.length > 500)) {
    throw new Error("SOURCE_CONFLICT_REVIEW_REQUIRED");
  }
  return {
    sources: ordered,
    primary: ordered[0],
    conflicts,
    normalizationWarnings: conflicts.length > 0
      ? [`Conflicting immutable versions require restrictive review: ${note}`]
      : []
  };
}

export function reviewedEngagement(engagements: Json[], engagementId: string, programId: string) {
  const matches = engagements.filter((engagement) => engagement.id === engagementId);
  const engagement = matches[0];
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (matches.length !== 1 || !engagement || !uuid.test(engagement.id) || engagement.program_id !== programId || !["draft", "approved", "active", "paused", "expired", "revoked"].includes(engagement.status) || !Number.isFinite(Date.parse(engagement.effective_from)) || !Number.isFinite(Date.parse(engagement.expires_at)) || Date.parse(engagement.effective_from) >= Date.parse(engagement.expires_at)) throw new Error("ENGAGEMENT_REVIEW_INVALID");
  return engagement;
}

export function encodeBytesBase64(bytes: Uint8Array) {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 16_384) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 16_384));
  }
  return btoa(binary);
}

export function sourceFileMediaType(filename: string) {
  const extension = filename.toLowerCase().split(".").pop();
  const mediaTypes: Record<string, string> = {
    txt: "text/plain", md: "text/markdown", markdown: "text/markdown",
    htm: "text/html", html: "text/html", json: "application/json", pdf: "application/pdf"
  };
  if (!extension || !mediaTypes[extension]) throw new Error("SOURCE_MEDIA_TYPE_INVALID");
  return mediaTypes[extension];
}

export async function prepareSourceImport(
  mode: SourceMode,
  authority: string,
  effectiveAt: string,
  sourceVersion: string,
  text: string,
  url: string,
  file: File | null
): Promise<SourceImport> {
  const normalizedEffectiveAt = effectiveAt ? new Date(effectiveAt) : null;
  if (normalizedEffectiveAt && !Number.isFinite(normalizedEffectiveAt.getTime())) throw new Error("SOURCE_EFFECTIVE_AT_INVALID");
  const provenance = {
    effectiveAt: normalizedEffectiveAt?.toISOString() ?? null,
    sourceVersion: sourceVersion.trim() || null
  };
  if (provenance.sourceVersion && provenance.sourceVersion.length > 128) throw new Error("SOURCE_VERSION_INVALID");
  if (mode === "file") {
    if (!file) throw new Error("SOURCE_FILE_REQUIRED");
    if (file.size > maxSourceBytes) throw new Error("SOURCE_TOO_LARGE");
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (bytes.byteLength > maxSourceBytes) throw new Error("SOURCE_TOO_LARGE");
    return { mode, authority, ...provenance, filename: file.name, mediaType: sourceFileMediaType(file.name), contentBase64: encodeBytesBase64(bytes) };
  }
  if (mode === "url") return { mode, authority, ...provenance, url };
  return { mode, authority, ...provenance, content: text };
}

export function IntakeWorkspace({
  connected, program, engagements, selectedEngagement, sources, selectedSources, state, error, submit, selectEngagement, selectBundle, refresh
}: {
  connected: boolean; program: Json | null; engagements: Json[]; selectedEngagement: Json | null; sources: Json[]; selectedSources: Json[];
  state: IntakeState; error: string; submit: (source: SourceImport) => Promise<void>;
  selectEngagement: (engagement: Json) => void;
  selectBundle: (review: SourceBundleReview, normalization: NormalizationReview) => void;
  refresh: () => Promise<void>;
}) {
  const [mode, setMode] = useState<SourceMode>("pasted_text");
  const [authority, setAuthority] = useState("contract");
  const [effectiveAt, setEffectiveAt] = useState("");
  const [sourceVersion, setSourceVersion] = useState("");
  const [text, setText] = useState("Synthetic authorization for HTTPS GET requests to example.test/api.");
  const [url, setUrl] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [preparationError, setPreparationError] = useState("");
  const [reviewIds, setReviewIds] = useState<string[]>(selectedSources.map((item) => item.id));
  const [conflictNote, setConflictNote] = useState("");
  const [reviewError, setReviewError] = useState("");
  const [allowedCapabilities, setAllowedCapabilities] = useState("network.http.get");
  const [deniedCapabilities, setDeniedCapabilities] = useState("");
  const [conditionalCapability, setConditionalCapability] = useState("");
  const [conditionalApprovalType, setConditionalApprovalType] = useState("");
  const [conditionalConditions, setConditionalConditions] = useState("");
  const [allowedHttpMethods, setAllowedHttpMethods] = useState<Array<TechniqueReview["allowedHttpMethods"][number]>>(["GET"]);
  const [requestsPerSecond, setRequestsPerSecond] = useState("1");
  const [perHostRequestsPerSecond, setPerHostRequestsPerSecond] = useState("1");
  const [burstLimit, setBurstLimit] = useState("1");
  const [concurrentConnections, setConcurrentConnections] = useState("1");
  const [maximumRuntimeMinutes, setMaximumRuntimeMinutes] = useState("30");
  const [maximumTotalRequests, setMaximumTotalRequests] = useState("50");
  const [maximumRequestBodyBytes, setMaximumRequestBodyBytes] = useState("0");
  const [maximumResponseBytes, setMaximumResponseBytes] = useState("100000");
  const [stopConditions, setStopConditions] = useState("authorization changes,safety control pauses");
  const [testingDays, setTestingDays] = useState("monday,tuesday,wednesday,thursday,friday");
  const [testingStartTime, setTestingStartTime] = useState("09:00");
  const [testingEndTime, setTestingEndTime] = useState("17:00");
  const [testingTimezone, setTestingTimezone] = useState("UTC");
  const [blackoutStartsAt, setBlackoutStartsAt] = useState("");
  const [blackoutEndsAt, setBlackoutEndsAt] = useState("");
  const [blackoutReason, setBlackoutReason] = useState("");
  const [realUserData, setRealUserData] = useState<DataHandlingReview["realUserData"]>("avoid_and_stop");
  const [maximumRecordsToView, setMaximumRecordsToView] = useState("");
  const [retentionDays, setRetentionDays] = useState("7");
  const [remoteAiMaxClassification, setRemoteAiMaxClassification] = useState<DataHandlingReview["remoteAiMaxClassification"]>("none");
  const [redactionRules, setRedactionRules] = useState("remove credentials,remove personal identifiers");
  const [submissionChannel, setSubmissionChannel] = useState("Manual program portal");
  const [requiredFields, setRequiredFields] = useState("title,affected asset,impact,reproduction,remediation");
  const [evidenceRules, setEvidenceRules] = useState("redact credentials,include only necessary evidence");
  const [disclosureTimeline, setDisclosureTimeline] = useState("Follow the reviewed program timeline; do not disclose publicly without approval.");
  const [normalizationRationale, setNormalizationRationale] = useState("Restrictive values transcribed from the reviewed sources.");
  const [thirdPartyServices, setThirdPartyServices] = useState<ScopeBoundaryReview["thirdPartyServices"]>("deny");
  const [sharedHostingAndCdn, setSharedHostingAndCdn] = useState<ScopeBoundaryReview["sharedHostingAndCdn"]>("deny");
  const [scopeExpansionProcess, setScopeExpansionProcess] = useState("Stop and obtain written authorization before adding any new asset.");
  const [assetRules, setAssetRules] = useState<AssetRuleDraft[]>([]);
  const selectedSourceIds = selectedSources.map((item) => item.id).join("|");

  useEffect(() => {
    setReviewIds(selectedSourceIds ? selectedSourceIds.split("|") : []);
  }, [selectedSourceIds]);

  useEffect(() => {
    if (assetRules.length === 0 && reviewIds.length > 0) {
      setAssetRules([{ effect: "allow", assetType: "domain", target: "example.test", sourceReference: reviewIds[0], includeApex: "false", allowedPaths: "/api", deniedPaths: "/api/admin", allowedPorts: "443" }]);
    }
  }, [assetRules.length, reviewIds]);

  const updateAssetRule = (index: number, changes: Partial<AssetRuleDraft>) => setAssetRules((current) => current.map((row, rowIndex) => rowIndex === index ? { ...row, ...changes } : row));

  async function importSource(event: FormEvent) {
    event.preventDefault();
    setPreparationError("");
    try {
      await submit(await prepareSourceImport(mode, authority, effectiveAt, sourceVersion, text, url, file));
    } catch (cause) {
      setPreparationError(cause instanceof Error ? cause.message : "SOURCE_PREPARATION_FAILED");
    }
  }

  function reviewBundle() {
    setReviewError("");
    try {
      const sourceReview = reviewedSourceBundle(sources, reviewIds, conflictNote);
      const reviewedRules = reviewedAssetRules(assetRules, sourceReview.sources.map((source) => source.id));
      const primaryAllow = reviewedRules.find((rule) => rule.effect === "allow")!;
      const normalization = reviewedNormalization({ assetType: primaryAllow.assetType, target: primaryAllow.target, includeApex: String(primaryAllow.includeApex ?? false), allowedPaths: primaryAllow.allowedPaths!.join(","), deniedPaths: primaryAllow.deniedPaths!.join(","), allowedPorts: primaryAllow.allowedPorts!.join(","), allowedCapabilities, requestsPerSecond, maximumTotalRequests, maximumResponseBytes, rationale: normalizationRationale });
      const schedule = reviewedTestingSchedule({ testingDays, testingStartTime, testingEndTime, testingTimezone, blackoutStartsAt, blackoutEndsAt, blackoutReason });
      selectBundle(sourceReview, { ...normalization, assetRules: reviewedRules, scopeBoundaries: reviewedScopeBoundaries({ thirdPartyServices, sharedHostingAndCdn, scopeExpansionProcess }), techniques: reviewedTechniques({ allowedCapabilities, deniedCapabilities, conditionalCapability, conditionalApprovalType, conditionalConditions, methodGET: String(allowedHttpMethods.includes("GET")), methodHEAD: String(allowedHttpMethods.includes("HEAD")), methodOPTIONS: String(allowedHttpMethods.includes("OPTIONS")) }), operationalLimits: { ...reviewedOperationalLimits({ requestsPerSecond, perHostRequestsPerSecond, burstLimit, concurrentConnections, maximumRuntimeMinutes, maximumTotalRequests, maximumRequestBodyBytes, maximumResponseBytes, stopConditions }), ...schedule }, dataHandling: reviewedDataHandling({ realUserData, maximumRecordsToView, retentionDays, remoteAiMaxClassification, redactionRules }), reporting: reviewedReporting({ submissionChannel, requiredFields, evidenceRules, disclosureTimeline }) });
    } catch (cause) {
      setReviewError(cause instanceof Error ? cause.message : "SOURCE_BUNDLE_INVALID");
    }
  }

  return (
    <section className="panel intake-workspace">
      <h2><span>2</span> Intake</h2>
      <p className="hint">Selected program: {program ? `${program.name} · ${program.id}` : "None — select a program first"}</p>
      <form onSubmit={(event) => void importSource(event)} aria-busy={state === "loading"}>
        <fieldset disabled={!connected || !program || state === "loading"}>
          <legend>Supervised source import</legend>
          <div className="mode-row" role="group" aria-label="Source type">
            {(["pasted_text", "file", "url"] as SourceMode[]).map((item) => (
              <button type="button" key={item} className={mode === item ? "selected" : ""} onClick={() => { setMode(item); setPreparationError(""); }}>
                {item === "pasted_text" ? "Paste text" : item === "file" ? "Choose file" : "Acquire URL"}
              </button>
            ))}
          </div>
          <label>Source authority<select value={authority} onChange={(event) => setAuthority(event.target.value)}>
            <option value="contract">Contract</option><option value="program_staff">Program staff</option>
            <option value="program_page">Program page</option><option value="platform_rule">Platform rule</option>
            <option value="internal_note">Internal note</option>
          </select></label>
          <label>Effective from (optional)<input type="datetime-local" value={effectiveAt} onChange={(event) => setEffectiveAt(event.target.value)} /></label>
          <label>Source version (optional)<input maxLength={128} value={sourceVersion} onChange={(event) => setSourceVersion(event.target.value)} /></label>
          {mode === "pasted_text" && <label>Authoritative text<textarea rows={4} value={text} onChange={(event) => setText(event.target.value)} /></label>}
          {mode === "file" && <label>Local source file (maximum 2 MiB)<input type="file" accept=".txt,.md,.markdown,.htm,.html,.json,.pdf,text/plain,text/markdown,text/html,application/json,application/pdf" onChange={(event) => setFile(event.target.files?.[0] ?? null)} /></label>}
          {mode === "url" && <label>Public HTTP(S) source URL<input type="url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://program.example/rules" /></label>}
          <button type="submit">{state === "loading" ? "Importing…" : "Review and import source"}</button>
        </fieldset>
      </form>
      {preparationError && <p className="result bad" role="alert">Import denied: {preparationError}</p>}
      <p className={`intake-state ${state}`} role="status">
        {state === "empty" && "No sources imported."}{state === "ready" && `${sources.length} immutable source${sources.length === 1 ? "" : "s"} available.`}
        {state === "loading" && "Import in progress. No background retries will occur."}{state === "denied" && `Import denied: ${error}`}
        {state === "degraded" && "Source intake unavailable until the authenticated core recovers."}{state === "error" && `Import failed safely: ${error}`}
      </p>
      <div className="panel-heading"><strong>Engagement history</strong><span className="hint">Select the exact validity window for source review.</span></div>
      {engagements.length === 0 ? <p className="hint">No durable engagement is available yet.</p> : <ol className="source-list">{engagements.map((item) => <li key={item.id} className={selectedEngagement?.id === item.id ? "selected" : ""}><div><strong>{item.status}</strong><span>{item.effective_from} → {item.expires_at}</span><code>{item.id}</code></div><button type="button" onClick={() => selectEngagement(reviewedEngagement(engagements, item.id, program?.id ?? ""))} aria-pressed={selectedEngagement?.id === item.id}>{selectedEngagement?.id === item.id ? "Selected" : "Review engagement"}</button></li>)}</ol>}
      <div className="panel-heading"><strong>Source history</strong><button type="button" onClick={() => void refresh()} disabled={!connected || !program || state === "loading"}>Refresh</button></div>
      <p className="hint">Choose every immutable source used by the draft. Contract and authorized clarification take precedence; conflicting versions remain blocked for restrictive review.</p>
      {sources.length === 0 ? <p className="hint">The history is empty.</p> : <ol className="source-list">{sources.map((item) => <li key={item.id} className={reviewIds.includes(item.id) ? "selected" : ""}><div><strong>{item.source_kind} · {item.authority}</strong><span>{item.reference}</span><span>Retrieved {item.retrieved_at}{item.effective_at ? ` · effective ${item.effective_at}` : " · no separate effective date"}</span><code>{item.content_hash.slice(0, 16)}…</code></div><label className="source-choice"><input type="checkbox" checked={reviewIds.includes(item.id)} onChange={(event) => setReviewIds((current) => event.target.checked ? [...current, item.id] : current.filter((id) => id !== item.id))} /> Include</label></li>)}</ol>}
      {reviewIds.length > 1 && <label>Conflict review note (required only when one reference has different hashes)<textarea maxLength={500} value={conflictNote} onChange={(event) => setConflictNote(event.target.value)} placeholder="Record the restrictive interpretation and clarification still required." /></label>}
      <fieldset disabled={reviewIds.length === 0}>
        <legend>Structured normalization review</legend>
        <p className="hint">Transcribe exact restrictive values from the reviewed sources. The core canonicalizes and validates this draft again.</p>
        <div className="panel-heading"><strong>Scope rules</strong><button type="button" disabled={assetRules.length >= 50} onClick={() => setAssetRules((current) => [...current, { effect: "deny", assetType: "domain", target: "", sourceReference: reviewIds[0] ?? "", includeApex: "false", allowedPaths: "", deniedPaths: "", allowedPorts: "" }])}>Add scope rule</button></div>
        <p className="hint">Each row must cite one selected immutable source. Deny rows cannot carry paths, ports, or ownership authority.</p>
        {assetRules.map((row, index) => <div className="boundary-review" key={index}>
          <div className="panel-heading"><strong>Rule {index + 1}</strong><button type="button" disabled={assetRules.length === 1} onClick={() => setAssetRules((current) => current.filter((_, rowIndex) => rowIndex !== index))}>Remove</button></div>
          <label>Effect<select value={row.effect} onChange={(event) => updateAssetRule(index, { effect: event.target.value, ...(event.target.value === "deny" ? { allowedPaths: "", deniedPaths: "", allowedPorts: "" } : {}) })}><option value="allow">In scope</option><option value="deny">Out of scope</option></select></label>
          <label>Asset type<select value={row.assetType} onChange={(event) => updateAssetRule(index, { assetType: event.target.value, target: "", includeApex: "false" })}><option value="domain">Domain</option><option value="wildcard_domain">Wildcard domain</option><option value="url">URL</option><option value="ipv4">IPv4</option><option value="ipv6">IPv6</option><option value="cidr">CIDR</option></select></label>
          <label>Exact asset value<input value={row.target} onChange={(event) => updateAssetRule(index, { target: event.target.value })} /></label>
          {row.assetType === "wildcard_domain" && <label className="source-choice"><input type="checkbox" checked={row.includeApex === "true"} onChange={(event) => updateAssetRule(index, { includeApex: String(event.target.checked) })} /> Explicitly include the apex</label>}
          <label>Source<select value={row.sourceReference} onChange={(event) => updateAssetRule(index, { sourceReference: event.target.value })}><option value="">Select reviewed source</option>{sources.filter((source) => reviewIds.includes(source.id)).map((source) => <option key={source.id} value={source.id}>{source.authority} · {source.reference}</option>)}</select></label>
          {row.effect === "allow" && <><label>Allowed paths (comma-separated)<input value={row.allowedPaths} onChange={(event) => updateAssetRule(index, { allowedPaths: event.target.value })} /></label><label>Denied paths (comma-separated)<input value={row.deniedPaths} onChange={(event) => updateAssetRule(index, { deniedPaths: event.target.value })} /></label><label>Allowed ports (comma-separated)<input value={row.allowedPorts} onChange={(event) => updateAssetRule(index, { allowedPorts: event.target.value })} /></label></>}
        </div>)}
        <div className="boundary-review">
          <strong>External infrastructure boundaries</strong>
          <label>Third-party services<select value={thirdPartyServices} onChange={(event) => setThirdPartyServices(event.target.value as ScopeBoundaryReview["thirdPartyServices"])}><option value="deny">Deny</option><option value="allow_if_explicit">Allow only when explicitly listed</option></select></label>
          <label>Shared hosting and CDN<select value={sharedHostingAndCdn} onChange={(event) => setSharedHostingAndCdn(event.target.value as ScopeBoundaryReview["sharedHostingAndCdn"])}><option value="deny">Deny</option><option value="allow_if_explicit">Allow only when explicitly listed</option></select></label>
          <label>Scope expansion process<textarea maxLength={500} value={scopeExpansionProcess} onChange={(event) => setScopeExpansionProcess(event.target.value)} /></label>
        </div>
        <div className="boundary-review">
          <strong>Technique review</strong>
          <label>Allowed capabilities (comma-separated)<input value={allowedCapabilities} onChange={(event) => setAllowedCapabilities(event.target.value)} /></label>
          <label>Denied capabilities (comma-separated)<input value={deniedCapabilities} onChange={(event) => setDeniedCapabilities(event.target.value)} /></label>
          <span className="hint">Allowed HTTP methods</span>{(["GET", "HEAD", "OPTIONS"] as const).map((method) => <label className="source-choice" key={method}><input type="checkbox" checked={allowedHttpMethods.includes(method)} onChange={(event) => setAllowedHttpMethods((current) => event.target.checked ? [...current, method] : current.filter((item) => item !== method))} /> {method}</label>)}
          <label>Conditional capability (optional)<input value={conditionalCapability} onChange={(event) => setConditionalCapability(event.target.value)} /></label>
          <label>Required approval type<input value={conditionalApprovalType} onChange={(event) => setConditionalApprovalType(event.target.value)} /></label>
          <label>Conditions (comma-separated)<input value={conditionalConditions} onChange={(event) => setConditionalConditions(event.target.value)} /></label>
        </div>
        <div className="boundary-review"><strong>Operational limits</strong>
          <label>Global requests per second<input type="number" min="0.001" step="0.001" value={requestsPerSecond} onChange={(event) => setRequestsPerSecond(event.target.value)} /></label>
          <label>Per-host requests per second<input type="number" min="0.001" step="0.001" value={perHostRequestsPerSecond} onChange={(event) => setPerHostRequestsPerSecond(event.target.value)} /></label>
          <label>Burst limit<input type="number" min="1" value={burstLimit} onChange={(event) => setBurstLimit(event.target.value)} /></label>
          <label>Concurrent connections<input type="number" min="1" value={concurrentConnections} onChange={(event) => setConcurrentConnections(event.target.value)} /></label>
          <label>Maximum runtime minutes<input type="number" min="1" value={maximumRuntimeMinutes} onChange={(event) => setMaximumRuntimeMinutes(event.target.value)} /></label>
          <label>Maximum total requests<input type="number" min="1" value={maximumTotalRequests} onChange={(event) => setMaximumTotalRequests(event.target.value)} /></label>
          <label>Maximum request body bytes<input type="number" min="0" value={maximumRequestBodyBytes} onChange={(event) => setMaximumRequestBodyBytes(event.target.value)} /></label>
          <label>Maximum response bytes<input type="number" min="1" value={maximumResponseBytes} onChange={(event) => setMaximumResponseBytes(event.target.value)} /></label>
          <label>Stop conditions (comma-separated)<textarea value={stopConditions} onChange={(event) => setStopConditions(event.target.value)} /></label>
          <label>Allowed testing days (comma-separated)<input value={testingDays} onChange={(event) => setTestingDays(event.target.value)} /></label>
          <label>Testing window start<input type="time" value={testingStartTime} onChange={(event) => setTestingStartTime(event.target.value)} /></label>
          <label>Testing window end<input type="time" value={testingEndTime} onChange={(event) => setTestingEndTime(event.target.value)} /></label>
          <label>Testing timezone<input maxLength={64} value={testingTimezone} onChange={(event) => setTestingTimezone(event.target.value)} /></label>
          <label>Blackout starts (optional, include timezone)<input value={blackoutStartsAt} onChange={(event) => setBlackoutStartsAt(event.target.value)} placeholder="2030-01-01T12:00:00Z" /></label>
          <label>Blackout ends (optional, include timezone)<input value={blackoutEndsAt} onChange={(event) => setBlackoutEndsAt(event.target.value)} placeholder="2030-01-01T13:00:00Z" /></label>
          <label>Blackout reason (required with blackout)<input maxLength={200} value={blackoutReason} onChange={(event) => setBlackoutReason(event.target.value)} /></label>
        </div>
        <div className="boundary-review"><strong>Data handling</strong>
          <label>Real-user data<select value={realUserData} onChange={(event) => { setRealUserData(event.target.value as DataHandlingReview["realUserData"]); setMaximumRecordsToView(""); }}><option value="avoid_and_stop">Avoid and stop if encountered</option><option value="minimal_if_explicit">Minimal only when explicit</option></select></label>
          {realUserData === "minimal_if_explicit" && <label>Maximum records to view<input type="number" min="1" value={maximumRecordsToView} onChange={(event) => setMaximumRecordsToView(event.target.value)} /></label>}
          <label>Retention days<input type="number" min="1" value={retentionDays} onChange={(event) => setRetentionDays(event.target.value)} /></label>
          <label>Approved storage<input value="Local encrypted storage only" disabled /></label>
          <label>Remote AI maximum classification<select value={remoteAiMaxClassification} onChange={(event) => setRemoteAiMaxClassification(event.target.value as DataHandlingReview["remoteAiMaxClassification"])}><option value="none">None</option><option value="public">Public</option><option value="internal">Internal</option><option value="confidential">Confidential</option></select></label>
          <label>Redaction rules (comma-separated)<textarea value={redactionRules} onChange={(event) => setRedactionRules(event.target.value)} /></label>
        </div>
        <div className="boundary-review"><strong>Reporting terms</strong>
          <label>Submission channel<input value={submissionChannel} onChange={(event) => setSubmissionChannel(event.target.value)} /></label>
          <label>Required report fields (comma-separated)<textarea value={requiredFields} onChange={(event) => setRequiredFields(event.target.value)} /></label>
          <label>Evidence rules (comma-separated)<textarea value={evidenceRules} onChange={(event) => setEvidenceRules(event.target.value)} /></label>
          <label>Disclosure timeline<textarea maxLength={500} value={disclosureTimeline} onChange={(event) => setDisclosureTimeline(event.target.value)} /></label>
          <p className="hint">Submission always requires human approval. Automatic submission remains disabled.</p>
        </div>
        <label>Review rationale<textarea maxLength={500} value={normalizationRationale} onChange={(event) => setNormalizationRationale(event.target.value)} /></label>
      </fieldset>
      <button type="button" onClick={reviewBundle} disabled={reviewIds.length === 0}>Use reviewed source bundle</button>
      {reviewError && <p className="result bad" role="alert">Review denied: {reviewError}</p>}
      {selectedSources.length > 0 && <dl className="hash"><dt>Reviewed immutable sources</dt><dd>{selectedSources.map((item) => item.id).join(", ")}</dd><dt>Primary authority</dt><dd>{selectedSources[0].authority}</dd><dt>SHA-256 provenance</dt><dd>{selectedSources.map((item) => item.content_hash).join(", ")}</dd></dl>}
    </section>
  );
}
