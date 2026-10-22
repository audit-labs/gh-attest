import { timingSafeEqualHex, bytesToHex } from "./crypto-utils";

const SIGNATURE_PREFIX = "sha256=";

export async function verifySignature(
  rawBody: ArrayBuffer,
  signatureHeader: string | null,
  secret: string,
): Promise<boolean> {
  if (!signatureHeader?.startsWith(SIGNATURE_PREFIX)) return false;

  const providedHex = signatureHeader.slice(SIGNATURE_PREFIX.length);
  if (!/^[0-9a-f]+$/i.test(providedHex) || providedHex.length !== 64) return false;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const expected = bytesToHex(new Uint8Array(await crypto.subtle.sign("HMAC", key, rawBody)));

  return timingSafeEqualHex(providedHex, expected);
}

interface ExtractedFact {
  resource: string;
  status: string;
  // Which entity within the repo/org the fact is about (alert number, member
  // login, team slug). Part of the exporter's latest-row-wins key, so facts
  // about different entities in the same repo don't overwrite each other.
  subject: string | null;
}

type Payload = Record<string, unknown>;
type Extractor = (payload: Payload, action: string | undefined) => ExtractedFact;

function record(value: unknown): Payload | undefined {
  return value as Payload | undefined;
}

function stringField(obj: Payload | undefined, field: string): string | null {
  const value = obj?.[field];
  return typeof value === "string" ? value : null;
}

// Minimal resource/status extraction per event type. Control-ID mapping
// (resource+status -> SOC 2 / ISO 27001 control) is a separate, later step.
const EXTRACTORS: Record<string, Extractor> = {
  // The event is scoped to one rule, which may target any branch. Only a
  // rule whose pattern is exactly the default branch changes the repo's
  // protection state (normalized to the enabled/disabled vocabulary the
  // poller shares); any other rule is recorded as an unmapped trail event,
  // with the hourly poll authoritative for current state.
  branch_protection_rule: (payload, action) => {
    const pattern = stringField(record(payload.rule), "name");
    const defaultBranch = stringField(record(payload.repository), "default_branch") ?? undefined;
    if (pattern !== null && pattern === defaultBranch) {
      return { resource: "branch_protection", status: action === "deleted" ? "disabled" : "enabled", subject: null };
    }
    return { resource: "branch_protection_rule_event", status: action ?? "unknown", subject: pattern };
  },
  // Ruleset events are ruleset-scoped: one ruleset being created or deleted
  // says nothing about whether *other* active rulesets still cover the
  // default branch, so this is trail-only; current repository_ruleset state
  // comes from the poller's /rules/branches/{default-branch} check.
  repository_ruleset: (payload, action) => {
    const ruleset = record(payload.repository_ruleset);
    const id = typeof ruleset?.id === "number" ? String(ruleset.id) : null;
    return { resource: "repository_ruleset_event", status: action ?? "unknown", subject: id };
  },
  dependabot_alert: (payload, action) => stateAlert("dependabot_alert", payload, action),
  code_scanning_alert: (payload, action) => stateAlert("code_scanning_alert", payload, action),
  // Unlike the two alert payloads above, the secret-scanning webhook alert
  // carries no `state` field — only `resolution`, which is set iff the
  // alert is resolved. Derive open/resolved from that (falling back to
  // `state` should GitHub ever add it).
  secret_scanning_alert: (payload) => {
    const alert = record(payload.alert);
    return {
      resource: "secret_scanning_alert",
      status: stringField(alert, "state") ?? (alert?.resolution ? "resolved" : "open"),
      subject: alertNumber(alert),
    };
  },
  // Repository collaborators. Org-level membership arrives on the
  // `organization` event below, not here.
  member: (payload, action) => ({
    resource: "member_access",
    status: action ?? "unknown",
    subject: stringField(record(payload.member), "login"),
  }),
  team: (payload, action) => ({
    resource: "team",
    status: action ?? "unknown",
    subject: stringField(record(payload.team), "slug"),
  }),
  // member_invited identifies the invitee via `invitation` (login for
  // existing users, email otherwise) rather than `membership`.
  organization: (payload, action) => {
    const user = record(record(payload.membership)?.user);
    const invitation = record(payload.invitation);
    const subject =
      stringField(user, "login") ?? stringField(invitation, "login") ?? stringField(invitation, "email");
    return { resource: "org_membership", status: action ?? "unknown", subject };
  },
  repository: (_payload, action) => ({ resource: "repository", status: action ?? "unknown", subject: null }),
  push: () => ({ resource: "push", status: "received", subject: null }),
};

function stateAlert(resource: string, payload: Payload, action: string | undefined): ExtractedFact {
  const alert = record(payload.alert);
  return { resource, status: stringField(alert, "state") ?? action ?? "unknown", subject: alertNumber(alert) };
}

export function extractFact(eventType: string, payload: Payload): ExtractedFact {
  const action = typeof payload.action === "string" ? payload.action : undefined;
  const extract = Object.hasOwn(EXTRACTORS, eventType) ? EXTRACTORS[eventType] : undefined;
  return extract ? extract(payload, action) : { resource: eventType, status: action ?? "received", subject: null };
}

function alertNumber(alert: Record<string, unknown> | undefined): string | null {
  return typeof alert?.number === "number" ? String(alert.number) : null;
}

export function extractRepoFullName(payload: Record<string, unknown>): string | null {
  const repository = payload.repository as Record<string, unknown> | undefined;
  return typeof repository?.full_name === "string" ? repository.full_name : null;
}

export function extractInstallationId(payload: Record<string, unknown>): number | null {
  const installation = payload.installation as Record<string, unknown> | undefined;
  return typeof installation?.id === "number" ? installation.id : null;
}
