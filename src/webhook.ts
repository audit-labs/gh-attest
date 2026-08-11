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

// Minimal resource/status extraction per event type. Control-ID mapping
// (resource+status -> SOC 2 / ISO 27001 control) is a separate, later step.
export function extractFact(eventType: string, payload: Record<string, unknown>): ExtractedFact {
  const action = typeof payload.action === "string" ? payload.action : undefined;

  switch (eventType) {
    // The event is scoped to one rule, which may target any branch. Only a
    // rule whose pattern is exactly the default branch changes the repo's
    // protection state (normalized to the enabled/disabled vocabulary the
    // poller shares); any other rule is recorded as an unmapped trail event,
    // with the hourly poll authoritative for current state.
    case "branch_protection_rule": {
      const rule = payload.rule as Record<string, unknown> | undefined;
      const repository = payload.repository as Record<string, unknown> | undefined;
      const pattern = typeof rule?.name === "string" ? rule.name : null;
      const defaultBranch = typeof repository?.default_branch === "string" ? repository.default_branch : undefined;
      if (pattern !== null && pattern === defaultBranch) {
        return { resource: "branch_protection", status: action === "deleted" ? "disabled" : "enabled", subject: null };
      }
      return { resource: "branch_protection_rule_event", status: action ?? "unknown", subject: pattern };
    }
    // Ruleset events are ruleset-scoped: one ruleset being created or deleted
    // says nothing about whether *other* active rulesets still cover the
    // default branch, so this is trail-only; current repository_ruleset state
    // comes from the poller's /rules/branches/{default-branch} check.
    case "repository_ruleset": {
      const ruleset = payload.repository_ruleset as Record<string, unknown> | undefined;
      const id = typeof ruleset?.id === "number" ? String(ruleset.id) : null;
      return { resource: "repository_ruleset_event", status: action ?? "unknown", subject: id };
    }
    case "dependabot_alert":
    case "code_scanning_alert": {
      const alert = payload.alert as Record<string, unknown> | undefined;
      const state = typeof alert?.state === "string" ? alert.state : undefined;
      return { resource: eventType, status: state ?? action ?? "unknown", subject: alertNumber(alert) };
    }
    // Unlike the two alert payloads above, the secret-scanning webhook alert
    // carries no `state` field — only `resolution`, which is set iff the
    // alert is resolved. Derive open/resolved from that (falling back to
    // `state` should GitHub ever add it).
    case "secret_scanning_alert": {
      const alert = payload.alert as Record<string, unknown> | undefined;
      const state = typeof alert?.state === "string" ? alert.state : undefined;
      return {
        resource: eventType,
        status: state ?? (alert?.resolution ? "resolved" : "open"),
        subject: alertNumber(alert),
      };
    }
    // Repository collaborators. Org-level membership arrives on the
    // `organization` event below, not here.
    case "member": {
      const member = payload.member as Record<string, unknown> | undefined;
      return {
        resource: "member_access",
        status: action ?? "unknown",
        subject: typeof member?.login === "string" ? member.login : null,
      };
    }
    case "team": {
      const team = payload.team as Record<string, unknown> | undefined;
      return {
        resource: "team",
        status: action ?? "unknown",
        subject: typeof team?.slug === "string" ? team.slug : null,
      };
    }
    case "organization": {
      const membership = payload.membership as Record<string, unknown> | undefined;
      const user = membership?.user as Record<string, unknown> | undefined;
      // member_invited identifies the invitee via `invitation` (login for
      // existing users, email otherwise) rather than `membership`.
      const invitation = payload.invitation as Record<string, unknown> | undefined;
      const subject =
        typeof user?.login === "string"
          ? user.login
          : typeof invitation?.login === "string"
            ? invitation.login
            : typeof invitation?.email === "string"
              ? invitation.email
              : null;
      return { resource: "org_membership", status: action ?? "unknown", subject };
    }
    case "repository":
      return { resource: "repository", status: action ?? "unknown", subject: null };
    case "push":
      return { resource: "push", status: "received", subject: null };
    default:
      return { resource: eventType, status: action ?? "received", subject: null };
  }
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
