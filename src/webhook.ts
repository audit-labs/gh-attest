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
}

// Minimal resource/status extraction per event type. Control-ID mapping
// (resource+status -> SOC 2 / ISO 27001 control) is a separate, later step.
export function extractFact(eventType: string, payload: Record<string, unknown>): ExtractedFact {
  const action = typeof payload.action === "string" ? payload.action : undefined;

  switch (eventType) {
    // Normalized to current-state vocabulary (enabled/disabled) rather than
    // the raw action, so this lines up with what the poller reports for
    // pre-existing protection state — the mapping table joins on one
    // vocabulary regardless of source.
    case "branch_protection_rule":
      return { resource: "branch_protection", status: action === "deleted" ? "disabled" : "enabled" };
    case "repository_ruleset":
      return { resource: "repository_ruleset", status: action === "deleted" ? "disabled" : "enabled" };
    case "dependabot_alert":
    case "code_scanning_alert":
    case "secret_scanning_alert": {
      const alert = payload.alert as Record<string, unknown> | undefined;
      const state = typeof alert?.state === "string" ? alert.state : undefined;
      return { resource: eventType, status: state ?? action ?? "unknown" };
    }
    case "member":
      return { resource: "member_access", status: action ?? "unknown" };
    case "team":
      return { resource: "team", status: action ?? "unknown" };
    case "repository":
      return { resource: "repository", status: action ?? "unknown" };
    case "push":
      return { resource: "push", status: "received" };
    default:
      return { resource: eventType, status: action ?? "received" };
  }
}

export function extractRepoFullName(payload: Record<string, unknown>): string | null {
  const repository = payload.repository as Record<string, unknown> | undefined;
  return typeof repository?.full_name === "string" ? repository.full_name : null;
}

export function extractInstallationId(payload: Record<string, unknown>): number | null {
  const installation = payload.installation as Record<string, unknown> | undefined;
  return typeof installation?.id === "number" ? installation.id : null;
}
