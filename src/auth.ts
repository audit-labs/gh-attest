import { hmacHex, timingSafeEqualHex } from "./crypto-utils";

const GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token";
const GITHUB_API = "https://api.github.com";

export const SESSION_COOKIE = "gh_attest_session";
export const STATE_COOKIE = "gh_attest_oauth_state";
const SESSION_TTL_SECONDS = 60 * 60 * 12; // 12 hours
export const STATE_TTL_SECONDS = 60 * 10; // 10 minutes

export interface SessionPayload {
  userId: number;
  login: string;
  /** The installation currently being viewed. */
  installationId: number;
  /**
   * Every installation this user may view, captured at login. Kept inside the
   * signed payload so switching can be authorised without re-querying GitHub
   * and without trusting a client-supplied id. Optional so sessions issued
   * before the switcher existed still verify.
   */
  installationIds?: number[];
  exp: number;
}

export function buildAuthorizeUrl(env: Env, redirectUri: string, state: string): string {
  const url = new URL(GITHUB_AUTHORIZE_URL);
  url.searchParams.set("client_id", env.GITHUB_APP_CLIENT_ID);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("state", state);
  return url.toString();
}

interface GithubTokenResponse {
  access_token?: string;
  error?: string;
  error_description?: string;
}

export async function exchangeCodeForToken(env: Env, code: string, redirectUri: string): Promise<string> {
  const res = await fetch(GITHUB_TOKEN_URL, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: env.GITHUB_APP_CLIENT_ID,
      client_secret: env.GITHUB_APP_CLIENT_SECRET,
      code,
      redirect_uri: redirectUri,
    }),
  });

  const data = (await res.json()) as GithubTokenResponse;
  if (!res.ok || !data.access_token) {
    throw new Error(data.error_description ?? `GitHub OAuth token exchange failed (${res.status})`);
  }
  return data.access_token;
}

interface GithubUser {
  id: number;
  login: string;
}

export async function fetchGithubUser(userAccessToken: string): Promise<GithubUser> {
  const res = await fetch(`${GITHUB_API}/user`, {
    headers: {
      Authorization: `Bearer ${userAccessToken}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "gh-attest",
    },
  });
  if (!res.ok) throw new Error(`Failed to fetch GitHub user (${res.status})`);
  return res.json();
}

interface GithubInstallationsResponse {
  installations: Array<{ id: number }>;
}

// Installations the logged-in user themselves can see via this App —
// scoped by GitHub to orgs/repos they actually have access to.
export async function fetchUserInstallationIds(userAccessToken: string): Promise<number[]> {
  const res = await fetch(`${GITHUB_API}/user/installations`, {
    headers: {
      Authorization: `Bearer ${userAccessToken}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "gh-attest",
    },
  });
  if (!res.ok) throw new Error(`Failed to fetch user installations (${res.status})`);
  const data = (await res.json()) as GithubInstallationsResponse;
  return data.installations.map((installation) => installation.id);
}

function base64UrlEncode(input: string): string {
  // Padding is bounded to two characters, so the quantifier is too — an
  // unbounded `=+$` backtracks super-linearly.
  return btoa(input).replaceAll("+", "-").replaceAll("/", "_").replace(/={1,2}$/, "");
}

function base64UrlDecode(input: string): string {
  const padded = input.replaceAll("-", "+").replaceAll("_", "/");
  const padding = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  return atob(padded + padding);
}

export async function signSession(payload: SessionPayload, secret: string): Promise<string> {
  const body = base64UrlEncode(JSON.stringify(payload));
  const signature = await hmacHex(body, secret);
  return `${body}.${signature}`;
}

export async function verifySession(token: string, secret: string): Promise<SessionPayload | null> {
  const [body, signature] = token.split(".");
  if (!body || !signature) return null;

  const expectedSignature = await hmacHex(body, secret);
  if (!timingSafeEqualHex(signature, expectedSignature)) return null;

  let payload: SessionPayload;
  try {
    payload = JSON.parse(base64UrlDecode(body)) as SessionPayload;
  } catch {
    return null;
  }

  if (payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload;
}

export function newSessionPayload(
  user: GithubUser,
  installationId: number,
  installationIds: number[],
): SessionPayload {
  return {
    userId: user.id,
    login: user.login,
    installationId,
    installationIds,
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
  };
}

export { SESSION_TTL_SECONDS };
