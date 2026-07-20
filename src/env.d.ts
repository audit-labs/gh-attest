// Secrets are set with `wrangler secret put`, not declared in
// wrangler.jsonc, so `wrangler types` can only discover their names from a
// local `.dev.vars` — which is gitignored and therefore absent in CI.
// Declaring them here merges with the generated `Env` interface, so the
// contract is explicit in source and type checking behaves the same on a
// developer machine and in a clean clone.
//
// Keep in sync with `.dev.vars.example` and the secrets set on the Worker.
interface Env {
  /** GitHub App ID, for minting the App JWT. */
  GITHUB_APP_ID: string;
  /** GitHub App private key (PEM). PKCS#1 or PKCS#8 both accepted. */
  GITHUB_APP_PRIVATE_KEY: string;
  /** Shared secret used to verify inbound webhook signatures. */
  GITHUB_WEBHOOK_SECRET: string;
  /** OAuth client credentials for dashboard sign-in. */
  GITHUB_APP_CLIENT_ID: string;
  GITHUB_APP_CLIENT_SECRET: string;
  /** HMAC key for signing session cookies. */
  SESSION_SECRET: string;
  /** Bearer token guarding the /admin/* routes. */
  ADMIN_TOKEN: string;
}
