# gh-attest

Turns GitHub security settings into auditor-ready evidence. A GitHub App that
records branch protection, scanning alerts, and organization access as they
change, maps them to SOC 2 and ISO 27001 controls, and exports point-in-time
CSV and PDF evidence packages.

Read-only — it never modifies your repositories, permissions, or membership.

## What it collects

| Signal | Evidence for |
| --- | --- |
| Branch protection, repository rulesets | SOC 2 CC8.1 · ISO 27001 A.8.32 |
| Secret scanning alerts | SOC 2 CC6.6 |
| Dependabot alerts | SOC 2 CC7.1, CC7.2 |
| Code scanning alerts | ISO 27001 A.8.28, A.8.29 |
| Organization / team membership | SOC 2 CC6.2, CC6.3 · ISO 27001 A.5.18 |
| Repository inventory | ISO 27001 A.5.9 |

Mappings live in `migrations/` and are applied as a join at query time, so a
mapping can be corrected without re-ingesting history.

## How it works

Webhooks capture changes as they happen; an hourly cron polls for state that
webhooks never announce (protection that existed before install, and current
membership). Each observation is stored as a timestamped snapshot in D1.
Exports render off the request path via a queue, into R2.

**Stack:** Cloudflare Workers · D1 · R2 · Queues. All storage is provisioned
under Cloudflare's `eu` jurisdiction.

## Endpoints

| Route | Auth | Purpose |
| --- | --- | --- |
| `GET /` | session | Dashboard: current posture, exports |
| `GET /access-review` | session | Membership changes since a date |
| `POST /exports`, `/resync`, `/switch` | session | Dashboard actions |
| `GET /exports/:id[/download]` | session | Export status / file |
| `POST /webhooks/github` | HMAC | App events |
| `POST /webhooks/marketplace` | HMAC | Marketplace events |
| `POST /admin/{poll,export,cleanup,purge}` | bearer | Operations |

Session routes are scoped by installation; admin routes require `ADMIN_TOKEN`.

## Development

```sh
npm install
cp .dev.vars.example .dev.vars   # fill in, see below
npm run db:migrate:local
npm run dev
```

Type checking: `npm run typecheck`. Generate binding types after editing
`wrangler.jsonc`: `npm run types`.

## Deployment

```sh
npm run db:migrate:remote
npm run deploy
```

Secrets are set with `wrangler secret put <NAME>` — never in `wrangler.jsonc`:

| Secret | Purpose |
| --- | --- |
| `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY` | Mint installation tokens |
| `GITHUB_WEBHOOK_SECRET` | Verify webhook signatures |
| `GITHUB_APP_CLIENT_ID`, `GITHUB_APP_CLIENT_SECRET` | Dashboard OAuth |
| `SESSION_SECRET` | Sign session cookies |
| `ADMIN_TOKEN` | Bearer for `/admin/*` |

Pipe the private key from its file rather than pasting it:
`wrangler secret put GITHUB_APP_PRIVATE_KEY < key.pem`

> Cron triggers occasionally stop firing after a deploy. If the hourly poll
> goes quiet, set `triggers.crons` to `[]`, deploy, restore it, and deploy
> again — a same-value redeploy does not clear it.

## Data handling

Evidence is retained for 13 months and exports for 90 days; everything for an
installation is deleted when the App is uninstalled. No source code or access
tokens are stored. See [PRIVACY.md](PRIVACY.md).

Retention periods are defined in `src/index.ts` and restated in `PRIVACY.md` —
change both together.

## License

GPL-3.0. See [LICENSE](LICENSE).
