# Architecture

gh-attest is a single [Cloudflare Worker](../src/index.ts) with three entry
points — an HTTP router, an hourly cron, and a queue consumer — backed by D1,
R2, and a Queue, all provisioned in Cloudflare's `eu` jurisdiction. It ingests
GitHub security posture as immutable timestamped snapshots and renders them into
auditor-ready evidence packages mapped to SOC 2 / ISO 27001 controls.

This document is the shape of the system. For *why* a given GitHub signal counts
as evidence for a given control, see [framework-mapping.md](framework-mapping.md).

## System context

```mermaid
flowchart LR
  subgraph ext[External]
    GH["GitHub App<br/>webhooks · OAuth · REST API"]
    USER["User / Auditor<br/>browser"]
  end

  subgraph cf["Cloudflare Worker — src/index.ts"]
    FETCH["fetch()<br/>HTTP router"]
    CRON["scheduled()<br/>hourly cron"]
    QUEUE["queue()<br/>export consumer"]
  end

  subgraph store["Storage — EU jurisdiction"]
    D1[("D1<br/>gh-attest-db-eu")]
    R2[("R2<br/>gh-attest-exports-eu")]
    Q[["Queue<br/>generate-export"]]
  end

  GH -- "POST /webhooks/*" --> FETCH
  USER -- "login · dashboard · exports" --> FETCH
  CRON -- "poll (installation token)" --> GH

  FETCH -- "snapshots · export rows" --> D1
  FETCH -- "enqueue job" --> Q
  FETCH -- "stream download" --> R2

  CRON -- "snapshots · retention" --> D1
  CRON -- "retention delete" --> R2

  Q --> QUEUE
  QUEUE -- "read evidence" --> D1
  QUEUE -- "write file" --> R2
```

## Entry points

| Handler | Trigger | Responsibility | Code |
| --- | --- | --- | --- |
| `fetch` | HTTP request | Webhooks, OAuth/session dashboard, export requests + downloads, admin ops | [index.ts](../src/index.ts) |
| `scheduled` | Cron `0 * * * *` (hourly) | Poll GitHub for state webhooks never announce; enforce retention | [index.ts](../src/index.ts) |
| `queue` | `generate-export` message | Render CSV/PDF off the request path into R2 | [index.ts](../src/index.ts) |

### Routes and their auth

| Route | Auth | Purpose |
| --- | --- | --- |
| `POST /webhooks/github`, `/webhooks/marketplace` | HMAC (`GITHUB_WEBHOOK_SECRET`) | Ingest App / marketplace events |
| `GET /login`, `/callback`, `/logout` | OAuth state cookie | Dashboard sign-in |
| `GET /`, `/access-review` | Session cookie | Posture dashboard, membership diff |
| `POST /exports`, `/resync`, `/switch` | Session cookie | Dashboard actions (installation-scoped) |
| `GET /exports/:id[/download]` | Session cookie | Export status / file (scoped to installation) |
| `POST /admin/{poll,export,cleanup,purge}`, `GET /admin/export/:id` | Bearer (`ADMIN_TOKEN`) | Operations |

## Ingestion — two paths into one table

Both paths write to the append-only `snapshots` table; nothing is ever updated
in place, which is what makes the table a point-in-time audit trail.

### Webhooks (change events)

```mermaid
sequenceDiagram
  autonumber
  participant GH as GitHub
  participant W as Worker (fetch)
  participant D1 as D1
  participant R2 as R2

  GH->>W: POST /webhooks/github (event + X-Hub-Signature-256)
  W->>W: verifySignature(body, GITHUB_WEBHOOK_SECRET)
  alt invalid signature
    W-->>GH: 401
  else valid
    W->>W: extractFact(event) → {resource, status}
    W->>D1: upsert installations row
    alt installation.deleted
      W->>D1: DELETE all rows for installation
      W->>R2: delete export objects
      W-->>GH: 200 (purged)
    else suspend / unsuspend
      W->>D1: toggle suspended_at
      W-->>GH: 200
    else normal event
      W->>D1: INSERT snapshot (append-only)
      W-->>GH: 200
    end
  end
```

### Hourly poll + retention (baseline / drift)

Webhooks only fire on change, so protection that existed *before* install, and
current membership, would never appear. The cron closes that gap and enforces
the retention windows in the same invocation.

```mermaid
sequenceDiagram
  autonumber
  participant Cron as scheduled (hourly)
  participant W as Worker
  participant GH as GitHub REST
  participant D1 as D1
  participant R2 as R2

  Cron->>W: fire
  par Poll every active installation
    W->>GH: app JWT → installation token
    W->>GH: repos · branch protection · rulesets · org/team members
    GH-->>W: current state
    W->>D1: INSERT snapshots (one captured_at per batch)
  and Retention cleanup
    W->>D1: SELECT expired export r2_keys
    W->>R2: delete expired objects
    W->>D1: DELETE exports > 90d, snapshots > 396d
  end
```

## Export pipeline

Rendering runs off the request path via the Queue because PDF / large CSV can
exceed request CPU limits. The `exports` row is the job's state machine
(`queued → processing → done | error`).

```mermaid
sequenceDiagram
  autonumber
  participant U as User (session)
  participant W as Worker (fetch)
  participant D1 as D1
  participant Q as Queue
  participant C as Worker (queue)
  participant R2 as R2

  U->>W: POST /exports (framework, format)
  W->>D1: INSERT exports (status=queued)
  W->>Q: send job
  W-->>U: 303 redirect to dashboard

  Q->>C: deliver job
  C->>D1: status=processing
  C->>D1: buildEvidenceRows — snapshots ⋈ control_mappings
  C->>C: renderCsv / renderPdf
  C->>R2: put file at exports/{installation}/{jobId}.{fmt}
  C->>D1: status=done, r2_key
  Note over C,D1: render failure → status=error (deterministic, not retried)

  U->>W: GET /exports/:id/download
  W->>D1: lookup scoped to session installation
  W->>R2: get object
  R2-->>W: file body
  W-->>U: stream (Content-Disposition: attachment)
```

## Data model

`control_mappings` has **no foreign key** to `snapshots`. Mapping is a join on
`(resource, status)` performed at query/export time — so a mapping can be
corrected without re-ingesting webhook history. A mapping row with `status =
NULL` matches any status for that resource.

```mermaid
erDiagram
  installations ||--o{ snapshots : has
  installations ||--o{ exports : has
  snapshots }o..o{ control_mappings : "query-time join on (resource, status)"

  installations {
    integer installation_id PK
    text    org_login
    text    installed_at
    text    suspended_at "null unless suspended"
  }
  snapshots {
    integer id PK
    integer installation_id FK
    text    repo "null for org-level facts"
    text    subject "member/team for access facts"
    text    resource "e.g. branch_protection"
    text    status "e.g. enabled | open | added"
    text    raw_payload "original JSON, audit trail"
    text    captured_at
  }
  control_mappings {
    integer id PK
    text    resource
    text    status "null matches any"
    text    framework "soc2 | iso27001"
    text    control_id "e.g. CC8.1 | A.8.32"
    text    posture "positive | negative | informational"
    text    rationale
  }
  exports {
    text    id PK "uuid"
    integer installation_id FK
    text    framework
    text    format "csv | pdf"
    text    status "queued|processing|done|error"
    text    r2_key "null until rendered"
    text    error
    text    created_at
    text    completed_at
  }
```

### Evidence query

`buildEvidenceRows` ([exporter.ts](../src/exporter.ts)) reduces the append-only
table to current posture, then attaches controls:

```mermaid
flowchart TB
  S[("snapshots<br/>append-only")] --> L["latest row per<br/>(repo, subject, resource)"]
  L --> J{{"JOIN control_mappings<br/>on resource + status"}}
  CM[("control_mappings")] --> J
  J --> F["filter by framework<br/>(soc2 | iso27001 | all)"]
  F --> C["collapse branch_protection<br/>+ repository_ruleset to one row"]
  C --> E["evidence rows<br/>control · posture · rationale"]
  E --> CSV["renderCsv"]
  E --> PDF["renderPdf"]
```

Unmapped `(resource, status)` pairs (e.g. `unavailable`, raw `push`) simply
produce no rows — no evidence in either direction.

Classic branch protection and repository rulesets both attest the same control,
so the two are collapsed to one row per (framework, control, repo) — enabled
wins over disabled — rather than letting an unused mechanism report a gap the
other one covers.

## Boundaries & isolation

- **Multi-tenant scoping.** Every session route is scoped to the session's
  `installationId`; the allowed set lives in the signed session, so a tampered
  id can't widen access. Export downloads are looked up with an installation
  filter, so one org can't read another's file by guessing its UUID.
- **Three auth schemes.** HMAC for webhooks, signed session cookies
  (`SESSION_SECRET`) for the dashboard, timing-safe bearer (`ADMIN_TOKEN`) for
  `/admin/*`.
- **Data residency.** D1, R2, and the Queue are all in the `eu` jurisdiction;
  see [wrangler.jsonc](../wrangler.jsonc). No source code or access tokens are
  stored — only posture facts and their raw event JSON.
- **Deletion.** Uninstall (`installation.deleted`) purges all D1 rows and R2
  objects for the installation; `/admin/purge` does the same on request.

## Where things live

| Concern | File |
| --- | --- |
| Router, handlers, retention, purge | [src/index.ts](../src/index.ts) |
| Webhook verification + fact extraction | [src/webhook.ts](../src/webhook.ts) |
| GitHub polling (protection, rulesets, access) | [src/poller.ts](../src/poller.ts) |
| App JWT + installation tokens | [src/github-app.ts](../src/github-app.ts) |
| OAuth + session sign/verify | [src/auth.ts](../src/auth.ts) |
| Evidence query + CSV/PDF rendering | [src/exporter.ts](../src/exporter.ts) |
| Access-review diff | [src/access-review.ts](../src/access-review.ts) |
| Dashboard HTML | [src/dashboard.ts](../src/dashboard.ts) |
| Schema + control mappings | [migrations/](../migrations) |
```
