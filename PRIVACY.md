# gh-attest — Privacy Policy

**Effective date:** 2026-07-19

gh-attest ("the App") is a GitHub App operated by Audit Labs ("we",
"us"). It helps compliance and security teams collect
point-in-time evidence about the security configuration of their own
GitHub organization and map it to SOC 2 and ISO 27001 control
identifiers. This policy explains what the App processes, why, how long
it is kept, and your choices.

This policy covers the gh-attest App and its dashboard only. It does not
cover GitHub itself — see GitHub's Privacy Statement for how GitHub
handles your data.

## What we process

The App processes data only for organizations that have installed it,
and only within the scope of the permissions granted at installation.

**Organization & installation metadata.** Installation ID, organization
login, and installation/suspension timestamps.

**Security & access-control signals (the evidence).** As your
configuration changes and on a periodic re-sync, the App records
point-in-time "snapshots" of security-relevant state, which may include:

- branch protection and repository ruleset configuration (enabled /
  disabled);
- repository, push, and member/team change events;
- Dependabot, code scanning, and secret scanning alert state.

For audit-trail integrity, each snapshot stores the original GitHub
webhook payload that produced it. These payloads can contain repository
names, team names, and the GitHub logins of members whose access
changed.

**Dashboard sign-in.** When you sign in to the dashboard, the App reads
your GitHub user ID and login and the list of installations you can
access, solely to confirm you belong to an organization that installed
the App. Your GitHub profile is stored only inside a signed, expiring
session cookie in your browser — it is **not** written to our database.

**Exports.** Evidence exports you generate (CSV or PDF) are stored so
you can download them, along with metadata about each export job.

## What we do NOT process

- We do **not** store the contents of your source code.
- We do **not** store GitHub personal access tokens. The App
  authenticates using short-lived installation access tokens minted per
  request (valid ~1 hour) and never persisted.
- We do **not** collect passwords or payment information.
- We do **not** sell your data or share it with third parties for
  advertising, and we do **not** aggregate data across organizations.

## How we use it

Solely to provide the App's function: presenting your current security
posture, mapping it to SOC 2 / ISO 27001 controls, and generating
point-in-time evidence exports and access-review comparisons for your
own organization.

## Where it is stored and how it is protected

All data is stored on Cloudflare's platform (D1 and R2) in the
**European Union**. Both the database and the object storage are created
under Cloudflare's `eu` jurisdiction, which restricts them to storing and
running within the EU.

Note that the application code itself runs on Cloudflare Workers, which
execute at the network edge close to the requesting user. A request made
from outside the EU is therefore processed outside the EU, even though
the data it reads and writes is stored within the EU. We do not currently
use Cloudflare's Regional Services to constrain where request processing
occurs.

Protections include:

- webhook payloads are verified with HMAC-SHA256 signatures before
  processing;
- the GitHub App private key, webhook secret, and session-signing key
  are stored as encrypted platform secrets, never in source code;
- authentication uses short-lived installation tokens that are never
  stored;
- all stored data is scoped per installation, and the dashboard enforces
  that a signed-in user can access only their own organization's data.

## Subprocessors

- **Cloudflare, Inc.** — hosting, database (D1), and object storage (R2),
  under the EU jurisdiction described above.

**GitHub, Inc.** is the system the data comes from. Your organization has
its own relationship with GitHub, so GitHub is not a subprocessor we
engage on your behalf.

If we add or replace a subprocessor, we will notify installed
organizations in advance so they have an opportunity to object.

## Security incidents

If we become aware of a breach affecting your organization's data, we
will notify you without undue delay and provide the information you need
to meet your own notification obligations.

## Data retention & deletion

Evidence snapshots are retained for 13 months, export files
for 90 days, and all data for an organization is deleted when the App
is uninstalled. You may also request deletion at any time.

## Your choices and rights

**If you administer an installing organization:**

- **Uninstall** the App at any time from your organization's GitHub
  settings to stop all processing and trigger deletion of your data.
- **Export** your organization's data as CSV or PDF from the dashboard
  at any time.
- **Request deletion** of your organization's data by contacting us.
- Request a **Data Processing Addendum** if you need one for your own
  compliance obligations.

**If you are an individual whose GitHub login appears in an
organization's data:** we hold that data on behalf of that organization,
which decides how it is used. We have no direct relationship with you
and cannot verify your identity, so please direct access, correction, or
deletion requests to the organization. If you contact us, we will refer
your request to them rather than acting on it ourselves.

Depending on your jurisdiction (e.g., GDPR, CCPA/CPRA), you may have
additional rights; the organization can exercise them with our
assistance.

## Contact

privacy@audit-labs.dev — Audit Labs

## Changes

We may update this policy. Material changes will be reflected by the
effective date above and, where appropriate, communicated to installed
organizations.
