# gh-attest — Data handling

gh-attest is self-hosted. Audit Labs does not run an instance and receives no
data from any deployment. Whoever deploys it operates it: the data described
here is stored in that operator's own Cloudflare account, and the operator is
responsible for it.

This document describes what a deployment processes, where it is stored, and
how long it is kept. It does not cover GitHub itself — see GitHub's Privacy
Statement for how GitHub handles your data.

## What a deployment processes

A deployment processes data only for organizations that have installed its
GitHub App, and only within the scope of the permissions granted at
installation.

**Organization & installation metadata.** Installation ID, organization
login, and installation/suspension timestamps. If repositories are excluded
from scanning, the excluded repository names are stored for that installation.

**Security & access-control signals (the evidence).** As configuration
changes and on a periodic re-sync, the Worker records point-in-time
"snapshots" of security-relevant state, which may include:

- branch protection and repository ruleset configuration (enabled /
  disabled);
- repository, push, and member/team change events;
- Dependabot, code scanning, and secret scanning alert state.

For audit-trail integrity, each snapshot stores the original GitHub
webhook payload that produced it. These payloads can contain repository
names, team names, and the GitHub logins of members whose access
changed.

**Dashboard sign-in.** On sign-in, the Worker reads the user's GitHub user ID
and login and the list of installations they can access, solely to confirm
they belong to an organization that installed the App. The profile is stored
only inside a signed, expiring session cookie in the browser — it is **not**
written to the database.

**Exports.** Evidence exports (CSV or PDF) are stored so they can be
downloaded, along with metadata about each export job.

## What it does NOT process

- It does **not** store the contents of source code.
- It does **not** store GitHub personal access tokens. The Worker
  authenticates using short-lived installation access tokens minted per
  request (valid ~1 hour) and never persisted.
- It does **not** collect passwords or payment information.
- It does **not** send data anywhere other than the operator's Cloudflare
  account and GitHub's API.

## Where it is stored and how it is protected

All data is stored in the operator's Cloudflare account (D1 and R2). The
deployment steps in the README create both under Cloudflare's `eu`
jurisdiction, which restricts them to storing and running within the EU.

The Worker itself runs on Cloudflare Workers, which execute at the network
edge close to the requesting user. A request made from outside the EU is
therefore processed outside the EU, even though the data it reads and writes
is stored within the EU.

Protections include:

- webhook payloads are verified with HMAC-SHA256 signatures before
  processing;
- the GitHub App private key, webhook secret, and session-signing key
  are stored as encrypted Worker secrets, never in source code;
- authentication uses short-lived installation tokens that are never
  stored;
- all stored data is scoped per installation, and the dashboard enforces
  that a signed-in user can access only their own organization's data.

## Data retention & deletion

Evidence snapshots are retained for 13 months, export files for 90 days, and
all data for an organization is deleted when the App is uninstalled. The
operator can also purge an installation through `POST /admin/purge`.

## Contact

Questions about the software: privacy@audit-labs.dev. Requests about data held
by a deployment go to the organization that operates it.
