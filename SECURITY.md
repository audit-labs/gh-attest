# Security Policy

## Supported versions

gh-attest is a hosted GitHub App. There is one supported version — the
currently deployed one. Fixes are rolled out to all installations at once;
there is nothing for you to upgrade.

## Reporting a vulnerability

Please report privately rather than opening a public issue.

- **Preferred:** [Report a vulnerability](https://github.com/audit-labs/gh-attest/security/advisories/new)
  via GitHub private vulnerability reporting.
- **Alternative:** email `security@audit-labs.dev`.

Please include enough detail to reproduce: the endpoint or component, the
request, and what you observed. If you have a proof of concept, use your own
organization's installation.

We aim to acknowledge within 3 working days and to keep you updated until the
issue is resolved. We will credit you when publishing a fix unless you prefer
otherwise. We do not currently run a paid bug bounty.

## Scope

**In scope**

- The Worker and its endpoints, including webhook signature verification,
  session handling, and the `/admin/*` bearer-guarded routes.
- Tenant isolation — anything allowing one installation to read another's
  evidence or exports.
- The evidence pipeline, where incorrect data could mislead an audit.

**Out of scope**

- GitHub and Cloudflare themselves. Report those to
  [GitHub](https://bounty.github.com/) and
  [Cloudflare](https://hackerone.com/cloudflare) respectively.
- Findings that gh-attest *reports about your own organization* — a repository
  without branch protection is the product working, not a vulnerability.
- Denial of service, volumetric testing, and social engineering.

## Testing guidance

Please test against an installation on an organization you control. Do not
attempt to access data belonging to another installation; if you believe you
have found a way to, stop and report it rather than confirming the extent.

## How gh-attest handles data

Read-only GitHub scopes, short-lived installation tokens that are never
persisted, no source code or personal access tokens stored, and all data held
in the EU. See [PRIVACY.md](PRIVACY.md) for the full description and
[README.md](README.md) for the architecture.
