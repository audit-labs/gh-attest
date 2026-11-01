# Security Policy

## Supported versions

gh-attest is self-hosted; Audit Labs does not run an instance. Only the latest
`main` is supported. Fixes land there, and each operator deploys them to their
own Worker.

## Reporting a vulnerability

Please report privately rather than opening a public issue.

- **Preferred:** [Report a vulnerability](https://github.com/audit-labs/gh-attest/security/advisories/new)
  via GitHub private vulnerability reporting.
- **Alternative:** email `security@audit-labs.dev`.

Please include enough detail to reproduce: the endpoint or component, the
request, and what you observed. If you have a proof of concept, use your own
deployment.

We aim to acknowledge within 3 working days and to keep you updated until the
issue is resolved. We will credit you when publishing a fix unless you prefer
otherwise. We do not currently run a paid bug bounty.

## Scope

**In scope**

- The Worker and its endpoints, including webhook signature verification,
  session handling, and the `/admin/*` bearer-guarded routes.
- Tenant isolation — anything allowing one installation on a deployment to
  read another's evidence or exports.
- The evidence pipeline, where incorrect data could mislead an audit.

**Out of scope**

- GitHub and Cloudflare themselves. Report those to
  [GitHub](https://bounty.github.com/) and
  [Cloudflare](https://hackerone.com/cloudflare) respectively.
- Findings that gh-attest *reports about your own organization* — a repository
  without branch protection is the product working, not a vulnerability.
- Denial of service, volumetric testing, and social engineering.

## Testing guidance

Please test against your own deployment and an organization you control. Do
not attempt to access anyone else's deployment or data.

## How gh-attest handles data

Read-only GitHub scopes, short-lived installation tokens that are never
persisted, no source code or personal access tokens stored, and all data held
in the operator's Cloudflare account under the `eu` jurisdiction. See
[PRIVACY.md](PRIVACY.md) for the full description and [README.md](README.md)
for the architecture.
