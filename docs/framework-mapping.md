# Framework Mapping

This document is the rationale behind every control mapping in gh-attest: what
each GitHub signal is, which compliance control it is offered as evidence for,
and **why that mapping is defensible to an auditor**. It also explains what each
control code (`A.8.32`, `CC8.1`, …) actually means in plain language, and how to
add a new framework.

It is the human-readable companion to the machine-readable mappings in
[`migrations/`](../migrations). The two must agree — see
[Keeping this document in sync](#keeping-this-document-in-sync).

> **Scope of the claim.** gh-attest produces *evidence*, not a compliance
> verdict. A "positive" row means a GitHub setting is in a state that supports a
> control; it does not mean the control is satisfied — that judgment belongs to
> the organization and its auditor. This document explains why each signal is
> *relevant* to a control, and is honest about where a mapping is a strong fit
> versus a defensible-but-debatable one.

---

## Contents

- [How mapping works mechanically](#how-mapping-works-mechanically)
- [The frameworks in one paragraph each](#the-frameworks-in-one-paragraph-each)
- [The signals and their mappings](#the-signals-and-their-mappings)
  - [Branch protection & repository rulesets](#1-branch-protection--repository-rulesets)
  - [Dependabot](#2-dependabot)
  - [Code scanning](#3-code-scanning)
  - [Secret scanning](#4-secret-scanning)
  - [Membership changes (webhook trail)](#5-membership-changes-webhook-trail)
  - [Membership & team inventory (polled)](#6-membership--team-inventory-polled)
  - [Repository inventory](#7-repository-inventory)
- [Complete mapping reference](#complete-mapping-reference)
- [Adding a new framework](#adding-a-new-framework)
- [Keeping this document in sync](#keeping-this-document-in-sync)
- [Sources](#sources)

---

## How mapping works mechanically

Understanding the evidence output requires understanding four rules in the
mapping engine. All four live in [`control_mappings`](../migrations/0002_control_mappings.sql)
and [`buildEvidenceRows`](../src/exporter.ts).

**1. A snapshot is a `(resource, status)` pair about a `subject`; a mapping is a
row that attaches a control to a `(resource, status)`.** The poller and webhook
handler both normalize GitHub events into a small vocabulary — `resource`
(e.g. `branch_protection`, `dependabot_alert`) and `status` (e.g. `enabled`,
`open`, `fixed`) — plus a `subject` identifying which entity within the repo or
org the fact is about (an alert number, a member login, a team slug). See
[`extractFact`](../src/webhook.ts) and [`poller.ts`](../src/poller.ts). Mapping
happens as a **join at export time**, never at ingest, so a mapping can be
corrected without re-ingesting history.

**2. `status = NULL` in a mapping matches *any* status for that resource.** The
join condition is `cm.status IS NULL OR cm.status = l.status`. This is used for
trail/inventory resources (`team`, `repository`, `org_member`, `team_member`)
where every state is the same kind of informational fact.

**3. One snapshot can emit multiple evidence rows.** A single secret-scanning
alert with `status = 'open'` matches the `open` mapping under **each** of
CC6.6, CC6.1 (SOC 2) and A.5.17 (ISO). This is intentional: the same fact is
legitimate evidence for more than one control expectation, and attesting all of
them lets the export serve whichever control the organization's narrative uses.
This behavior is called out per-signal below wherever it applies.

**4. `posture` is the auditor-facing verdict on a row**, one of:

| Posture | Meaning | Example |
| --- | --- | --- |
| `positive` | State supports the control | Branch protection enabled |
| `negative` | State is a gap against the control | Branch protection disabled; open secret |
| `informational` | Neither pass nor fail — an audit-trail / inventory fact | A member was added; a finding was dismissed by a user |

Two more rules affect *which* snapshots become evidence at all:

- **Unmapped states produce no evidence, in either direction.** A
  `branch_protection` status of `unavailable` (GitHub returned 403 — the feature
  isn't on the repo's plan; see [`fetchBranchProtection`](../src/poller.ts)) has
  no mapping row, so it never counts as a pass *or* a fail. The same applies to
  the `disabled`/`unavailable` states of the detection-tooling resources
  (`dependabot`, `code_scanning`, `secret_scanning`), to the trail-only
  resources `branch_protection_rule_event` and `repository_ruleset_event`
  (rule-scoped webhook events that can't be attributed to the default branch —
  the poll is authoritative for state), and to raw `push` events.
- **"Latest row wins" per `(repo, subject, resource)`** gives point-in-time
  current posture from an append-only table. Because `subject` carries the
  alert number / login / slug, this operates **per entity**: one alert being
  fixed does not mask another alert that is still open in the same repo. Access
  facts are further special-cased so a member who lost access stops being
  attested — only the most recent poll batch counts. See the CTE in
  [`buildEvidenceRows`](../src/exporter.ts).

---

## The frameworks in one paragraph each

**SOC 2** is an attestation report defined by the AICPA's *Trust Services
Criteria* (TSC). The criteria we map to are all in the **Common Criteria (CC)**
series, which every SOC 2 report shares regardless of which trust categories are
in scope. A code like `CC8.1` reads as *Common Criteria, category 8 (Change
Management), criterion 1*. The CC categories used here: **CC6** — logical &
physical access; **CC7** — system operations (detection & monitoring); **CC8** —
change management.

**ISO/IEC 27001:2022** is a certifiable ISMS standard. Its **Annex A** lists 93
controls grouped into four themes: **A.5** organizational (37), **A.6** people
(8), **A.7** physical (14), **A.8** technological (34). A code like `A.8.32`
reads as *Annex A, theme 8 (Technological), control 32*. Note this is the
**2022** numbering — the 2013 edition used different numbers, so a mapping must
state which edition it targets.

---

## The signals and their mappings

Each section below states: what GitHub thing we read and how, the `(resource,
status)` vocabulary we normalize it to, the control(s) we map it to with a
plain-language explanation, the evidentiary argument, and an honest fit
assessment.

### 1. Branch protection & repository rulesets

**What we collect.** For each repo's **default branch**, whether merge controls
are in force. The hourly poll is authoritative: the branch-protection API for
classic protection, and the `rules/branches/{default-branch}` API for rulesets —
which aggregates the rules from every *active* ruleset (repo- and org-level)
that actually applies to that branch, so evaluate-mode (monitor-only) rulesets
and rulesets targeting other branches correctly count as **not** enabled.
Normalized to `resource ∈ {branch_protection, repository_ruleset}`, `status ∈
{enabled, disabled}`.

Webhooks supplement the poll only where they are unambiguous: a
`branch_protection_rule` event whose rule pattern is exactly the default branch
updates state immediately. Any other rule event — and *every*
`repository_ruleset` event, since one ruleset's deletion says nothing about
whether other rulesets still cover the branch — is recorded as an unmapped
trail event (`branch_protection_rule_event`, `repository_ruleset_event`) and
the next poll settles the state. See [`extractFact`](../src/webhook.ts).

**Maps to:**

| Framework | Control | Title / plain meaning |
| --- | --- | --- |
| SOC 2 | **CC8.1** | *Change management.* Changes to software/infrastructure must go through an authorized, controlled process — designed, tested, approved, and implemented — and unauthorized changes must be prevented. |
| ISO 27001 | **A.8.32** | *Change management.* Changes to information systems must follow formal change-management procedures to prevent unauthorized or destabilizing changes. |

**Why this holds.** Branch protection / rulesets are the technical enforcement of
change control in a Git workflow. Enabled → **positive**; disabled →
**negative** ("direct pushes possible" is a concrete change-control gap).

**Fit assessment: strong, with the scope stated in the evidence itself.** Both
frameworks name "change management" explicitly, and branch protection is the
canonical GitHub-native implementation of it. What the evidence attests is that
a change-control gate **exists on the default branch** — it does not verify that
the *specific* rules (required reviewers, status checks, …) match the
organization's policy, and the exported rationale says so explicitly ("rule
contents not verified") rather than claiming review is required.

### 2. Dependabot

**What we collect.** Two distinct facts:

- **Tooling state** (`resource = dependabot`, `status ∈ {enabled, disabled,
  unavailable}`) — the hourly poll checks whether Dependabot alerts are enabled
  on each repo (the alert-list API answering at all is the signal; see
  [`pollRepoAlerts`](../src/poller.ts)). Only `enabled` is mapped; a disabled or
  unavailable scanner is recorded but deliberately produces no evidence either
  way, matching the branch-protection `unavailable` precedent.
- **Findings** (`resource = dependabot_alert`, `status ∈ {open, fixed,
  dismissed, auto_dismissed}`, `subject` = alert number) — from
  `dependabot_alert` webhooks, plus the same hourly poll re-recording every
  *open* alert. The poll matters twice: alerts already open before the App was
  installed never sent a webhook, and an open alert with no events for the
  whole retention window would otherwise age out of evidence.

**Maps to:**

| Framework | Control | When | Posture |
| --- | --- | --- | --- |
| SOC 2 | **CC7.1** | tooling `enabled` | positive — detection tooling is on |
| SOC 2 | **CC7.1** | `open` | negative — unremediated known vulnerability |
| SOC 2 | **CC7.1** | `fixed` / `auto_dismissed` | positive — remediated (machine-verified) |
| SOC 2 | **CC7.1** | `dismissed` | informational — human risk-acceptance, justification subject to review |
| ISO 27001 | **A.8.8** | tooling `enabled` | positive — vulnerability management active |
| ISO 27001 | **A.8.8** | `open` | negative — unremediated known vulnerability |
| ISO 27001 | **A.8.8** | `fixed` / `auto_dismissed` | positive — remediated (machine-verified) |
| ISO 27001 | **A.8.8** | `dismissed` | informational — human risk-acceptance, justification subject to review |

**Control meanings.**
- **CC7.1** — *Detection & monitoring.* The entity uses detection procedures to
  identify configuration changes that introduce new vulnerabilities, and
  susceptibilities to *newly discovered* vulnerabilities. Dependabot is a
  textbook example: it continuously matches your dependency tree against newly
  published CVEs.
- **A.8.8** — *Management of technical vulnerabilities.* Information about
  technical vulnerabilities must be obtained, exposure evaluated, and
  appropriate measures taken — one control spanning the whole lifecycle.

**Why this holds.** The tooling-`enabled` fact proves the detection capability
required by CC7.1/A.8.8 exists and is on *right now* — it comes from the
feature's own state, not (as in earlier versions) from inference off the latest
alert event, which kept attesting after a scanner was switched off and never
fired for a clean repo. Each individual alert's lifecycle is then finding-level
evidence under the same controls: an open alert is an unresolved known
vulnerability; a `fixed` (patched) or `auto_dismissed` (e.g. dependency
removed) alert is a machine-verified closure; a `dismissed` alert is a **human
decision** — it may be sound risk acceptance or may be rubber-stamping, and the
justification is exactly what an auditor samples, so it is recorded as
informational rather than claimed as remediation.

**Fit assessment: strong on both frameworks.** The whole SOC 2 lifecycle sits
under CC7.1, whose "susceptibility to newly discovered vulnerabilities"
language covers known-CVE management directly. (Earlier versions split
open/remediated state to CC7.2; CC7.2's anomaly-monitoring text is about
runtime security events, which made it the weakest link in the system — that
split has been removed.) A.8.8 is purpose-built for this signal and absorbs the
whole lifecycle.

### 3. Code scanning

**What we collect.** Same two-fact shape as Dependabot: tooling state
(`resource = code_scanning`, from the hourly poll; only `enabled` mapped) and
findings (`resource = code_scanning_alert`, `status ∈ {open, fixed,
dismissed}`, `subject` = alert number) from `code_scanning_alert` webhooks plus
the hourly re-record of open alerts. Findings are SAST results from CodeQL or a
third-party analyzer.

**Maps to:**

| Framework | Control | When | Posture |
| --- | --- | --- | --- |
| ISO 27001 | **A.8.29** | tooling `enabled` | positive — security testing in development is on |
| ISO 27001 | **A.8.28** | `open` | negative — unremediated finding |
| ISO 27001 | **A.8.28** | `fixed` | positive — remediated |
| ISO 27001 | **A.8.28** | `dismissed` | informational — human risk-acceptance, justification subject to review |
| SOC 2 | **CC7.1** | tooling `enabled` | positive — detection tooling is on |
| SOC 2 | **CC7.1** | `open` | negative — unremediated finding |
| SOC 2 | **CC7.1** | `fixed` | positive — remediated |
| SOC 2 | **CC7.1** | `dismissed` | informational — human risk-acceptance, justification subject to review |

**Control meanings.**
- **A.8.29** — *Security testing in development and acceptance.* Security testing
  processes must be defined and run within the development lifecycle. The
  existence of code scanning *is* that testing process.
- **A.8.28** — *Secure coding.* Secure coding principles must be applied during
  development. An open finding is evidence of a secure-coding gap in the source;
  a remediated one is evidence the gap was closed.
- **CC7.1** — *Detection & monitoring.* (Same control as Dependabot's SOC 2
  mapping.)

**Why this holds.** On the **ISO** side this splits cleanly across two controls
that map to two facts: *"a testing process exists"* (A.8.29, from tooling
state) versus *"the code itself is / isn't secure"* (A.8.28, from each
finding's state). On the **SOC 2** side the full lifecycle mirrors Dependabot
under CC7.1 — the finding-level rows were previously deferred pending the
CC7.1-vs-CC7.2 decision, which is now settled in CC7.1's favor.

**Fit assessment: strong on both.** The A.8.29-vs-A.8.28 split follows the
controls' own having-a-process vs. code-quality distinction, and the SOC 2 side
is now symmetric with Dependabot rather than intentionally partial.

### 4. Secret scanning

**What we collect.** Tooling state (`resource = secret_scanning`, from the
hourly poll; only `enabled` mapped) and findings (`resource =
secret_scanning_alert`, `status ∈ {open, resolved}`, `subject` = alert number)
from `secret_scanning_alert` webhooks plus the hourly re-record of open alerts.
One payload quirk matters: unlike the other two alert payloads, the
secret-scanning webhook alert carries **no `state` field** — ingest derives
open/resolved from `alert.resolution`, which is set iff the alert is resolved
(see [`extractFact`](../src/webhook.ts)).

**Maps to:**

| Framework | Control | When | Posture |
| --- | --- | --- | --- |
| SOC 2 | **CC6.6** | tooling `enabled` | positive — leaked-credential detection is on |
| SOC 2 | **CC6.6** | `open` | negative — live credential exposure |
| SOC 2 | **CC6.6** | `resolved` | informational — resolution reason subject to review |
| SOC 2 | **CC6.1** | tooling `enabled` | positive — logical-access credential protection is on |
| SOC 2 | **CC6.1** | `open` | negative — exposed credential undermines logical access controls |
| SOC 2 | **CC6.1** | `resolved` | informational — resolution reason subject to review |
| ISO 27001 | **A.5.17** | tooling `enabled` | positive — authentication-information protection is on |
| ISO 27001 | **A.5.17** | `open` | negative — exposed authentication information |
| ISO 27001 | **A.5.17** | `resolved` | informational — resolution reason subject to review |

**Control meanings.**
- **CC6.6** — *Protection against external threats.* The entity implements
  logical-access security measures to protect against threats from **outside**
  its system boundaries.
- **CC6.1** — *Logical access controls over protected assets.* The entity
  implements logical-access security software, infrastructure, and architectures
  over protected information assets to protect them from security events. A
  credential *is* such a control; its exposure is a failure of that control.
- **A.5.17** — *Authentication information.* Allocation and management of
  authentication information (passwords, keys, tokens) must be controlled. A
  credential committed to a repository is exposed authentication information —
  exactly what this control governs.

**Why this holds.** A committed credential is relevant to all three controls at
once. For **CC6.6**, it is a direct path for an *external* attacker to cross the
system boundary. For **CC6.1**, the credential is itself one of the
logical-access keys the control is meant to safeguard. For **A.5.17**, the
credential is authentication information whose confidentiality the control
requires. Scanning enabled → **positive**; open alert → **negative**. A
`resolved` alert is **informational**, not positive: GitHub's resolution
reasons include `wont_fix`, so "resolved" may mean the credential was revoked
*or* that someone decided to leave it — the recorded reason is what the
reviewer must check.

**Fit assessment: all three defensible.** CC6.6 is the external-threat framing,
CC6.1 the logical-access framing, A.5.17 the ISO authentication-information
framing. Mapping to all three means the export satisfies whichever control the
organization's narrative uses — at the cost of row multiplicity: one open
secret emits a negative under each of the three. A further SOC 2 framing,
**CC6.7** (restricting the transmission/movement of information), also touches
this and could be added if an auditor prefers it.

### 5. Membership changes (webhook trail)

**What we collect.** The *change* events for access administration, each with a
`subject` so the trail keeps one latest row per person/team rather than one per
repo:

- `member` webhook → `resource = member_access`, subject = the collaborator's
  login. **Scope note: this event covers repository collaborators**, not org
  members.
- `organization` webhook → `resource = org_membership`, subject = the member's
  login (or the invitee's login/email). This is where org-level joins, removals
  and invitations arrive.
- `team` webhook → `resource = team`, subject = the team slug.

**Maps to:**

| Framework | Control | When | Posture |
| --- | --- | --- | --- |
| SOC 2 | **CC6.2** | `member_access` `added`, `org_membership` `member_added` / `member_invited` | informational — access grant / invitation, logged for review |
| SOC 2 | **CC6.3** | `member_access` `removed` / `edited`, `org_membership` `member_removed` | informational — modification / deprovisioning recorded |
| ISO 27001 | **A.5.18** | all of the above | informational — access-rights change, audit trail |
| ISO 27001 | **A.5.18** | `team` (any) | informational — access-rights change, audit trail |

**Control meanings.**
- **CC6.2** — *Registration & authorization of new users.* Before credentials are
  issued, new users are registered and authorized; credentials are removed when
  access is no longer authorized. A member being *added* or *invited* is the
  provisioning event this criterion governs.
- **CC6.3** — *Authorize / modify / remove access.* Access is authorized,
  modified, or removed based on roles, least privilege, and segregation of
  duties. Removal and role change are the modify/remove events here.
- **A.5.18** — *Access rights.* Access rights are provisioned, reviewed,
  modified, and removed per the access-control policy.

**Why this holds & posture logic.** These are the *audit trail* of access
administration — evidence that grants/changes are captured, which is what an
auditor samples. **All rows are informational**, removals included: the event
proves a removal happened and when, but not that it was *timely* relative to an
offboarding trigger the system cannot see — so the rationale says
"deprovisioning recorded; timeliness subject to review" rather than claiming
timeliness as a positive. (Earlier versions claimed "timely access removal";
that was rounding up.)

**Fit assessment: strong on the CC6.2/CC6.3 split** (it follows the criteria's
own provisioning-vs-modification language), and honest about scope now that
repo-collaborator and org-member events are separate resources with separate
rationales.

### 6. Membership & team inventory (polled)

**What we collect.** The hourly poll writes the **full current set** of org
members and team members (see [`pollOrgAccess`](../src/poller.ts)), distinct from
the webhook change-trail above. `resource ∈ {org_member, team_member}`,
`status` = the role. Each poll shares one `captured_at` so a batch is a coherent
point-in-time snapshot — this is what powers the [access-review diff](../src/access-review.ts).

**Maps to:**

| Framework | Control | Resource | Posture |
| --- | --- | --- | --- |
| SOC 2 | **CC6.2** | `org_member` | informational — org access inventory, subject to periodic review |
| SOC 2 | **CC6.3** | `team_member` | informational — team-based access inventory |
| ISO 27001 | **A.5.18** | `org_member`, `team_member` | informational — access-rights inventory |

**Why this holds.** A point-in-time roster of who has access is the raw material
of a periodic access review — the recurring auditor ask that CC6.2/CC6.3 and
A.5.18 all expect. Org membership maps to CC6.2 (who is registered/authorized in
the org); team membership maps to CC6.3 (role-/least-privilege-based access).
A.5.18 explicitly names "reviewed" among its verbs, so both feed it. All rows
are **informational**: an inventory does not pass or fail, it *enables* the
review.

**Fit assessment: strong, with one nuance.** The org→CC6.2 / team→CC6.3 split is
reasonable but not the only defensible cut — the *review* of org membership is
arguably as much CC6.3 (appropriateness of access) as CC6.2 (registration). Since
these are informational inventory rows feeding a review, the exact CC6.2/CC6.3
attribution is low-stakes; A.5.18 is unambiguous. Note the two resource families
(`member_access`/`org_membership`/`team` webhook trail vs.
`org_member`/`team_member` polled inventory) are deliberately separate resource
names so the change-trail and the current-state inventory don't collide.

### 7. Repository inventory

**What we collect.** `repository` webhook events — repos created/deleted/renamed
and visibility changes within the installation. `resource = repository`.

**Maps to:**

| Framework | Control | When | Posture |
| --- | --- | --- | --- |
| ISO 27001 | **A.5.9** | any action | informational — asset inventory trail |
| SOC 2 | **CC6.1** | `publicized` | informational — repo made public, flagged for review |

**Control meaning.**
- **A.5.9** — *Inventory of information and other associated assets.* A complete,
  maintained inventory of information assets and their owners must exist.

**Why this holds.** Repositories are information assets. The trail of repo
create/delete/rename events is evidence that the asset inventory is maintained as
it changes — exactly A.5.9's requirement. One action gets an extra row: a repo
being **publicized** is a visibility change with direct confidentiality impact,
so it is additionally surfaced under CC6.1 rather than left as a generic
inventory tick. Both rows are **informational** — whether going public was
intended is a judgment the reviewer makes.

**Fit assessment: strong for what it claims.** The honest caveat is completeness:
this is a *change trail*, so it evidences that inventory changes are captured, not
that a full, owner-annotated asset register exists. If a future need is to attest
a complete inventory, the polled repo list (already fetched in
[`listInstallationRepos`](../src/poller.ts)) would be the better source than the
webhook trail.

---

## Complete mapping reference

This table is the authoritative human-readable copy of every row in
[`control_mappings`](../migrations/0002_control_mappings.sql) after all
migrations (0002 seeds most; 0003 replaces branch-protection/ruleset with the
enabled/disabled vocabulary; 0005 adds the polled access inventory; 0006 adds
the secret-scanning CC6.1 rows; 0007 closes cross-framework coverage gaps; 0008
applies the mapping-review fixes — per-entity subjects, polled tooling state,
the CC7.1 consolidation, and informational postures for human dismissals).
**A "·" in Status means the mapping's `status` is `NULL` — it matches any
status.** The Rationale column is the exact auditor-facing string in the
database, and is CI-checked against it.

| Resource | Status | Framework | Control | Posture | Rationale |
| --- | --- | --- | --- | --- | --- |
| `branch_protection` | `enabled` | SOC 2 | CC8.1 | positive | Change management — a protection rule is enforced on the default branch (rule contents not verified) |
| `branch_protection` | `disabled` | SOC 2 | CC8.1 | negative | Change-control gap — no protection on the default branch; direct pushes possible |
| `branch_protection` | `enabled` | ISO 27001 | A.8.32 | positive | Change management — a protection rule is enforced on the default branch (rule contents not verified) |
| `branch_protection` | `disabled` | ISO 27001 | A.8.32 | negative | Change-control gap — no protection on the default branch; direct pushes possible |
| `repository_ruleset` | `enabled` | SOC 2 | CC8.1 | positive | Change management — an active ruleset covers the default branch (rule contents not verified) |
| `repository_ruleset` | `disabled` | SOC 2 | CC8.1 | negative | Change-control gap — no active ruleset covers the default branch |
| `repository_ruleset` | `enabled` | ISO 27001 | A.8.32 | positive | Change management — an active ruleset covers the default branch (rule contents not verified) |
| `repository_ruleset` | `disabled` | ISO 27001 | A.8.32 | negative | Change-control gap — no active ruleset covers the default branch |
| `dependabot` | `enabled` | SOC 2 | CC7.1 | positive | Detection tooling — Dependabot alerts are enabled on the repository |
| `dependabot` | `enabled` | ISO 27001 | A.8.8 | positive | Technical vulnerability management — Dependabot alerts are enabled on the repository |
| `code_scanning` | `enabled` | SOC 2 | CC7.1 | positive | Detection tooling — code scanning is enabled on the repository |
| `code_scanning` | `enabled` | ISO 27001 | A.8.29 | positive | Security testing in development — code scanning is enabled on the repository |
| `secret_scanning` | `enabled` | SOC 2 | CC6.6 | positive | Leaked-credential detection — secret scanning is enabled on the repository |
| `secret_scanning` | `enabled` | SOC 2 | CC6.1 | positive | Logical-access credential protection — secret scanning is enabled on the repository |
| `secret_scanning` | `enabled` | ISO 27001 | A.5.17 | positive | Authentication-information protection — secret scanning is enabled on the repository |
| `dependabot_alert` | `open` | SOC 2 | CC7.1 | negative | Unremediated known vulnerability |
| `dependabot_alert` | `fixed` | SOC 2 | CC7.1 | positive | Vulnerability remediated |
| `dependabot_alert` | `dismissed` | SOC 2 | CC7.1 | informational | Dismissed by a user — risk-acceptance justification subject to review |
| `dependabot_alert` | `auto_dismissed` | SOC 2 | CC7.1 | positive | Auto-dismissed by GitHub (e.g. dependency removed) |
| `dependabot_alert` | `open` | ISO 27001 | A.8.8 | negative | Unremediated known technical vulnerability |
| `dependabot_alert` | `fixed` | ISO 27001 | A.8.8 | positive | Vulnerability remediated |
| `dependabot_alert` | `dismissed` | ISO 27001 | A.8.8 | informational | Dismissed by a user — risk-acceptance justification subject to review |
| `dependabot_alert` | `auto_dismissed` | ISO 27001 | A.8.8 | positive | Auto-dismissed by GitHub (e.g. dependency removed) |
| `code_scanning_alert` | `open` | SOC 2 | CC7.1 | negative | Unremediated static-analysis finding |
| `code_scanning_alert` | `fixed` | SOC 2 | CC7.1 | positive | Finding remediated |
| `code_scanning_alert` | `dismissed` | SOC 2 | CC7.1 | informational | Dismissed by a user — risk-acceptance justification subject to review |
| `code_scanning_alert` | `open` | ISO 27001 | A.8.28 | negative | Unremediated static-analysis finding |
| `code_scanning_alert` | `fixed` | ISO 27001 | A.8.28 | positive | Finding remediated |
| `code_scanning_alert` | `dismissed` | ISO 27001 | A.8.28 | informational | Dismissed by a user — risk-acceptance justification subject to review |
| `secret_scanning_alert` | `open` | SOC 2 | CC6.6 | negative | Live credential exposure |
| `secret_scanning_alert` | `resolved` | SOC 2 | CC6.6 | informational | Resolution recorded — reason (revoked vs. won't-fix) subject to review |
| `secret_scanning_alert` | `open` | SOC 2 | CC6.1 | negative | Exposed credential undermines logical access controls |
| `secret_scanning_alert` | `resolved` | SOC 2 | CC6.1 | informational | Resolution recorded — reason (revoked vs. won't-fix) subject to review |
| `secret_scanning_alert` | `open` | ISO 27001 | A.5.17 | negative | Exposed authentication information |
| `secret_scanning_alert` | `resolved` | ISO 27001 | A.5.17 | informational | Resolution recorded — reason (revoked vs. won't-fix) subject to review |
| `member_access` | `added` | SOC 2 | CC6.2 | informational | Repository collaborator added — access grant logged for review |
| `member_access` | `removed` | SOC 2 | CC6.3 | informational | Repository collaborator removed — deprovisioning recorded; timeliness subject to review |
| `member_access` | `edited` | SOC 2 | CC6.3 | informational | Repository collaborator permission changed — logged for review |
| `member_access` | `added` | ISO 27001 | A.5.18 | informational | Repository collaborator added — access-rights change, audit trail |
| `member_access` | `removed` | ISO 27001 | A.5.18 | informational | Repository collaborator removed — access-rights change, audit trail |
| `member_access` | `edited` | ISO 27001 | A.5.18 | informational | Repository collaborator permission changed — access-rights change, audit trail |
| `org_membership` | `member_added` | SOC 2 | CC6.2 | informational | Organization member added — access grant logged for review |
| `org_membership` | `member_removed` | SOC 2 | CC6.3 | informational | Organization member removed — deprovisioning recorded; timeliness subject to review |
| `org_membership` | `member_invited` | SOC 2 | CC6.2 | informational | Organization invitation issued — logged for review |
| `org_membership` | `member_added` | ISO 27001 | A.5.18 | informational | Organization member added — access-rights change, audit trail |
| `org_membership` | `member_removed` | ISO 27001 | A.5.18 | informational | Organization member removed — access-rights change, audit trail |
| `org_membership` | `member_invited` | ISO 27001 | A.5.18 | informational | Organization invitation issued — access-rights change, audit trail |
| `team` | · | ISO 27001 | A.5.18 | informational | Access-rights change, audit trail |
| `repository` | · | ISO 27001 | A.5.9 | informational | Asset inventory trail |
| `repository` | `publicized` | SOC 2 | CC6.1 | informational | Repository made public — visibility change affecting asset confidentiality, flagged for review |
| `org_member` | · | SOC 2 | CC6.2 | informational | Organization access inventory — subject to periodic access review |
| `org_member` | · | ISO 27001 | A.5.18 | informational | Access rights inventory |
| `team_member` | · | SOC 2 | CC6.3 | informational | Team-based access inventory |
| `team_member` | · | ISO 27001 | A.5.18 | informational | Access rights inventory |

### Control glossary

| Code | Title (plain language) |
| --- | --- |
| **CC6.1** | Implement logical-access controls over protected information assets |
| **CC6.2** | Register & authorize new users before granting access; remove credentials when access ends |
| **CC6.3** | Authorize, modify, and remove access by role, with least privilege and segregation of duties |
| **CC6.6** | Protect against threats originating outside the system boundary |
| **CC7.1** | Detect configuration changes that introduce vulnerabilities, and susceptibility to newly discovered ones |
| **CC8.1** | Put changes through an authorized, controlled process; block unauthorized changes |
| **A.5.9** | Maintain an inventory of information and associated assets, with owners |
| **A.5.17** | Control the allocation and management of authentication information (passwords, keys, tokens) |
| **A.5.18** | Provision, review, modify, and remove access rights per policy |
| **A.8.8** | Obtain, evaluate, and act on information about technical vulnerabilities |
| **A.8.28** | Apply secure coding principles throughout development |
| **A.8.29** | Run security testing within the development and acceptance lifecycle |
| **A.8.32** | Subject system changes to formal change-management procedures |

---

## Adding a new framework

The join engine is framework-agnostic — a new framework is **data, not code**.
Adding one (e.g. NIST CSF 2.0, PCI DSS 4.0, CIS Controls) is a new migration that
inserts `control_mappings` rows with a new `framework` value, plus a section in
this document. No changes to the poller, exporter query, or webhook handler are
needed. The only code touchpoints are the `Framework` type and the
`normalizeFramework` allow-list — see [What the code needs](#what-the-code-needs).

### Methodology — how to map a signal to a control accurately

Do this per `(resource, status)` you want to attest, and write the reasoning into
this document as you go. The goal the user cares about is **100% defensibility**,
so bias toward under-claiming.

1. **Start from the signal, not the control.** Name exactly what the GitHub state
   proves ("a merge gate exists on the default branch"), in one sentence, without
   reference to any framework.
2. **Find the control whose *intent* that sentence satisfies** — read the actual
   control text, not a blog summary. If the signal only partially satisfies the
   control, say so in the fit assessment; do not round up.
3. **Prefer one strong control over several weak ones.** A single defensible
   mapping is worth more to an auditor than three tenuous ones. Tenuous mappings
   erode trust in the whole evidence pack.
4. **Assign posture from the control's expectation, not the signal's sentiment:**
   - `positive` — the state is what the control wants, and the platform verified
     it (not merely a human clicking "dismiss").
   - `negative` — the state is a concrete gap the control would flag.
   - `informational` — the state is audit-trail/inventory that feeds a review but
     is not itself pass/fail. Human decisions (dismissals, resolutions with a
     reason) belong here. When in doubt, use `informational`.
5. **Separate tooling state from findings.** If the signal is a scanner/alert
   stream, attest "the control's *tooling* is on" from the feature's own state
   (polled), not from the existence of alerts — and attest each finding's
   lifecycle per alert, with the alert number as `subject` so findings don't
   mask each other.
6. **Pin the edition.** State which version of the framework you mapped (e.g.
   "PCI DSS v4.0.1", "NIST CSF 2.0") — control numbers move between editions.
7. **Write the rationale** in the `rationale` column *and* copy it into the
   reference table here verbatim — it is CI-checked. The `rationale` is what an
   auditor reads in the export; make it a complete thought that claims no more
   than the signal proves.

### What the code needs

Three touchpoints, all small:

- **`src/exporter.ts`** — add the new value to the `Framework` type
  (`"soc2" | "iso27001" | ...`).
- **`src/index.ts`** — add it to `normalizeFramework` so `?framework=` and the
  export form accept it.
- **`src/dashboard.ts`** — add it to the framework selector if it should be
  user-selectable.

### Checklist for a new framework

- [ ] New migration `migrations/000N_<framework>_mappings.sql` inserting
      `control_mappings` rows with the new `framework` value.
- [ ] Every mapping uses a `resource`/`status` the pipeline already produces (see
      [`extractFact`](../src/webhook.ts) and [`poller.ts`](../src/poller.ts)). If
      you need a signal that isn't collected yet, that is a collection change
      first — a mapping to a resource that is never written produces no evidence.
- [ ] `rationale` on each row is a complete, auditor-readable sentence.
- [ ] A new `### <Framework>` subsection here, or per-signal rows added to the
      existing sections, plus reference-table and glossary entries.
- [ ] The framework edition/version is stated.
- [ ] `Framework` type + `normalizeFramework` updated.
- [ ] `npm run typecheck` passes; `npm run db:migrate:local` applies cleanly.

### Worked micro-example

To map branch protection to **NIST CSF 2.0**, whose `PR.PS-06` covers a secure
software development lifecycle:

```sql
INSERT INTO control_mappings (resource, status, framework, control_id, posture, rationale) VALUES
  ('branch_protection', 'enabled',  'nistcsf', 'PR.PS-06', 'positive', 'SDLC change control — review required before merge to the default branch'),
  ('branch_protection', 'disabled', 'nistcsf', 'PR.PS-06', 'negative', 'SDLC change-control gap — direct pushes to the default branch possible');
```

Then add `"nistcsf"` to the `Framework` type and `normalizeFramework`, and add a
`### NIST CSF 2.0` subsection here documenting the reasoning and fit.

---

## Keeping this document in sync

The mappings live in two places that must agree: the SQL seed rows in
`migrations/` (the source of truth the engine reads) and the
[reference table](#complete-mapping-reference) and per-signal sections here.
**When you change a mapping, change both in the same PR** — the same discipline
the README applies to retention periods. A mapping row with no rationale here, or
a row here with no SQL, is a bug.

This is enforced. [`scripts/check-mappings.mjs`](../scripts/check-mappings.mjs)
applies every migration to an in-memory SQLite database, reads back
`control_mappings`, and diffs the `(resource, status, framework, control_id,
posture, rationale)` tuples against the rows parsed out of the
[reference table](#complete-mapping-reference) above. It fails with a row-level
diff if the two drift. Run it with:

```sh
npm run test:mappings
```

It has no dependencies (Node's built-in `node:sqlite`) and is a good CI gate. It
checks the **reference table** specifically — the per-signal tables and glossary
are prose and are not parsed, so keep those consistent by hand.

---

## Sources

Control *numbers and titles* are cited from the published standards; exact
criterion text is paraphrased (the standards themselves are copyrighted).

- ISO/IEC 27001:2022, Annex A — control titles confirmed via
  [ISMS.online, "ISO 27001:2022 Annex A Explained"](https://www.isms.online/iso-27001/annex-a-2022/).
- AICPA *Trust Services Criteria* (TSP Section 100, 2017 criteria with 2022
  revised points of focus) — CC category scope confirmed via
  [Linford & Co., "Trust Services Criteria"](https://linfordco.com/blog/trust-services-critieria-principles-soc-2/)
  and [Secureframe, "SOC 2 Common Criteria"](https://secureframe.com/hub/soc-2/common-criteria).
- The authoritative text for both is the source standard: purchase ISO/IEC
  27001:2022 from ISO, and the AICPA Trust Services Criteria from the AICPA.
  Verify any mapping against those before an audit.
