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
  - [Dependabot alerts](#2-dependabot-alerts)
  - [Code scanning alerts](#3-code-scanning-alerts)
  - [Secret scanning alerts](#4-secret-scanning-alerts)
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

**1. A snapshot is a `(resource, status)` pair; a mapping is a row that attaches
a control to one.** The poller and webhook handler both normalize GitHub events
into a small vocabulary — `resource` (e.g. `branch_protection`, `dependabot_alert`)
and `status` (e.g. `enabled`, `open`, `fixed`). See [`extractFact`](../src/webhook.ts)
and [`poller.ts`](../src/poller.ts). Mapping happens as a **join at export time**,
never at ingest, so a mapping can be corrected without re-ingesting history.

**2. `status = NULL` in a mapping matches *any* status for that resource.** The
join condition is `cm.status IS NULL OR cm.status = l.status`. This is how a
"the tooling exists and is producing signal" fact is expressed independently of
any individual finding's state.

**3. Consequently, one snapshot can emit multiple evidence rows.** A single
Dependabot alert with `status = 'open'` matches *both* the `NULL` mapping
(CC7.1, "detection tooling is active", **positive**) *and* the `'open'` mapping
(CC7.2, "unremediated vulnerability", **negative**). This is intentional: the
existence of the scanner and the existence of an open finding are two different
facts about two different control expectations. This behavior is called out
per-signal below wherever it applies.

**4. `posture` is the auditor-facing verdict on a row**, one of:

| Posture | Meaning | Example |
| --- | --- | --- |
| `positive` | State supports the control | Branch protection enabled |
| `negative` | State is a gap against the control | Branch protection disabled; open secret |
| `informational` | Neither pass nor fail — an audit-trail / inventory fact | A member was added; a repo exists |

Two more rules affect *which* snapshots become evidence at all:

- **Unmapped states produce no evidence, in either direction.** A
  `branch_protection` status of `unavailable` (GitHub returned 403 — the feature
  isn't on the repo's plan; see [`fetchBranchProtection`](../src/poller.ts)) has
  no mapping row, so it never counts as a pass *or* a fail. Same for raw
  `push` events.
- **"Latest row wins" per `(repo, subject, resource)`** gives point-in-time
  current posture from an append-only table. Access facts are special-cased so a
  member who lost access stops being attested — only the most recent poll batch
  counts. See the CTE in [`buildEvidenceRows`](../src/exporter.ts).

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

**What we collect.** For each repo's default branch, whether merge controls are
in force — via the `branch_protection_rule` and `repository_ruleset` webhooks
(change events) and an hourly poll of the branch-protection and rulesets APIs
(baseline, for protection that predates the install). Normalized to
`resource ∈ {branch_protection, repository_ruleset}`, `status ∈ {enabled,
disabled}`. A ruleset in `evaluate` (monitor-only) mode counts as **not**
enabled because it does not actually block anything — see
[`fetchRulesets`](../src/poller.ts).

**Maps to:**

| Framework | Control | Title / plain meaning |
| --- | --- | --- |
| SOC 2 | **CC8.1** | *Change management.* Changes to software/infrastructure must go through an authorized, controlled process — designed, tested, approved, and implemented — and unauthorized changes must be prevented. |
| ISO 27001 | **A.8.32** | *Change management.* Changes to information systems must follow formal change-management procedures to prevent unauthorized or destabilizing changes. |

**Why this holds.** Branch protection / rulesets are the technical enforcement of
change control in a Git workflow: requiring pull-request review before merge,
blocking direct pushes to the default branch, and requiring status checks to
pass. That is exactly the "controlled process… stops unauthorized changes"
language of both controls. Enabled → **positive**; disabled → **negative**
("direct pushes now possible" is a concrete change-control gap).

**Fit assessment: strong.** This is the least ambiguous mapping in the system —
both frameworks name "change management" explicitly, and branch protection is
the canonical GitHub-native implementation of it. The one nuance an auditor will
probe is *scope*: we check the **default branch** only, and "enabled" does not
verify that the *specific* rules (required reviewers, etc.) match the
organization's policy. The evidence attests that a change-control gate exists,
not that its configuration is sufficient.

### 2. Dependabot alerts

**What we collect.** `dependabot_alert` webhook events — known-vulnerability
alerts against the repo's dependencies. `status` is the alert state: `open`,
`fixed`, `dismissed`, `auto_dismissed`.

**Maps to:**

| Framework | Control | When | Posture |
| --- | --- | --- | --- |
| SOC 2 | **CC7.1** | any alert (`status = NULL`) | positive — "detection tooling is active" |
| SOC 2 | **CC7.2** | `open` | negative — "unremediated known vulnerability" |
| SOC 2 | **CC7.2** | `fixed` / `dismissed` / `auto_dismissed` | positive — "remediated" |
| ISO 27001 | **A.8.8** | any alert (`status = NULL`) | positive — "technical vulnerability management active" |
| ISO 27001 | **A.8.8** | `open` | negative — "unremediated known vulnerability" |
| ISO 27001 | **A.8.8** | `fixed` / `dismissed` / `auto_dismissed` | positive — "remediated" |

**Control meanings.**
- **CC7.1** — *Detection & monitoring.* The entity uses detection procedures to
  identify configuration changes that introduce new vulnerabilities, and
  susceptibilities to *newly discovered* vulnerabilities. Dependabot is a
  textbook example: it continuously matches your dependency tree against newly
  published CVEs.
- **CC7.2** — *Anomaly monitoring.* The entity monitors system components for
  anomalies and analyzes them to determine whether they are security events.
- **A.8.8** — *Management of technical vulnerabilities.* Information about
  technical vulnerabilities must be obtained, exposure evaluated, and
  appropriate measures taken. This is a single control spanning the whole
  vulnerability lifecycle — detect, evaluate, remediate.

**Why this holds.** The *presence* of Dependabot alerts proves the detection
capability required by CC7.1 exists and is running — hence the `NULL` mapping
fires positive on any alert regardless of state. Each *individual* alert's
lifecycle (open vs. remediated) is then evidence for CC7.2: an open alert is an
unresolved condition, a fixed/dismissed one is a closed one. On the **ISO** side
the entire story lands on a *single* control, A.8.8, because A.8.8 explicitly
covers the full lifecycle — so every status maps to A.8.8 (open → negative,
remediated → positive, tooling-active → positive). See
[migration 0007](../migrations/0007_close_coverage_gaps.sql).

**Fit assessment: CC7.1 strong; CC7.2 defensible but the weakest link in the
system.** CC7.2's formal text is about anomalies "indicative of malicious acts,
natural disasters, and errors" — i.e. runtime security events. An unpatched
dependency is a *known vulnerability*, which sits more naturally in CC7.1's
"susceptibility to newly discovered vulnerabilities" language than in CC7.2's
anomaly-detection language. Many auditors keep the **entire** dependency story
(detection *and* remediation tracking) under CC7.1. **Recommendation:** before
you present this to an auditor, decide whether open/remediated Dependabot state
belongs under CC7.1 or CC7.2 in your control narrative, and align the mapping to
that decision. Both are defensible; the current split is a design choice, not a
requirement. The **ISO A.8.8** mapping, by contrast, is a strong, clean fit —
A.8.8 is purpose-built for technical-vulnerability management and absorbs the
whole lifecycle without the CC7.1/CC7.2 ambiguity. It was added in migration 0007
to close a gap: before it, Dependabot produced no evidence at all in an ISO
export.

### 3. Code scanning alerts

**What we collect.** `code_scanning_alert` webhook events — SAST findings from
CodeQL or a third-party analyzer. `status ∈ {open, fixed, dismissed}`.

**Maps to:**

| Framework | Control | When | Posture |
| --- | --- | --- | --- |
| ISO 27001 | **A.8.29** | any alert (`status = NULL`) | positive — "security testing in development is active" |
| ISO 27001 | **A.8.28** | `open` | negative — "unremediated finding" |
| ISO 27001 | **A.8.28** | `fixed` / `dismissed` | positive — "remediated" |
| SOC 2 | **CC7.1** | any alert (`status = NULL`) | positive — "detection tooling is active" |

**Control meanings.**
- **A.8.29** — *Security testing in development and acceptance.* Security testing
  processes must be defined and run within the development lifecycle so
  vulnerabilities are found before production. The existence of code scanning
  *is* that testing process.
- **A.8.28** — *Secure coding.* Secure coding principles must be applied during
  development. An open finding is evidence of a secure-coding gap in the source;
  a remediated one is evidence the gap was closed.
- **CC7.1** — *Detection & monitoring.* (Same control as Dependabot's SOC 2
  mapping.) Code scanning is detection tooling that surfaces vulnerabilities, so
  its presence satisfies the "detection procedures exist and run" expectation.

**Why this holds.** On the **ISO** side this splits cleanly across two controls
that map to two facts: *"a testing process exists"* (A.8.29, from the `NULL`
mapping) versus *"the code itself is/ isn't secure"* (A.8.28, from each finding's
state). On the **SOC 2** side (added in [migration 0007](../migrations/0007_close_coverage_gaps.sql))
only the tooling-active fact is mapped, to CC7.1 — mirroring how Dependabot's
tooling-active fact maps to CC7.1.

**Fit assessment: strong on ISO; SOC 2 intentionally partial.** The
A.8.29-vs-A.8.28 split is clean — one control is about *having* the testing
process, the other about the *code quality* it reveals — and both titles match
the signal directly. The new SOC 2 CC7.1 mapping covers only detection-active,
**not** finding-level state: code-scanning `open`/`fixed` rows are deliberately
*not* routed to CC7.2, because whether the vulnerability lifecycle belongs under
CC7.1 or CC7.2 is still an open decision (see the Dependabot fit assessment). Once
that is settled, finding-level SOC 2 rows for code scanning can be added to match
Dependabot. Until then a SOC 2 export shows code scanning as "detection active"
only — which under-claims rather than over-claims, the safe direction.

### 4. Secret scanning alerts

**What we collect.** `secret_scanning_alert` webhook events — detected
credentials/tokens committed to the repo. `status ∈ {open, resolved}`.

**Maps to:**

| Framework | Control | When | Posture |
| --- | --- | --- | --- |
| SOC 2 | **CC6.6** | any alert (`status = NULL`) | positive — "leaked-credential detection is active" |
| SOC 2 | **CC6.6** | `open` | negative — "live credential exposure" |
| SOC 2 | **CC6.6** | `resolved` | positive — "exposure remediated" |
| SOC 2 | **CC6.1** | any alert (`status = NULL`) | positive — "logical-access credential protection active" |
| SOC 2 | **CC6.1** | `open` | negative — "exposed credential undermines logical access controls" |
| SOC 2 | **CC6.1** | `resolved` | positive — "logical access control restored" |
| ISO 27001 | **A.5.17** | any alert (`status = NULL`) | positive — "authentication-information protection active" |
| ISO 27001 | **A.5.17** | `open` | negative — "exposed authentication information" |
| ISO 27001 | **A.5.17** | `resolved` | positive — "exposure remediated" |

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
system boundary. For **CC6.1**, the credential is itself one of the logical-access
keys the control is meant to safeguard, so a leak is a compromise of the access
controls themselves. For **A.5.17**, the credential is authentication information
whose confidentiality the control requires. In every case: scanning active →
**positive** (a protective measure exists); open alert → **negative** (a live
gap); resolved → **positive** (gap closed). See
[migration 0006](../migrations/0006_secret_scanning_cc6_1.sql) (CC6.1) and
[migration 0007](../migrations/0007_close_coverage_gaps.sql) (A.5.17).

**Fit assessment: all three defensible.** CC6.6 is the external-threat framing,
CC6.1 the logical-access framing, A.5.17 the ISO authentication-information
framing (added in migration 0007 to close a gap — before it, secret scanning
produced no ISO evidence). Mapping to all three means the export satisfies
whichever control the organization's narrative uses. A further SOC 2 framing,
**CC6.7** (restricting the transmission/movement of information), also touches
this and could be added if an auditor prefers it. Note the multiplicity: one
`open` secret now emits **six** rows — a positive ("scanner running") and a
negative ("open exposure") under *each* of CC6.6, CC6.1 (SOC 2 export) and A.5.17
(ISO export). That is intended and reads correctly, but expect the row counts to
scale accordingly.

### 5. Membership changes (webhook trail)

**What we collect.** `member`, `team`, and `repository` webhook events — the
*change* events, recording that an access-related mutation happened. Normalized
to `resource ∈ {member_access, team, repository}` with the GitHub action as
status.

**Maps to:**

| Framework | Control | When | Posture |
| --- | --- | --- | --- |
| SOC 2 | **CC6.2** | `member_access` `added` | informational — "access grant, logged for review" |
| SOC 2 | **CC6.3** | `member_access` `removed` | positive — "timely access removal" |
| SOC 2 | **CC6.3** | `member_access` `edited` | informational — "access-level change, logged" |
| ISO 27001 | **A.5.18** | `team` (any) | informational — "access-rights change, audit trail" |

**Control meanings.**
- **CC6.2** — *Registration & authorization of new users.* Before credentials are
  issued, new users are registered and authorized; credentials are removed when
  access is no longer authorized. A member being *added* is the provisioning
  event this criterion governs.
- **CC6.3** — *Authorize / modify / remove access.* Access is authorized,
  modified, or removed based on roles, least privilege, and segregation of
  duties. Member *removal* and *role change* are the modify/remove events here.
- **A.5.18** — *Access rights.* Access rights are provisioned, reviewed,
  modified, and removed per the access-control policy. A team membership change
  is an access-rights mutation on that trail.

**Why this holds & posture logic.** These are the *audit trail* of access
administration — evidence that grants/changes are captured, which is what an
auditor samples. Most are **informational** (an add or a role change is neither
inherently good nor bad — it needs human review). The one exception is
`removed` → **positive**, because timely de-provisioning is itself a control
objective (CC6.3), so a captured removal is affirmative evidence.

**Fit assessment: strong on the CC6.2/CC6.3 split** (it follows the criteria's
own provisioning-vs-modification language). The informational posture is the
right call — this data feeds the access review, it does not pass/fail on its own.

### 6. Membership & team inventory (polled)

**What we collect.** The hourly poll writes the **full current set** of org
members and team members (see [`pollOrgAccess`](../src/poller.ts)), distinct from
the webhook change-trail above. `resource ∈ {org_member, team_member}`,
`status` = the role. Each poll shares one `captured_at` so a batch is a coherent
point-in-time snapshot — this is what powers the [access-review diff](../src/access-review.ts).

**Maps to:**

| Framework | Control | Resource | Posture |
| --- | --- | --- | --- |
| SOC 2 | **CC6.2** | `org_member` | informational — "org access inventory, subject to periodic review" |
| SOC 2 | **CC6.3** | `team_member` | informational — "team-based access inventory" |
| ISO 27001 | **A.5.18** | `org_member`, `team_member` | informational — "access-rights inventory" |

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
(`member_access`/`team` webhook trail vs. `org_member`/`team_member` polled
inventory) are deliberately separate resource names so the change-trail and the
current-state inventory don't collide.

### 7. Repository inventory

**What we collect.** `repository` webhook events — repos created/deleted/renamed
within the installation. `resource = repository`.

**Maps to:**

| Framework | Control | Posture |
| --- | --- | --- |
| ISO 27001 | **A.5.9** | informational — "asset inventory trail" |

**Control meaning.**
- **A.5.9** — *Inventory of information and other associated assets.* A complete,
  maintained inventory of information assets and their owners must exist.

**Why this holds.** Repositories are information assets. The trail of repo
create/delete/rename events is evidence that the asset inventory is maintained as
it changes — exactly A.5.9's requirement. **Informational**: it is inventory, not
a pass/fail condition.

**Fit assessment: strong for what it claims.** The honest caveat is completeness:
this is a *change trail*, so it evidences that inventory changes are captured, not
that a full, owner-annotated asset register exists. If a future need is to attest
a complete inventory, the polled repo list (already fetched in
[`listInstallationRepos`](../src/poller.ts)) would be the better source than the
webhook trail.

---

## Complete mapping reference

This table is the authoritative human-readable copy of every row in
[`control_mappings`](../migrations/0002_control_mappings.sql) after all migrations
(0002 seeds most; 0003 replaces branch-protection/ruleset with the
enabled/disabled vocabulary; 0005 adds the polled access inventory; 0006 adds
the secret-scanning CC6.1 rows; 0007 closes the cross-framework coverage gaps —
Dependabot→A.8.8, code scanning→CC7.1, secret scanning→A.5.17). **A "·" in
Status means the mapping's `status` is `NULL` — it matches any status.**

| Resource | Status | Framework | Control | Posture | Rationale |
| --- | --- | --- | --- | --- | --- |
| `branch_protection` | `enabled` | SOC 2 | CC8.1 | positive | Change management — review before merge |
| `branch_protection` | `disabled` | SOC 2 | CC8.1 | negative | Change-control gap — direct pushes possible |
| `branch_protection` | `enabled` | ISO 27001 | A.8.32 | positive | Change management |
| `branch_protection` | `disabled` | ISO 27001 | A.8.32 | negative | Change-control gap — direct pushes possible |
| `repository_ruleset` | `enabled` | SOC 2 | CC8.1 | positive | Change management — review before merge |
| `repository_ruleset` | `disabled` | SOC 2 | CC8.1 | negative | Change-control gap — direct pushes possible |
| `repository_ruleset` | `enabled` | ISO 27001 | A.8.32 | positive | Change management |
| `repository_ruleset` | `disabled` | ISO 27001 | A.8.32 | negative | Change-control gap — direct pushes possible |
| `dependabot_alert` | · | SOC 2 | CC7.1 | positive | Detection tooling is active |
| `dependabot_alert` | `open` | SOC 2 | CC7.2 | negative | Unremediated known vulnerability |
| `dependabot_alert` | `fixed` | SOC 2 | CC7.2 | positive | Remediated |
| `dependabot_alert` | `dismissed` | SOC 2 | CC7.2 | positive | Remediated (risk accepted) |
| `dependabot_alert` | `auto_dismissed` | SOC 2 | CC7.2 | positive | Remediated (e.g. dependency removed) |
| `dependabot_alert` | · | ISO 27001 | A.8.8 | positive | Technical vulnerability management — detection active |
| `dependabot_alert` | `open` | ISO 27001 | A.8.8 | negative | Unremediated known technical vulnerability |
| `dependabot_alert` | `fixed` | ISO 27001 | A.8.8 | positive | Vulnerability remediated |
| `dependabot_alert` | `dismissed` | ISO 27001 | A.8.8 | positive | Vulnerability remediated (risk accepted) |
| `dependabot_alert` | `auto_dismissed` | ISO 27001 | A.8.8 | positive | Vulnerability remediated (e.g. dependency removed) |
| `code_scanning_alert` | · | ISO 27001 | A.8.29 | positive | Security testing in development is active |
| `code_scanning_alert` | `open` | ISO 27001 | A.8.28 | negative | Unremediated finding |
| `code_scanning_alert` | `fixed` | ISO 27001 | A.8.28 | positive | Remediated |
| `code_scanning_alert` | `dismissed` | ISO 27001 | A.8.28 | positive | Remediated (risk accepted) |
| `code_scanning_alert` | · | SOC 2 | CC7.1 | positive | Detection tooling is active (findings unmapped in SOC 2) |
| `secret_scanning_alert` | · | SOC 2 | CC6.6 | positive | Leaked-credential detection is active |
| `secret_scanning_alert` | `open` | SOC 2 | CC6.6 | negative | Live credential exposure |
| `secret_scanning_alert` | `resolved` | SOC 2 | CC6.6 | positive | Exposure remediated |
| `secret_scanning_alert` | · | SOC 2 | CC6.1 | positive | Logical-access credential protection — detection active |
| `secret_scanning_alert` | `open` | SOC 2 | CC6.1 | negative | Exposed credential undermines logical access controls |
| `secret_scanning_alert` | `resolved` | SOC 2 | CC6.1 | positive | Logical access control restored — exposure remediated |
| `secret_scanning_alert` | · | ISO 27001 | A.5.17 | positive | Authentication-information protection — detection active |
| `secret_scanning_alert` | `open` | ISO 27001 | A.5.17 | negative | Exposed authentication information |
| `secret_scanning_alert` | `resolved` | ISO 27001 | A.5.17 | positive | Authentication-information exposure remediated |
| `member_access` | `added` | SOC 2 | CC6.2 | informational | Access grant — logged for review |
| `member_access` | `removed` | SOC 2 | CC6.3 | positive | Timely access removal |
| `member_access` | `edited` | SOC 2 | CC6.3 | informational | Access-level change — logged for review |
| `team` | · | ISO 27001 | A.5.18 | informational | Access-rights change, audit trail |
| `repository` | · | ISO 27001 | A.5.9 | informational | Asset inventory trail |
| `org_member` | · | SOC 2 | CC6.2 | informational | Org access inventory — subject to periodic review |
| `org_member` | · | ISO 27001 | A.5.18 | informational | Access-rights inventory |
| `team_member` | · | SOC 2 | CC6.3 | informational | Team-based access inventory |
| `team_member` | · | ISO 27001 | A.5.18 | informational | Access-rights inventory |

### Control glossary

| Code | Title (plain language) |
| --- | --- |
| **CC6.1** | Implement logical-access controls over protected information assets |
| **CC6.2** | Register & authorize new users before granting access; remove credentials when access ends |
| **CC6.3** | Authorize, modify, and remove access by role, with least privilege and segregation of duties |
| **CC6.6** | Protect against threats originating outside the system boundary |
| **CC7.1** | Detect configuration changes that introduce vulnerabilities, and susceptibility to newly discovered ones |
| **CC7.2** | Monitor components for anomalies and analyze them as potential security events |
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
   - `positive` — the state is what the control wants.
   - `negative` — the state is a concrete gap the control would flag.
   - `informational` — the state is audit-trail/inventory that feeds a review but
     is not itself pass/fail. When in doubt, use `informational`.
5. **Decide detection-vs-finding.** If the signal is a scanner/alert stream, you
   usually want two mapping kinds: a `status = NULL` row for "the control's
   *tooling* exists" (positive), and per-status rows for individual findings.
   Remember rule 3 in [How mapping works](#how-mapping-works-mechanically): both
   fire on the same snapshot.
6. **Pin the edition.** State which version of the framework you mapped (e.g.
   "PCI DSS v4.0.1", "NIST CSF 2.0") — control numbers move between editions.
7. **Write the rationale** in the `rationale` column *and* the fit assessment
   here. The `rationale` is what an auditor reads in the export; make it a
   complete thought, not a keyword.

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
posture)` tuples against the rows parsed out of the
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
