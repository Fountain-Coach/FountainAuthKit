# ADR 0001 — Domain-owned authentication is a product capability, not a Reframe launch prerequisite

**Decision date:** 2026-10-20  
**Status:** ACCEPTED — preserve as an independent product horizon; implementation and deployment DEFERRED  
**Owner:** FountainAuthKit (domain-scoped authorization), with FountainAuthHostKit (host authentication adapters and ceremonies) and the governed domain publisher (future provisioning/orchestration).

## Decision

**Your writing is not an account. It is a domain.**

The durable product opportunity is a repeatable, domain-owned identity and authorization authority: given an independently controlled and admitted domain, a future provisioner may establish **`auth.<owned-domain>`** with that domain's *own* issuer, credentials, registered clients, relying party, scoped grants, signing-key custody, revocation, recovery, operational ownership and audit evidence.

`auth.fountain.coach` is a possible reference deployment. `auth.anydomain.tld` describes the desired *generality*, not an already running service, automatic delegation for arbitrary domains or a claim that a domain is owned. A writer, publishing house, cultural institution or other domain owner should be able to change applications, service providers, or hosts without transferring the authority over their domain.

This is potentially a substantial **standalone Fountain Coach product capability**, not merely login for Reframe. Preserve it and all prior proof. **Do not build or deploy it as a prerequisite for the first authenticated Reframe iPad model conversation.**

## Why it matters

A host account, an Apple/Google login, an OpenAI identity, a session cookie, a domain registrar and a deployed Caddy endpoint are all *potential inputs or interfaces*. None automatically becomes the owner of a domain's authorization state.

The provisioned domain can independently determine:
- which identity evidence it trusts, and how an owner enrolls, authenticates, recovers and revokes credentials;
- which public/native clients are admitted and for which protected resources, scopes and operations;
- how keys and grants are rotated, revoked, audited, restored and moved to a different host;
- how two unrelated writer domains remain isolated even if hosted in the same process.

**Authentication ≠ authorization ≠ protected-resource admission ≠ manuscript authority ≠ model-provider invitation.** These separations survive both the immediate and future product paths.

## Existing reusable assets — preserve, do not reimplement

- `Fountain-Coach/FountainAuthKit`: public, domain-scoped Swift authorization kit. It already documents multi-domain isolation, PKCE, short-lived resource/capability-bound grants, persistent authority state, SecretStore custody, revocation, and signing-key lifecycle; see GOAL.md, AUTHORITY.md, PLANS.md and Scenario/evidence/acceptance-report.md. No public auth service is claimed here.
- `Fountain-Coach/FountainAuthHostKit`: private host-side R34–R37 owner-approved authority and named-site/WebAuthn research, with an R38 source-only native passkey assertion-wire bridge. R37 signed assertions and R38 wire tests are **source test proofs**, not public identity enrollment or a live authenticated iPad.
- Reframe R38: a real physical-iPad Chapter 149 MIDI-CI CodexKit profile reply was verified in `midi2-gpu-fabric` commit `d66aac82`. It advertises a profile but does not authorize a writer or model turn.

Treat repositories, tests, pinned dependencies, scenarios and evidence as recoverable assets. No special case for Fountain Coach, no parallel in-house WebAuthn cryptography, no secret material committed to Git.

## Two independent horizons

### NOW — R38: First Session (narrow)

Accept one **genuine authenticated, owner-approved**, writer-initiated OpenAI/Codex conversation in the same native iPad Composer over the existing governed MIDI2/host architecture. Reuse an existing authenticated host/provider session and a bounded owner pairing/admission mechanism **if independently verifiable**. That reuse is an architectural option, not proof that such a session already exists.

Require distinct host trust, protected Composer session scope, explicit model-provider invitation, a real correlated reply, and a non-mutation/refusal proof. No writer manuscript mutation and no unearned Send enablement.

**Not a prerequisite:** publishing `auth.fountain.coach`, enrolling a new WebAuthn passkey, upgrading Apple's signing team for Associated Domains, or completing a general-purpose `auth.<domain>` provisioner. These belong to the later product horizon, unless a later independently accepted scenario requires them.

### LATER — Authenticated domain as a provisionable product

Keep `auth.fountain.coach` as the reference use case and extend to genuinely owner-controlled domains. Future integration with the Semantic Domain Publisher should be governed and reproducible, including domain admission, DNS ownership, TLS/certificates, exact issuer and relying-party policy, credential enrollment, recovery, persisted grant state, routing, observability, migration and disaster recovery.

Domain publication and domain authority must remain **different** operations; DNS or a valid certificate does not mint a credential or grant. A shared host never implies shared issuer, subject, key or fallback global authority. Provisioning must not require proprietary identity ownership by Reframe.

### Future definition of done — product, not current R38 gate

A fresh, approved second domain can provision its own named HTTPS authentication origin with an independent owner-enrolled credential and recovery path; independently authenticate and issue/verifiably revoke a resource-scoped grant; survive host restart or restore; and refuse cross-domain replay, wrong-origin claims, unadmitted owners, unknown clients, wrong resources and stale/revoked credentials. The entire operation is reproducible with reviewable evidence and without sharing secrets, credentials or authority with `auth.fountain.coach`.

No claim is made that this product DoD has been reached.

## Scheduling and preservation rule

**PARKED — NOT ABANDONED.** Preserve the design, test proofs, reference implementation and ownership boundary. Do not delete or retire the authentication repositories, weaken existing security checks, merge unverified production routes, activate an IP-origin pilot, publish secrets, or replace existing published content. Continue this product line only through an explicitly selected scenario after the R38 First Session has its independent acceptance.

Related private implementation trail: `Fountain-Coach/FountainAuthHostKit` R37 `c9a81d7`, R38 `d29aea3` and draft PR #2; `Fountain-Coach/midi2-gpu-fabric` R38 draft PR #64. These are links to preserved work, not readiness claims.
