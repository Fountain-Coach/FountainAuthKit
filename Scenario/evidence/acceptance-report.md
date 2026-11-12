# Acceptance report

## FountainAuthKit 0.2.0 — source-only package admission (12 November 2026)

**Owner release scope:** The single-writer authorization Kit implementation and source checks may be versioned without calling the live Hetzner service or independent external review accepted. Owner approval for evidence-backed releases is explicit (Governance Chapter 90, canonical main f12263a). A Swift package release does not activate passkeys on the public issuer.

| Gate | Result | Exact evidence |
| --- | --- | --- |
| Canonical source history | PASS | PR #1 merge f89bb777, PR #2 merge b2c121f, Kit 0.1.0 as predecessor |
| Merged source Ubuntu Swift | PASS | 31/31 native tests, no failures, isolated complete checkout |
| GitHub tests | PASS on implementation | Both merged PRs have successful test checks; require final release-source CI |
| Kit issuer/PKCE/refresh/atomicity scope | PASS in package | Persisted client and grant state, replay denial, scope/client/redirect preflight, legacy import refusals |
| Owner source release authority | AUTHORIZED | Explicit owner instruction, real native tests and named review revisions; no independent-review claim |
| Public issuer/grant migration, real iPad, Store revoke proof | NOT_ESTABLISHED | Distinct Host/device/production acceptance |
| Independent security review/certification | NOT_CLAIMED | Optional outside assurance unless actual legal/contract obligation requires it |

**Decision:** source-only versioned 0.2.0 is admissible after a final matching source/CI check. The distinct live-service blocked items below remain blocked, not erased by this scoped package release.


## Slice F — Manage Client Access candidate (8 November 2026)

**Result: LOCALLY TESTED CANDIDATE. NOT ADMITTED, NOT SEMANTICALLY RELEASED, NOT LIVE ACCEPTED.**
This section is additive and does not revise the separate 7 October v0.1.0 acceptance.

| Gate | Result | Evidence and required scope |
| --- | --- | --- |
| Reuse existing `fountaincoach.authorization@0.1.0` contract and `fountaincoach/authorization.revoke` | PASS | `Scenarios/manage-client-access.yaml`; no IDL expansion |
| Durable rotating refresh, replay denial and event-family revocation | PASS (fixture) | Ubuntu Swift 6.3.3 `swift test --jobs 3`, 30/30 |
| Legacy one-shot import and refusal of repeated frozen family import | PASS (fixture) | Package tests; isolated Host executable smoke |
| Durable state changes only after atomic persistence succeeds | PASS (fixture) | Native filesystem write-failure regression |
| Owner grant overview from current issuer snapshot, without refresh/bearer disclosure | PASS (fixture) | `FountainAuthFileOwnerAccessReader` active/revoked, issuer separation, 0600 refusal |
| Public issuer JWKS verification-key API and validated-grant compatibility | PASS (source) | Existing Host consuming tests |
| Downstream Host source and test compatibility | PASS (isolated) | Host PR #105 candidate `a2fea4898fb3b7d94ca1ec4c04c9c59a838238dd`: 30/30 combined native tests plus OAuth HTTP DCR/PKCE/refresh and intercepted-browser callback on 3 viewports; no real iPad acceptance |
| Real issuer currently on Hetzner | NOT ADMITTED | Still executes older Kit; signing identity and three clients / one refresh family not migrated |
| Real isolated client revoke, independent MCP denial and FountainStore witness | NOT CLAIMED | Synthetic Host + Store tests do not establish live enforcement |
| Current Caddy, systemd and signed release target reconciliation | BLOCKED | Live units have candidate suffix; existing native release class names other units and root |
| Fountain Press working owner leaf and native iPad acceptance | PASS (isolated local client); live NOT CLAIMED | Press PR #8 `f493ca3bbb46d4e4ff5279825f3ad11f70cd4865`: 11/11 client tests and 3 synthetic browser viewports; native iPad, live Store/MCP denied grant and published route remain unaccepted |
| Independent review / release authorization | PENDING | PR #1 ready and green; no independent review or authorized release. Repository has only the implementing GitHub collaborator `Contexter` listed and no eligible team reviewer surfaced as of 8 November; do not self-approve |

**Historical 8 November gate:** a production Host cutover and real client acceptance were not established, so a live-service claim remains prohibited. The 12 November owner decision above separates a package source release from that deployment. Do not switch the production Host, import live credentials, mutate the issuer or advertise actual owner passkeys without their own evidence. The original ChatGPT refresh family is unchanged.

---

Date: 2026-10-07

## Result

**Public repository promotion: PASS. First semantic release gates: PASS.**

The existing governed FountainAuthKit implementation has been promoted into its own public repository and extended with exact multi-domain resolution and a typed `host.describe` protected-resource admission contract.

## Gates

| Gate | State | Evidence |
| --- | --- | --- |
| Controlling goal and authority map | PASS | `GOAL.md`, `AUTHORITY.md` |
| History-first provenance | PASS | `PLANS.md` |
| Swift-native OAuth/PKCE core | PASS | package tests |
| Exact multi-domain fail-closed resolution | PASS | domain runtime tests |
| Two-domain token/key isolation | PASS | cross-domain validation test |
| Resource/capability/expiry/signature/revocation checks | PASS | adversarial tests |
| Safe evidence | PASS | evidence tests + secret-shape scan |
| SecretStore signing-key custody | PASS | existing custody tests |
| Protected-resource `host.describe` contract | PASS | typed admission test |
| Restart-safe client/code/revocation/domain state | PASS | file authority-state store + restart/replay/race tests |
| Raw bearer exclusion from authority snapshot | PASS | code digest + token-ID persistence tests |
| Complete signing-key retirement/compromise/recovery | PASS | restart-persistent lifecycle + overlap/retirement/compromise/recovery test |
| Live Reframe/HTTP/MCP integration | NOT CLAIMED | consumer integration is external to this package |
| Public issuer / DNS / TLS edge | NOT CLAIMED | not deployed by this promotion |
| External security review | NOT CLAIMED | no review performed |

## Release decision

All implementation-kit gates for the first Swift package release are now closed. This establishes a releasable library profile; it does **not** claim a live public issuer, OpenID Connect provider behavior, external security review, or completed Reframe/HTTP/MCP deployment.

## Slice D evidence

`FountainAuthFileAuthorityStateStore` persists a domain-partitioned JSON snapshot with owner-only permissions and atomic file replacement. Authorization codes are keyed by SHA-256 digest; raw code values are returned to the client but never written to the snapshot. Revocation stores token identifiers, not token strings. Tests reconstruct the store/server/runtime and prove client continuity, one-time code redemption, replay refusal, concurrent single consumption, revocation continuity, domain admission continuity, explicit runtime rebinding, and unknown-domain refusal.

## Slice E evidence

Signing-key lifecycle metadata is durable and non-secret. Normal rotation converts the previous active key to verification-only with an explicit deadline. Validation excludes it at and after that deadline. Expired overlap can be durably retired. Compromise immediately excludes the key from verification and removes active signing authority; restart in that degraded state remains fail-closed. Recovery creates a fresh SecretStore key and records it as active without reviving compromised material.

## Release boundary

The accepted first release is the Swift package and its executable contracts. Public domain deployment, HTTP projection, Reframe user experience integration and external security review remain separate integration/operations work and are not prerequisites for the package's semantic version.
