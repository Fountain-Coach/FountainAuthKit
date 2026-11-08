# Acceptance report

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
| Downstream Host source and test compatibility | PASS (isolated) | Host PR #105 merged-source tree `f390639c1d3413268b2abad218ff89c98fb8509c`, 30/30 focused native tests and two executable builds |
| Real issuer currently on Hetzner | NOT ADMITTED | Still executes older Kit; signing identity and three clients / one refresh family not migrated |
| Real isolated client revoke, independent MCP denial and FountainStore witness | NOT CLAIMED | Synthetic Host + Store tests do not establish live enforcement |
| Current Caddy, systemd and signed release target reconciliation | BLOCKED | Live units have candidate suffix; existing native release class names other units and root |
| Fountain Press working owner leaf and native iPad acceptance | NOT CLAIMED | Press consumer PR #8 remains a scenario candidate |
| Independent review / release authorization | PENDING | PR #1 is review-ready; no approved reviewer or semantic version promotion |

**Release gate:** do not tag, merge as a released package, switch the production Host, import live credentials, mutate the live issuer, or publicly advertise the owner instrument while the rows above remain unaccepted. The existing live ChatGPT refresh family remains unaffected. The source is reviewable; promotion is a separate authority decision.

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
