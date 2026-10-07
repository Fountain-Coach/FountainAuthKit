# Acceptance report

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
