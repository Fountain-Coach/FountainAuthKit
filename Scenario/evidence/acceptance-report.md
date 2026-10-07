# Acceptance report

Date: 2026-10-07

## Result

**Public repository promotion: PASS. First semantic release: BLOCKED.**

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
| Complete signing-key retirement/compromise/recovery | **BLOCKED** | rotation overlap exists; retirement/recovery API incomplete |
| Live Reframe/HTTP/MCP integration | NOT CLAIMED | consumer integration is external to this package |
| Public issuer / DNS / TLS edge | NOT CLAIMED | not deployed by this promotion |
| External security review | NOT CLAIMED | no review performed |

## Release decision

Do **not** create a version tag or GitHub release yet. Durable authority recovery is now proven. The remaining implementation-kit release blocker is the complete signing-key retirement / compromise-response / recovery lifecycle.

## Slice D evidence

`FountainAuthFileAuthorityStateStore` persists a domain-partitioned JSON snapshot with owner-only permissions and atomic file replacement. Authorization codes are keyed by SHA-256 digest; raw code values are returned to the client but never written to the snapshot. Revocation stores token identifiers, not token strings. Tests reconstruct the store/server/runtime and prove client continuity, one-time code redemption, replay refusal, concurrent single consumption, revocation continuity, domain admission continuity, explicit runtime rebinding, and unknown-domain refusal.

## Next bounded slice

Implement explicit signing-key states and lifecycle transitions: active -> overlap verification -> retired, plus compromise response and recovery. Prove retired-key refusal after the bounded overlap window and recovery without exposing private key material.
