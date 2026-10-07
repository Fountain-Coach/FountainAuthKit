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
| Restart-safe client/code/revocation/domain state | **BLOCKED** | current authority state is process-memory |
| Complete signing-key retirement/compromise/recovery | **BLOCKED** | rotation overlap exists; retirement/recovery API incomplete |
| Live Reframe/HTTP/MCP integration | NOT CLAIMED | consumer integration is external to this package |
| Public issuer / DNS / TLS edge | NOT CLAIMED | not deployed by this promotion |
| External security review | NOT CLAIMED | no review performed |

## Release decision

Do **not** create a version tag or GitHub release yet. FCIS-KIT release admission requires the blocked recovery and key-lifecycle gates to be closed and re-executed on a clean release commit.

## Next bounded slice

Implement a durable, domain-partitioned authority-state protocol and production adapter covering registered clients, authorization-code single-consumption state, revocation state and admitted-domain registry. Prove restart recovery and atomic code consumption. Then add explicit signing-key retirement and compromise/recovery semantics and re-run the scenario matrix.
