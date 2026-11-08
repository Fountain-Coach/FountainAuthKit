# Plan and history-first reconstruction

## Current release-admission tranche — 8 November 2026 (canonical, not an alternative tracker)

**Target:** advance existing `fountaincoach.authorization@0.1.0` Manage Client Access candidate PR #1 `a9940287a49eb10283c2a1f03aeb83321228026e` to a reviewed, semver-tagged Kit release consumable by Host PR #105; then prove unchanged existing ChatGPT grants through a single-writer Hetzner migration. Native iPad reconnection and Press owner revoke remain final live acceptance, not assumptions.

**Chapters read:** 07 history-first and one maintained plan; 08 evidence authority and independent release witnesses; 90 security review separate from source/test proof; 91 one FCIS-KIT capability owner; 93 scenario → test → evidence → independent admission → released reproducible artifact.
**What they forbid here:** self-approving an authentication security release; declaring the current green 30/30 suite to be independent review; tagging or activating with an open security/Store/live-service acceptance gate; creating an owner key, second client database, alternate deployment helper or ZIP distribution.
**Conflicts:** writer requests autonomous completion, while Chapter 90/93 and root AGENTS require a separate admission authority. Continue automated read-only checks and all dependency-ready implementation, but do not pretend the implementing agent constitutes an independent reviewer.
**Excluded, and why:** Reframe GUI/Audio/MIDI work, additional owner portal, public documentation and unrelated host services are outside the bounded access grant continuity scenario.

**Checked state:** PR #1 OPEN, clean/mergeable, GitHub Actions `test` SUCCESS and 0 reviews. Existing `v0.1.0` semantic release of 7 October is the predecessor, **not** this candidate. `Scenario/evidence/acceptance-report.md` explicitly records this slice as locally tested only. Suite of 30 Ubuntu Swift tests includes one-shot frozen import, rotating refresh, replay-triggered family revocation, owner overview, durable write-failure rollback, and no secret-bearing output. The candidate has no independent security approval or tagged release.

| Phase | Native next action | Admission / terminal predicate | Status |
| --- | --- | --- | --- |
| K1 | Confirm exact PR source, CI, `GOAL.md`, `AUTHORITY.md`, scenario JSON/Swift and secret-shape scan | Clean source, named revision, tests and checked projection agree | Source tested; revalidate after any change |
| K2 | Obtain independent review of authorization/security change and migration/rollback scope | Non-author review recorded; findings closed or explicitly accepted by owner | **PENDING, cannot self-approve** |
| K3 | Admit semver release on owning repository with signed/versioned tag, changelog and exact source SHA/digests | Named reproducible released Kit, acceptance report promoted by owning authority | BLOCKED on K2 |
| K4 | Pin Host consumer to the admitted Kit release instead of its candidate commit | Native Host OAuth/MCP/Store/refresh tests and binary hashes match pinned version | BLOCKED on K3 |
| K5 | Prove Hetzner freeze, one issuer writer, private signing identity unchanged, reversible predecessor and old ChatGPT refresh continuity | Exact native service/Store/HTTPS receipts and independent real-client denial | Requires Host target release readiness |
| K6 | Confirm installed ChatGPT iPad reconnect, refresh and `host.describe`, then Press real grant revoke | Physical iPad + independent MCP/Store witnesses | Not executed |

**Stop boundary:** no production registry mutations, signing key change, live issuer restart, Caddy activation, tag or GitHub release from this plan. Continue release preflight and review preparation without requiring the writer to babysit every step.


## Slice F2 — Owner read projection from the same authority (8 November 2026)

**Goal:** Fountain Press must select an actual client/grant without owning permission state. **Authority:** Chapter 142 and 161 require one Kit issuer and an owner-authenticated Host; the scenario from `Scenarios/manage-client-access.yaml` requires source-verified grant identity. **Forbidden:** querying legacy registry as an alternate authority, returning raw refresh digests or tokens, showing a cached revocation as current, exposing this reader to public callers, or asserting Host/UI acceptance from a Kit fixture. **Boundary:** `FountainAuthFileOwnerAccessReader` is Kit-owned and read-only; its Host adapter must authenticate the owner, match issuer and use this source on every request. No deployment or grant change in this slice.

**Test gate:** fresh active/revoked projection, issuer isolation, no digest or bearer serialization, and insecure file refusal: **PASS**, Ubuntu Swift 6.3.3 `swift test --jobs 3` **30/30** zero failures, including `testOwnerReadProjectionTracksOneIssuerWithoutExposingRefreshDigests`. The reader never writes and deliberately reads the current file each time. Explicit corrupt-state and dedicated separate-process Host acceptance are still outstanding. This is Kit fixture evidence, not live user acceptance.

## Slice F1 — Atomic authority mutation after failed persistence (8 November 2026)

**Chapters read:** 07 history-first goal fidelity and phase plan; 08 independently witnessed persisted proof; 73 scenario and negative-path terminal predicates; 91 FCIS-KIT owns authorization-state invariants; 93 build/evidence before release. Published Chapters 142 (one Kit authorization owner) and 161 (owner-visible revoke must match enforced state) remain binding. **Forbidden:** an issuer accepting mutations not committed durably, treating 27/27 as release admission, creating another permission store, altering the deployed ChatGPT refresh grant or choosing a new signing key. **Conflict:** the earlier file-backed state methods mutated their in-memory snapshot before a fallible atomic disk write; new event/refresh methods had correctly used copy-on-write. **Excluded:** Host deployment, real grant mutation, independent Store receipt, Press UX and release authority until native witness is complete.

**Observed defect:** `FountainAuthFileAuthorityStateStore` registration, authorization-code storage/consumption, token-ID revocation and issuer admission used `snapshot` mutation followed by `persist()`. A denied write could leave an unpersisted client, accepted revocation, consumed code or issuer in memory, in conflict with the next restart and protected resource. **Smallest correction:** stage a local `next` snapshot; persist it first; publish to actor memory only upon successful write. Reuse the existing actor and JSON snapshot without adding any new authority.

**Public validated-grant compatibility:** consuming Host tests construct `FountainAuthValidatedGrant` as a public value; the newer Kit exposed only an internal synthesized memberwise initializer, causing downstream tests to fail at compilation. Restore an explicit public initializer with the same 8-field validated-grant shape and test JSON roundtrip. This is not new authority or a production grant. Ubuntu Swift 6.3.3 `swift test --jobs 3` now passes **29/29** including this value roundtrip and all prior legacy migration/revocation tests; downstream Host consumer compilation remains a separate gate.\n\n**Host JWKS compatibility:** the issuer exposes current public verification keys through `FountainAuthAuthorizationServer.verificationKeys(now:)`, preserving its existing JWKS endpoint without exposing signing bytes or adding a second key registry; the same Kit suite passes 28/28 after this source-level adapter. Host use is a separate integration gate.

**Terminal proof:** `testFailedAuthorityStateWriteDoesNotChangeInMemoryAdmissionOrConsumeCode` uses a real file-path obstruction to force native filesystem failures, then verifies no unpersisted registration, token revocation, issuer admission, authorization-code creation or code consumption; restoring the existing snapshot permits the original code exactly once, with restart agreement. Focused Ubuntu Swift 6.3.3 test PASSED (1/1). Full Ubuntu Swift 6.3.3 `swift test --jobs 3` PASSED **28/28**, zero failures, on the isolated Mac mini checkout. Kit `.swiftmodule` SHA-256 `a0ca1d1f0cb0ab48b7bfbea00ba3768dc76ed21614646a921d07e684ad3e2c07`; XCTest executable SHA-256 `44025d707546819692cf07e0171cf6689d9ed9a1887151c72131fcacf4e3a596`. GitHub CI and owning review/release remain separate gates. No Host or Caddy changes.



## Source boundary

Problem/source: promotion of the existing in-repository `midi2-gpu-fabric/kits/FountainAuthKit` seam into its own public owned-kit repository.

Observed provenance:
- `3f7bf1f671f08a3064b0957feac3afbcf8d9bd1c` — initial authorization kit.
- `d49d1d8dfb4d6532e935b524675b1b5d97a9fefa` — SecretStore signing-key custody.
- `38897bb95f47b4a3f1027d65e347d562a2babdb1` — grant lineage contract.
- `00d9520fc9d9894183cd5dbab8ed0ab125c8d431` — grant evidence and state tools.

Current authority: `FountainAuthAuthorizationServer` plus explicit signing-key and evidence protocols.
Current execution surface: Swift package.
Established proof: metadata, exact redirect, PKCE S256, single-use code, resource/scope/expiry checks, in-process revocation, Ed25519 signing, SecretStore custody adapter, safe evidence.
Missing release seam: restart-safe persistence for authority state and full external protected-resource/host integration.
Classification: source/history and local tests are observed; public production behavior is unestablished.

## Slice F — Manage Client Access (scenario-first candidate, 2026-11-08)

**Controlling goal:** A working revoke/reauthorize operation for an isolated test client, eventually consumed by Fountain Press as an FCIS instrument; not another management dashboard or authorization authority. Existing `fountaincoach.authorization@0.1.0` and the already declared `fountaincoach/authorization.revoke` MIDI2 operation are reused, without modifying the IDL.

**Chapters read:** 07 planning/goal fidelity, 08 independent evidence, 91 kit ownership, 93 scenario→contract→implementation→evidence→admission/release, 73 scenario ownership. Published 142 keeps authorization in FountainAuthKit and host execution in the Host, while Chapter 161 requires explicit consent and revocation. **Forbidden:** rotating owner keys, altering production ChatGPT grants, treating an unadmitted read-only dashboard as management, equating fixture tests with live issuer enforcement. **Conflict:** existing standalone kit already durably revokes individual token IDs; the running MCP issuer and protected resource are separate consumers, so kit-local success does not prove production rejection. **Excluded:** production issuer/Caddy mutations, owner portal, Fountain Press consumer integration, new instrument namespace, live FountainStore/AX receipts until source-level scenario proof passes.

**History-first sources:** `Sources/FountainAuthKit/FountainAuthKit.swift` owns the issuer-scoped `FountainAuthAuthorityStateStore` and `FountainAuthAuthorizationServer`; durable token ID revocation is already implemented and tested in `testDurableAuthorityStateSurvivesRestartWithoutPersistingBearers`. The missing evidence-backed seam is an owner-mediated revoke by a known authorization event ID, affecting all access tokens issued from that event while preserving reauthorization as a fresh event. No second database is needed; extend the existing authority state and retain backward JSON compatibility.

**Scenario:** `Scenarios/manage-client-access.yaml` with checked `.json` projection. Precondition: unique isolated client, exact issuer/resource, PKCE consent and file-backed state. Terminal: success before revocation; `revoked` first, `already-revoked` repeated; old access denied immediately and after restart; unknown/wrong issuer/client/resource refused; fresh consent obtains a distinct event and succeeds; persisted state excludes all bearer material. Evidence to pursue: focused Swift XCTest and full package CI first, then independent Host/Store and Fountain Press browser/AX evidence. **Status: locally tested candidate (22/22 Swift tests), not live-accepted, released or deployed.**

**Test witness (same candidate):** GitHub PR #1, head `b0060d91a5ecbb5458310a5e1c048d154931815a`, workflow run `42487727800` / job `128753165747`: macOS Swift CI completed successfully on 8 November 2026; secret-shape scan PASS, dependency resolution PASS, 22 XCTest methods PASS, zero failures. Tests include the new event revoke, legacy snapshot decoding and scenario projection. This establishes package-level fixture execution only, not a released FCIS-KIT artifact, live FountainStore receipt, real protected-resource denial, external peer MIDI2 exchange, Press UI, security review or production client revocation. Review before release: the currently running MCP issuer uses its own host adapter, so it must consume an admitted kit version and prove event-level invalidation at the protected resource independently. Do not infer this from the kit's issuer-local `validate` method.

**Protected-resource scenario correction (8 November 2026):** The current Hetzner MCP resource source in the operational Monorepo uses `FountainAuthProtectedResourceValidator` with a revocation list loaded from `FOUNTAIN_AUTH_REVOKED_TOKEN_IDS` when the process starts. That list cannot witness immediate authorization-event revocation. The owner-side monorepo Kit is older than the standalone library and its issuer persists refresh-family digests in a separate service. Therefore the new standalone kit may NOT be presented as already enforcing live Host revocation; no production key, client or Caddy change was performed. The smallest owned-kit contract correction is the public-key-only `FountainAuthProtectedResourceValidator` accepting a current issuer-scoped revocation reader. It performs complete signature/issuer/resource/scope/expiry checks and refuses when current revocation state is unavailable, as a distinct protected-resource operation. This does not install a new database or issue a token. The full Host adapter requires a deliberate, version-pinned kit release and current-state sharing between the issuer and protected resource; it cannot reuse a static startup list or silently assume the older snapshot proves authority.

**Current tests:** GitHub PR #1 head `850a88e2b8fb441db474771208760b85e5c27750`, workflow `42491603689` job `128764983282`: all 23 Swift XCTest methods PASS, including `testProtectedResourceValidatorReadsLiveRevocationAcrossRestartAndFailsClosed`, isolated event-revoke flow, legacy snapshot, cross-resource denial, and injected reader unavailability refusal. Secret-shape scan PASS. **State:** candidate, source and CI level; no Host/Store/Press production acceptance, admission, semantic release or deployed revocation. The source uses a typed revocation reader callback; the Host adapter must supply independently verified, current, fail-closed issuer state. Do not reinterpret a callback to a static list as a completed integration.

**Same-host cross-process reader seam (8 November 2026, bounded kit continuation).** Source traced: the kit's `FountainAuthFileAuthorityStateStore` currently snapshots its JSON at initialization; the independent `FountainAuthProtectedResourceValidator` accepts a current revocation callback, but handing it an old initialized state object would falsely allow access after an issuer writes a new revocation. This is not fixed by the 23 fixture tests. Implement one kit-owned **read-only file revocation reader** that re-opens the issuer's *existing* safe authority snapshot for every token-validation decision (never caching a negative grant), checks exact issuer/event/client/resource binding, refuses missing or corrupt/over-permissive state, and has no writing or token-issuance API. Modify the kit's protected-resource callback to receive client ID and resource as well as token ID, event ID, issuer. Use an isolated test writer and an already-constructed separate reader/validator, then revoke and verify immediate denial, bad binding and unavailable state refusal. This is a reusable read adapter, not an independent authority database, a Host-specific HTTP endpoint, or a new ceremony. **Chapters read:** internal 07 planning/lookup and 08 independent tests; 73 complete scenario and negative paths; 91 FCIS-KIT enforcement; 93 kit admission/release separation. **Forbidden:** revocation from a static environment variable, cached successful validation after an issuer write, direct access to private FountainStore in the MCP process, presenting a fixture as ChatGPT denial, deploying a draft kit, changing current Hetzner registry/caddy. **Conflict:** existing operational issuer persists refresh families rather than the standalone kit authority snapshot; the new file reader cannot be treated as a production integration until the Host uses the *released* kit, a real issuer-authoritative snapshot is created via its normal native path, and the protected resource can read it safely. **Excluded:** public portal, Press buttons, live Host Store, production cross-process permissions, and release/admission authority. **State:** implementation candidate only, pending Swift CI and separately reviewed Host rollout.

**Linux candidate and production compatibility witness (8 November 2026):** Candidate commit `63924df7b23e4b546414c74bb5e3bbdbada17381` fetched as a clean source checkout on Ubuntu Mac mini, `swift test --jobs 3` under Swift 6.3.3: **24/24 tests PASS**, including the new cross-process fresh-reader and protected-resource denial tests. GitHub Actions Swift run `42492759930` job `128768486716` independently PASSED 24/24 + secret-shape scan. Ubuntu Swift module digest `33ec207b64d3613c71cab9ffa162f82ae278a4abb8a370a33cf6d9bb37402363`, path `.build/x86_64-unknown-linux-gnu/debug/Modules/FountainAuthKit.swiftmodule`; dependency commits swift-crypto `95ba0316a9b733e92bb6b071255ff46263bbe7dc`, swift-secretstore `3d923610e89753b6e68a63efe0fa8cf49814616b`. Ubuntu source worktree clean. This is an **independently built candidate**, not the owning release artifact.

**Proven compatibility gap—not an owner-key or SSH admission blocker:** The live Hetzner OAuth and MCP units are both systemd `User=fcis-host` / `Group=fcis-host`. The current `clients.json` and `refresh-families.json` are both owned by `fcis-host`, mode 0600. Same-host protected read is feasible. However the active in-repository `FountainAuthKit` has `FountainAuthRefreshFamily`, `redeemWithRefresh`, `rotateRefresh` and `revokeRefreshFamily` while the standalone candidate has **none** of these four APIs and uses a different authority JSON snapshot. Replacing the in-repo Kit with this candidate would discard the working ChatGPT refresh-grant lifecycle. Do NOT silently pin or deploy it as a drop-in Host dependency. Before Host integration, preserve all existing DCR/refresh-family grants and rotation/replay semantics in a single authoritative source/compatibility migration; validate against an isolated client and exact currently deployed issuer signing identity. The in-repo MCP still reads `FOUNTAIN_AUTH_REVOKED_TOKEN_IDS` once at process start, so independent live-protected-resource denial remains unestablished. Release and production switching stay separately governed. Avoid writing a second database, importing plaintext refresh credentials or invoking the live ChatGPT grant. **Next admitted work:** scenario-driven refresh-continuity reconciliation in the owning Kit, then reviewed release and exact Host consumer pin—not user portal styling.

**Refresh-compatibility first code slice and independent build witnesses (8 November 2026):** `Scenarios/legacy-refresh-continuity.yaml` and checked JSON projection declare the existing DCR and rotating refresh-family semantics to preserve. `FountainAuthLegacyRefreshPreflight.inspect` is a *pure read-only validator* for the existing `clients.json` and `refresh-families.json` legacy array shapes; it checks unique client/family identity, registered client, bound resource, event identity, non-empty scope, time ordering, fixed lowercase SHA-256 digest shape and absence of duplicate digests. It returns counts only; it neither imports, mints, rotates, stores nor revokes anything. Tests use synthetic digest values, not real ChatGPT credentials. Candidate commit `1c70025aff338bac5a00fc81dab0866f02a9eea5`: Ubuntu Mac mini Swift 6.3.3 `swift test --jobs 3` PASS 25/25 (clean checkout), Linux Kit module SHA-256 `c88d59a9d387ede1893111e18803277b9a8291ba3debf7a0e4f3104720a1ff5c`, compiled XCTest executable SHA-256 `3d30a033099cbafd75ec040eba0cbd59c299cdd44fbeaf7a8de71a7c25532bef`. SwiftPM resolved dependencies: swift-crypto `95ba0316a9b733e92bb6b071255ff46263bbe7dc`, swift-secretstore `3d923610e89753b6e68a63efe0fa8cf49814616b`. Independently, GitHub Swift workflow `42493285527` job `128770063606`: completed SUCCESS, secret-shape scan and Test step PASS. **Unimplemented:** compatible issuance/rotation/replay handling and atomic migration of existing refresh state into the standalone authority without losing working production ChatGPT grants. The preflight cannot be mistaken for that integration. **No admission/release/Host/Press mutation is claimed.**

**Refresh-continuity implementation result — 8 November 2026.** The standalone owning Kit now contains the original digest-only `FountainAuthRefreshFamily` shape and the existing-issuer `redeemWithRefresh`, `rotateRefresh`, `revokeRefreshFamily` and frozen-only `importLegacy` operations. Source-owned `FountainAuthAuthorityStateSnapshot` serializes client identities, authorization events, consumed/current SHA-256 refresh digests, expiry and revocation in **the one existing authority snapshot**; issuer-scoped writes are atomic. A replayed consumed refresh token revokes its entire family and authorization event (which also denies already-issued access tokens); explicit event revocation atomically marks the corresponding refresh-family record revoked for owner-facing projection. An imported legacy array is checked for unique family/event identities and digest lineage, bound to a named issuer and resource, and refused if that issuer already has records. No bearer tokens or signing keys are imported or persisted.

**Current candidate evidence:** last executable/source revision `06edf3ed2d944bb3656ef39ccb1c99cde51b84d2`; Ubuntu Swift 6.3.3 `swift test --jobs 3` **27/27 PASS**, clean checkout, module SHA-256 `74f2135e36be2c99bdf4806c075ebb2966dc56a875b097ae4b0931795dbd6c13`, XCTest executable SHA-256 `31dbf68a6f2c06abbdaa5014c22ff61fbd702d092ca1ab9ff7941c5057cab583`. GitHub Actions workflow `42495123278`, job `128775721673`: **SUCCESS**, secret-shape scan/resolve/test all PASS, 27 tests zero failures. Fixture scenario `Scenarios/legacy-refresh-continuity.yaml`/JSON state `fixture-tested-candidate-not-live`. Tests cover one-issuer import, exact legacy digest preservation, refusal of second import, rotation across restart, replay revocation, event refresh-family state consistency, protected-resource denial and new consent.

**Explicit remaining boundaries:** the live Hetzner issuer is still the original older in-repo Kit running with the existing ChatGPT refresh-family registry; it has not been switched, imported, released or revoked. Existing standalone candidate has been tested with **synthetic** legacy records only; the real Host still requires a separately reviewed, version-pinned Kit release, native single-writer migration rehearsal with exact current protected files/signing identity, and source/Host adapter acceptance including independent FountainStore receipt plus MCP denial. The Fountain Press single-leaf management control remains a consumer scenario draft; do not activate Revoke until its real Host path is proven. No new owner key or portal is a prerequisite of the tested Kit functionality. **State: implemented and fixture-tested candidate; no admission, release or live acceptance claimed.**

## Current promotion slices

### Slice A — public repository baseline
Scenarios: FA-META, FA-CLIENT, FA-CODE, FA-GRANT, FA-TOKEN, FA-EVID.
Authority: package.
Predicate: extracted implementation builds and tests in its own repository.
Evidence: `swift test`.

### Slice B — domain isolation
Scenarios: FA-DOM-001..005, FA-SEC cross-domain rows.
Authority: shared runtime resolver; each resolved server remains domain authority.
Predicate: exact issuer resolves one authority; unknown issuer refuses; no fallback; two domains do not substitute issuers.
Evidence: domain-runtime tests.

### Slice C — protected host capability contract
Scenarios: FA-HOST-001..004.
Authority: protected-resource admission then host-owned execution.
Predicate: only a validated grant containing `host.describe` for the exact resource becomes a typed host-description admission.
Evidence: focused tests. Actual machine description remains outside this package.

### Slice D — recovery
Scenarios: restart/recovery rows across FA-CODE, FA-REV, FA-DOM.
Authority: `FountainAuthAuthorityStateStore`, with memory fixture and file-backed durable adapter.
Predicate: client/code/revocation/domain state survives process restart atomically without bearer evidence.
Status: ACCEPTED.

Evidence:
- authorization codes persist only as SHA-256 digests plus bounded code records;
- a pre-restart code can be redeemed after reconstruction exactly once;
- replay remains refused after another reconstruction;
- two concurrent redeemers yield exactly one success;
- revocation persists token identifiers and remains effective after restart;
- admitted issuer identities survive runtime reconstruction and still require explicit authority rebinding;
- unknown issuers continue to fail closed;
- durable snapshot contains neither raw authorization code nor access-token bearer value.

The file adapter serializes mutations through one actor and writes its JSON snapshot atomically with owner-only file permissions. One store actor is the authority for one snapshot file; multi-process shared-file coordination is outside this profile.


### Slice E — signing-key lifecycle
Scenarios: FA-KEY-001..006.
Authority: SecretStore for private-key custody; FountainAuth signing-key lifecycle store for non-secret state transitions.
Predicate: normal rotation has a bounded verification deadline; expired overlap refuses; compromise refuses immediately; restart without an active key remains fail-closed; recovery creates a fresh active SecretStore key without reviving compromised material.
Status: ACCEPTED.

Evidence:
- lifecycle metadata survives restart;
- in-flight token verifies during admitted overlap;
- old key refuses exactly at/after overlap deadline;
- expired overlap is durably retired;
- compromised key refuses immediately and loses signing authority;
- restart after compromise remains degraded/fail-closed;
- recovery establishes a fresh active key;
- lifecycle snapshot contains references/state only and no private key bytes.

## Product horizon decision — domain-owned authentication (2026-10-20)

**ACCEPTED / PARKED, not abandoned.** The reusable product opportunity is a governed `auth.<owned-domain>` authority, composable with the Semantic Domain Publisher and independent of a single writer app. `auth.fountain.coach` is the proposed reference deployment, not a live production claim. Detailed rationale, existing reusable evidence, future DoD and revival criteria: [ADR 0001](Docs/decisions/0001-domain-owned-authentication-product-horizon.md).

The native Reframe R38 first authenticated model conversation **must not depend** on completing the new passkey service, Apple Associated Domains entitlement or domain provisioner. Existing safe host authentication may be reused only after genuine trust, owner consent, scoped Composer admission and explicit model invitation are proven. The long-term program remains owned and discoverable; no production work on the domain auth provisioner is currently authorized by this ADR.
