# Plan and history-first reconstruction

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
Authority: durable authority-state store.
Predicate: client/code/revocation/domain state survives process restart atomically without bearer evidence.
Status: BLOCKED pending a production durable state adapter/contract implementation. This is a release blocker.
