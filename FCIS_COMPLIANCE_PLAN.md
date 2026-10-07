# FCIS compliance plan

Promotion sequence:

```text
scenario -> implementation -> build -> execution -> evidence -> admission -> reuse
```

Each released capability records a stable identity, owning authority, inputs/outputs, mutation boundary, authorization requirement, recovery semantics, refusals, scenario identities and terminal evidence.

Current owned kit declaration:

```yaml
FCIS-KIT:
  owns:
    - FountainAuthKit: writer-domain authorization authority seam
  consumes:
    - kit: swift-secretstore
      mode: semver
      requirement: exact 0.2.1
  third-party-exceptions:
    - package: apple/swift-crypto
      capability: standards cryptographic primitives
      why-not-owned: first-party Apple ecosystem cryptographic implementation; reimplementing primitives would reduce security
      accepted-by: existing governed FountainAuthKit implementation provenance
```

Release remains blocked until restart-safe authority state is implemented and proven.
