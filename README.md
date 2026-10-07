# FountainAuthKit

> **Your writing is not an account. It is a domain.**

FountainAuthKit is the Swift-native authorization boundary for writer-owned Reframe domains. A writing domain may have its own issuer identity, clients, grants, signing keys, revocation state and protected resources without making Reframe, an identity provider, an AI provider, DNS, a reverse proxy or a transport the owner of that authority.

## Status

FountainAuthKit is the first public implementation of the governed Fountain authorization seam. The `v0.1.0` profile is a reusable Swift package with restart-safe authority state and a complete bounded signing-key lifecycle. **It does not claim a live public production issuer, OpenID Connect provider behavior, external security review, or completed Reframe deployment.**

The current profile implements Authorization Code with Proof Key for Code Exchange (PKCE, S256), exact redirect matching, resource-bound and capability-scoped short-lived signed access tokens, Ed25519/EdDSA signing, SecretStore-backed signing-key custody, durable domain-partitioned client/code/revocation/admission state, safe grant evidence, authorization-server metadata and protected-resource metadata contracts. Raw authorization codes and access-token bearer values are not persisted in authority state.

It does **not** claim OpenID Connect provider behavior, public `auth.fountain.coach` deployment, an external security review, or completed Reframe user-interface integration.

## Authority model

```text
human / authorized principal
  -> authentication adapter
  -> writer-domain authorization authority
  -> bounded signed grant
  -> protected resource
  -> typed capability
  -> owning host / instrument
  -> terminal result + safe durable evidence
```

Authentication is not authorization. The protected resource owns admission. The host owns host capability. Evidence never stores bearer credentials. Domain admission remains separate from DNS, certificate issuance and edge binding.

## Package

```swift
.package(url: "https://github.com/Fountain-Coach/FountainAuthKit.git", from: "0.1.0")
```

## Verification

```sh
swift test
./Scripts/secret-shape-scan.sh
```

See [Scenario/evidence/acceptance-report.md](Scenario/evidence/acceptance-report.md) for the exact acceptance state and release boundary.
