# FountainAuthKit

> **Your writing is not an account. It is a domain.**

FountainAuthKit is the Swift-native authorization boundary for writer-owned Reframe domains. A writing domain may have its own issuer identity, clients, grants, signing keys, revocation state and protected resources without making Reframe, an identity provider, an AI provider, DNS, a reverse proxy or a transport the owner of that authority.

## Status

This repository is the first public implementation promotion of the existing governed FountainAuthKit seam. The package is usable for local development and contract testing, but **no public production issuer is claimed yet and no release tag is cut yet**. Restart-safe persistence for authorization codes, client registration and revocation state remains a release gate.

The current profile implements Authorization Code with Proof Key for Code Exchange (PKCE, S256), exact redirect matching, resource-bound and capability-scoped short-lived signed access tokens, Ed25519/EdDSA signing, SecretStore-backed signing-key custody, revocation, safe grant evidence, authorization-server metadata and protected-resource metadata contracts.

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

The semantic-version dependency above becomes valid only after the first release is tagged. Until then, consumers must not pretend an unreleased commit is a released package.

## Verification

```sh
swift test
./Scripts/secret-shape-scan.sh
```

See [Scenario/evidence/acceptance-report.md](Scenario/evidence/acceptance-report.md) for the exact acceptance state and blockers.
