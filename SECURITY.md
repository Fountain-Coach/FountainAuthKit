# Security policy

FountainAuthKit is security-sensitive authorization infrastructure.

Report vulnerabilities privately to the Fountain Coach maintainers, following the organization security policy. Do not place vulnerability details, credentials, private keys, bearer tokens or authorization codes in public issues.

The first public profile requires exact redirect matching, PKCE S256 for public clients, resource-bound and capability-scoped short-lived tokens, fail-closed unknown authority handling, Ed25519/EdDSA signatures, replaceable SecretStore-backed key custody and safe evidence that contains no bearer material.

A passing unit suite is not a production security review. This repository does not currently claim an externally reviewed or publicly deployed authorization service.


## Durable authority state

The durable authority-state profile may contain public client registrations, authorization request metadata, hashed authorization-code identifiers, authorization event identifiers, token revocation identifiers and admitted issuer identities. It MUST NOT contain raw authorization codes, access tokens, refresh tokens, passwords or private signing keys.

`FountainAuthFileAuthorityStateStore` is a single-owner file profile: one actor owns mutations for one snapshot file and uses atomic replacement. Sharing the same snapshot concurrently between multiple processes is outside the admitted profile.
