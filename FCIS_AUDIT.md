# FCIS audit

FountainAuthKit is an owned Swift kit. It therefore follows the Fountain Coach instruction and kit standards.

## History first
The implementation was not invented for this public repository. It is promoted from `midi2-gpu-fabric/kits/FountainAuthKit` with source provenance recorded in `PLANS.md`.

## Kit ownership
The generic seam is authorization-server domain logic: metadata, public-client registration, PKCE authorization-code exchange, bounded grants, token validation/revocation, key custody interface and safe evidence interface.

Consumers bind Reframe, HTTP, MCP, FountainStore and host types on their own side. The package does not import consumer product types.

## Dependencies
- `apple/swift-crypto`: cryptographic primitive implementation.
- `Fountain-Coach/swift-secretstore`: Fountain-owned secret custody seam.

## Release status
No first semantic release is admitted until the acceptance report has no blocked gate.
