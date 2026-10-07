# Architecture

FountainAuthKit is Swift-native domain logic. HTTP is an adapter.

A shared process may host several `FountainAuthAuthorizationServer` values, but it must resolve them by exact issuer identity through `FountainAuthDomainRuntime`. There is no default authority. Each server owns its own client, code and revocation namespace and uses its own key-store boundary.

The package stops at protected-resource admission. Typed host execution remains owned by the host instrument.


## Durable authority state

`FountainAuthAuthorityStateStore` owns the mutable authorization state that must survive process restart: public-client registrations, authorization-code records, token revocation identifiers, and admitted issuer identities.

The file-backed profile persists one JSON snapshot per owner-selected file. It stores authorization-code SHA-256 digests rather than raw bearer codes and token identifiers rather than access-token strings. The actor serializes mutations and uses atomic file writes. The host must place this file in an appropriately protected directory; the adapter applies owner-only permissions to the snapshot itself.

Runtime server objects are deliberately not serialized. After process restart, admitted issuer identities are restored and the host explicitly rebinds the matching server object. This preserves the distinction between durable domain admission and live runtime wiring.
