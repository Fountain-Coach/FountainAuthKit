# Architecture

FountainAuthKit is Swift-native domain logic. HTTP is an adapter.

A shared process may host several `FountainAuthAuthorizationServer` values, but it must resolve them by exact issuer identity through `FountainAuthDomainRuntime`. There is no default authority. Each server owns its own client, code and revocation namespace and uses its own key-store boundary.

The package stops at protected-resource admission. Typed host execution remains owned by the host instrument.
