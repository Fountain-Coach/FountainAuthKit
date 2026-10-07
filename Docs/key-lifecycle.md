# Signing-key lifecycle

FountainAuthKit separates private-key custody from lifecycle authority.

SecretStore owns private Ed25519 key material. FountainAuthKit persists only non-secret key references and lifecycle metadata.

The admitted lifecycle is:

```text
active
  -> verification overlap (normal rotation, explicit deadline)
  -> retired

active / verification overlap
  -> compromised (immediate verification refusal)

no active key after compromise
  -> recovery with a fresh SecretStore key
  -> active
```

## Normal rotation

A new key is generated directly into SecretStore and becomes active. The former active key becomes verification-only until an explicit overlap deadline. Before that deadline, already-issued tokens may still verify. At and after the deadline, the old key is excluded from verification even if the lifecycle compaction step has not yet rewritten its state to `retired`.

`retireExpired` durably converts expired overlap records to `retired`.

## Compromise

`markCompromised` immediately removes the named key from verification. If it was the active key, signing becomes unavailable. The SecretStore item is deleted on a best-effort basis after lifecycle state has been durably changed to compromised, so failure cannot silently restore trust.

A process may restart while no active key exists. This is an admitted fail-closed state.

## Recovery

`recover` is admitted only when no active signing key exists. It generates a fresh private key directly into a new SecretStore account and records that reference as the new active lifecycle entry. Retired and compromised records remain as non-verifying lifecycle metadata.

No lifecycle file contains private key material.
