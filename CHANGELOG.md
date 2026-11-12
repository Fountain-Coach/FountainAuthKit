# Changelog

## 0.2.0 — 2026-11-12 (source library; not deployed issuer)

- Durable rotating refresh families, atomic event/refresh revocation, replay-triggered family refusal, and single-writer snapshots.
- Restart-safe authority state and one-shot frozen legacy importer with rejection of a second import.
- Read-only owner client/grant projection without bearer or credential material.
- Read-only pre-consent authorization preflight using the sole issuer registry, exact callback, scope and PKCE validation, without issuing codes or grants.
- Existing Host JWKS and public validated-grant compatibility preserved.
- Native Swift regression suite: 31 tests. Live issuer migration, recovery and owner-device enrollment are separate.

**Assurance:** owner-authorized Swift package source release. It does not restart the live Host, rotate signer keys, migrate production clients, or claim external independent review or certification.

## Unreleased — Manage Client Access candidate (8 November 2026)

- Existing authorizations may be revoked by event ID, with the corresponding refresh family revoked in the same durable transition; repeated revocation is idempotent.
- Refresh credentials rotate, detect replay, and survive issuer restart without storing raw bearer credentials.
- A frozen legacy client/refresh registry can be imported once into the current single-writer issuer snapshot, with digest-only records and refusal of a second import.
- All file authority mutations commit to memory only after a successful atomic durable write.
- A read-only owner projection reports client IDs and active/revoked grant lineage without any token or digest.
- Existing Host JWKS and public validated-grant value boundaries remain callable.

**Candidate evidence:** Ubuntu Swift 6.3.3 30/30 package tests, GitHub Actions green, and isolated Host consumer tests passing. **Not yet released:** no live Hetzner migration, no real-client denial receipt, no independent release approval, and no Fountain Press interface acceptance.


## 0.1.0 - 2026-10-07

First public FountainAuthKit package release.

- writer-domain authorization authority with exact issuer isolation;
- Authorization Code with PKCE S256 for public native clients;
- exact redirect, resource and capability binding;
- short-lived Ed25519/EdDSA signed access grants;
- safe authorization evidence without bearer credentials;
- SecretStore-backed signing-key custody;
- restart-safe, domain-partitioned client/code/revocation/admission state;
- authorization codes persisted only by SHA-256 digest;
- atomic single-consumption/replay refusal;
- bounded signing-key rotation overlap, retirement, compromise response and recovery;
- typed protected-resource admission for `host.describe`.

Nonclaims: no OpenID Connect provider behavior, live public issuer, external security review or completed Reframe/HTTP/MCP deployment.
