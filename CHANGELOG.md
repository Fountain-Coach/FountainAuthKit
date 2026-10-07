# Changelog

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
